# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2016

import logging
import sys

from datetime import datetime

from rucio.core.rule import get_rule, add_rule, update_rule
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse import list_rse_attributes, get_rse_name
from rucio.core.rse_selector import RSESelector
from rucio.core.subscription import get_subscription_by_id
from rucio.common.config import config_get
from rucio.db.sqla.session import transactional_session

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rebalance_rule(parent_rule_id, activity, rse_expression):
    """
    Rebalance a replication rule to a new RSE

    :param parent_rule_id:       Replication rule to be rebalanced.
    :param activity:             Activity to be used for the rebalancing.
    :param rse_expression:       RSE expression of the new rule.
    :returns:                    The new child rule id.
    """
    parent_rule = get_rule(rule_id=parent_rule_id)

    if parent_rule['expires_at'] is None:
        lifetime = None
    else:
        lifetime = (datetime.utcnow() - parent_rule['expires_at']).days * 24 * 3600 + (datetime.utcnow() - parent_rule['expires_at']).seconds

    child_rule = add_rule(dids=[{'scope': parent_rule['scope'],
                                 'name': parent_rule['name']}],
                          account=parent_rule['account'],
                          copies=parent_rule['copies'],
                          rse_expression=rse_expression,
                          grouping=parent_rule['grouping'],
                          weight=parent_rule['weight'],
                          lifetime=lifetime,
                          locked=parent_rule['locked'],
                          subscription_id=parent_rule['subscription_id'],
                          source_replica_expression=None,
                          activity=activity,
                          notify=parent_rule['notification'],
                          purge_replicas=parent_rule['purge_replicas'],
                          ignore_availability=True,
                          comment=parent_rule['comments'],
                          ask_approval=False,
                          asynchronous=False)[0]

    update_rule(rule_id=parent_rule_id, options={'child_rule_id': child_rule, 'lifetime': 0})
    return child_rule


@transactional_session
def list_rebalance_rule_candidates(rse, session=None):
    """
    List the rebalance rule candidates based on the agreed on specification
    """

    sql = """SELECT /*+ parallel(4) */ r.scope as scope, r.name as name, r.id as rule_id, r.rse_expression as rse_expression, r.subscription_id as subscription_id, d.bytes as bytes, d.length as length FROM dataset_locks dsl JOIN rules r ON (dsl.rule_id = r.id) JOIN dids d ON (dsl.scope = d.scope and dsl.name = d.name)
WHERE 
dsl.rse_id = rse2id('%s') and
(r.expires_at > sysdate+60 or r.expires_at is NULL) and
r.created_at < sysdate-60 and
r.account IN ('panda', 'root', 'ddmadmin') and
r.state = 'O' and
r.copies = 1 and
d.bytes is not NULL and
d.is_open = 0 and
r.grouping IN ('D', 'A') and
1 = (SELECT count(*) FROM dataset_locks WHERE scope=dsl.scope and name=dsl.name and rse_id = dsl.rse_id) and
0 < (SELECT count(*) FROM dataset_locks WHERE scope=dsl.scope and name=dsl.name and INSTR(id2rse(rse_id), 'TAPE') > 0)
ORDER BY dsl.accessed_at ASC NULLS FIRST, d.bytes DESC;
    """ & (rse)  # NOQA

    return session.execute(sql).fetchall()


@transactional_session
def select_target_rse(current_rse, rse_expression, subscription_id, rse_attributes, session=None):
    """
    Select a new target RSE for a rebalanced rule.

    :param current_rse:        RSE of the source.
    :param rse_expression:     RSE Expression of the source rule.
    :param subscription_id:    Subscription ID of the source rule.
    :param rse_attributes:     The attributes of the source rse.
    :param session:            The DB Session
    :returns:                  New RSE expression
    """
    if subscription_id:
        pass
        get_subscription_by_id(subscription_id, session)
    rses = parse_expression(expression=rse_expression, session=session)
    if len(rses) > 1:
        # Just define the RSE Expression without the current_rse
        return '(%s)\%s' % (rse_expression, current_rse)
    if rse_attributes['tier'] is True or rse_attributes['tier'] == 1:
        # Tier 1 should go to another Tier 1
        rses = parse_expression(expression='(tier=1&type=DATADISK)\\%s' % current_rse, filter={'availability_write': True}, session=session)
    if rse_attributes['tier'] == 2:
        # Tier 2 should go to another Tier 2
        rses = parse_expression(expression='(tier=2&type=DATADISK)\\%s' % current_rse, filter={'availability_write': True}, session=session)

    rseselector = RSESelector(account='ddmadmin', rses=rses, weight='freespace', copies=1, ignore_account_limit=True, session=session)
    return get_rse_name([rse_id for rse_id, _ in rseselector.select_rse(0)][0], session=session)


@transactional_session
def rebalance_rse(rse, max_bytes=1E9, max_files=None, session=None):
    """
    Rebalance data from an RSE

    :param rse:                  RSE to rebalance data from.
    :param max_bytes:            Maximum amount of bytes to rebalance.
    :param max_files:            Maximum amount of files to rebalance.
    :param session:              The database session.
    :returns:                    List of rebalanced datasets.
    """
    rebalanced_bytes = 0
    rebalanced_files = 0
    rebalanced_datasets = []
    rse_attributes = list_rse_attributes(rse=rse, session=session)

    for scope, name, rule_id, rse_expression, subscription_id, bytes, length in list_rebalance_rule_candidates(rse=rse):
        if rebalanced_bytes + bytes > max_bytes:
            continue
        if max_files:
            if rebalanced_files + length > max_files:
                continue
        # Select the target RSE for this rule
        target_rse_exp = select_target_rse(current_rse=rse,
                                           rse_expression=rse_expression,
                                           subscription_id=subscription_id,
                                           rse_attributes=rse_attributes,
                                           session=session)
        # Rebalance this rule
        rebalance_rule(parent_rule_id=rule_id,
                       activity='Rebalancing',
                       rse_expression=target_rse_exp)
        rebalanced_bytes += bytes
        rebalanced_files += length
        rebalanced_datasets.append((scope, name))
