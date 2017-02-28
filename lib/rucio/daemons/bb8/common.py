# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2016-2017

import logging
import sys

from datetime import datetime

from rucio.core.lock import get_dataset_locks
from rucio.core.rule import get_rule, add_rule, update_rule
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse import list_rse_attributes, get_rse_name
from rucio.core.rse_selector import RSESelector
# from rucio.core.subscription import get_subscription_by_id
from rucio.common.config import config_get
from rucio.common.exception import InsufficientTargetRSEs, RuleNotFound, DuplicateRule
from rucio.db.sqla.constants import RuleGrouping
from rucio.db.sqla.session import transactional_session


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rebalance_rule(parent_rule_id, activity, rse_expression, priority, source_replica_expression=None, comment=None):
    """
    Rebalance a replication rule to a new RSE

    :param parent_rule_id:             Replication rule to be rebalanced.
    :param activity:                   Activity to be used for the rebalancing.
    :param rse_expression:             RSE expression of the new rule.
    :param priority:                   Priority of the newly created rule.
    :param source_replica_expression:  Source replica expression of the new rule.
    :param comment:                    Comment to set on the new rules.
    :returns:                          The new child rule id.
    """
    parent_rule = get_rule(rule_id=parent_rule_id)

    if parent_rule['expires_at'] is None:
        lifetime = None
    else:
        lifetime = (parent_rule['expires_at'] - datetime.utcnow()).days * 24 * 3600 + (parent_rule['expires_at'] - datetime.utcnow()).seconds

    if parent_rule['grouping'] == RuleGrouping.ALL:
        grouping = 'ALL'
    elif parent_rule['grouping'] == RuleGrouping.NONE:
        grouping = 'NONE'
    else:
        grouping = 'DATASET'

    child_rule = add_rule(dids=[{'scope': parent_rule['scope'],
                                 'name': parent_rule['name']}],
                          account=parent_rule['account'],
                          copies=parent_rule['copies'],
                          rse_expression=rse_expression,
                          grouping=grouping,
                          weight=parent_rule['weight'],
                          lifetime=lifetime,
                          locked=parent_rule['locked'],
                          subscription_id=parent_rule['subscription_id'],
                          source_replica_expression=source_replica_expression,
                          activity=activity,
                          notify=parent_rule['notification'],
                          purge_replicas=parent_rule['purge_replicas'],
                          ignore_availability=False,
                          comment=parent_rule['comments'] if not comment else comment,
                          ask_approval=False,
                          asynchronous=False,
                          priority=priority)[0]

    update_rule(rule_id=parent_rule_id, options={'child_rule_id': child_rule, 'lifetime': 0})
    return child_rule


@transactional_session
def list_rebalance_rule_candidates(rse, mode=None, session=None):
    """
    List the rebalance rule candidates based on the agreed on specification

    :param rse:          RSE of the source.
    :param mode:         Rebalancing mode.
    :param session:      DB Session.
    """

    if mode is None:
        sql = """SELECT dsl.scope as scope, dsl.name as name, rawtohex(r.id) as rule_id, r.rse_expression as rse_expression, r.subscription_id as subscription_id, d.bytes as bytes, d.length as length FROM atlas_rucio.dataset_locks dsl JOIN atlas_rucio.rules r ON (dsl.rule_id = r.id) JOIN atlas_rucio.dids d ON (dsl.scope = d.scope and dsl.name = d.name)
WHERE
dsl.rse_id = atlas_rucio.rse2id(:rse) and
(r.expires_at > sysdate+60 or r.expires_at is NULL) and
r.created_at < sysdate-60 and
r.account IN ('panda', 'root', 'ddmadmin') and
r.state = 'O' and
r.copies = 1 and
r.did_type = 'D' and
r.child_rule_id is NULL and
d.bytes is not NULL and
d.is_open = 0 and
d.did_type = 'D' and
r.grouping IN ('D', 'A') and
1 = (SELECT count(*) FROM atlas_rucio.dataset_locks WHERE scope=dsl.scope and name=dsl.name and rse_id = dsl.rse_id) and
0 < (SELECT count(*) FROM atlas_rucio.dataset_locks WHERE scope=dsl.scope and name=dsl.name and rse_id IN (SELECT id FROM atlas_rucio.rses WHERE rse_type='TAPE'))
ORDER BY dsl.accessed_at ASC NULLS FIRST, d.bytes DESC"""  # NOQA
    elif mode == 'decomission':
        sql = """SELECT r.scope, r.name, rawtohex(r.id) as rule_id, r.rse_expression as rse_expression, r.subscription_id as subscription_id, 0 as bytes, 0 as length FROM atlas_rucio.rules r
WHERE
r.id IN (SELECT rule_id FROM atlas_rucio.locks WHERE rse_id = atlas_rucio.rse2id(:rse) GROUP BY rule_id) and
r.state = 'O' and
r.child_rule_id is NULL"""  # NOQA

    return session.execute(sql, {'rse': rse}).fetchall()


@transactional_session
def select_target_rse(current_rse, rse_expression, subscription_id, rse_attributes, other_rses=[], exclude_expression=None, force_expression=None, session=None):
    """
    Select a new target RSE for a rebalanced rule.

    :param current_rse:          RSE of the source.
    :param rse_expression:       RSE Expression of the source rule.
    :param subscription_id:      Subscription ID of the source rule.
    :param rse_attributes:       The attributes of the source rse.
    :param other_rses:           Other RSEs with existing dataset replicas.
    :param exclude_expression:   Exclude this rse_expression from being target_rses.
    :param force_expression:     Force a specific rse_expression as target.
    :param session:              The DB Session
    :returns:                    New RSE expression
    """

    if exclude_expression:
        target_rse = '(%s)\\%s' % (exclude_expression, current_rse)
    else:
        target_rse = current_rse

    rses = parse_expression(expression=rse_expression, session=session)
    # if subscription_id:
    #     pass
    #     # get_subscription_by_id(subscription_id, session)
    if force_expression is not None:
        rses = parse_expression(expression='(%s)\\%s' % (force_expression, target_rse), filter={'availability_write': True}, session=session)
    elif len(rses) > 1:
        # Just define the RSE Expression without the current_rse
        return '(%s)\\%s' % (rse_expression, target_rse)
    elif rse_attributes['tier'] is True or rse_attributes['tier'] == '1':
        # Tier 1 should go to another Tier 1
        rses = parse_expression(expression='(tier=1&type=DATADISK)\\%s' % target_rse, filter={'availability_write': True}, session=session)
    elif rse_attributes['tier'] == 2 or rse_attributes['tier'] == '2':
        # Tier 2 should go to another Tier 2
        rses = parse_expression(expression='(tier=2&type=DATADISK)\\%s' % target_rse, filter={'availability_write': True}, session=session)

    rseselector = RSESelector(account='ddmadmin', rses=rses, weight='freespace', copies=1, ignore_account_limit=True, session=session)
    return get_rse_name([rse_id for rse_id, _ in rseselector.select_rse(size=0,
                                                                        preferred_rse_ids=[],
                                                                        blacklist=other_rses)][0], session=session)


@transactional_session
def rebalance_rse(rse, max_bytes=1E9, max_files=None, dry_run=False, exclude_expression=None, comment=None, force_expression=None, mode=None, priority=3, source_replica_expression=None, session=None):
    """
    Rebalance data from an RSE

    :param rse:                        RSE to rebalance data from.
    :param max_bytes:                  Maximum amount of bytes to rebalance.
    :param max_files:                  Maximum amount of files to rebalance.
    :param dry_run:                    Only run in dry-run mode.
    :param exclude_expression:         Exclude this rse_expression from being target_rses.
    :param comment:                    Comment to set on the new rules.
    :param force_expression:           Force a specific rse_expression as target.
    :param mode:                       BB8 mode to execute (None=normal, 'decomission'=Decomission mode)
    :param priority:                   Priority of the new created rules.
    :param source_replica_expression:  Source replica expression of the new created rules.
    :param session:                    The database session.
    :returns:                          List of rebalanced datasets.
    """
    rebalanced_bytes = 0
    rebalanced_files = 0
    rebalanced_datasets = []
    rse_attributes = list_rse_attributes(rse=rse, session=session)

    print '***************************'
    print 'BB8 - Execution Summary'
    print 'Mode:    %s' % ('STANDARD' if mode is None else mode.upper())
    print 'Dry Run: %s' % (dry_run)
    print '***************************'

    print 'scope:name rule_id bytes(Gb) target_rse child_rule_id'

    for scope, name, rule_id, rse_expression, subscription_id, bytes, length in list_rebalance_rule_candidates(rse=rse, mode=mode):
        if force_expression is not None and subscription_id is not None:
            continue

        if rebalanced_bytes + bytes > max_bytes:
            continue
        if max_files:
            if rebalanced_files + length > max_files:
                continue

        try:
            other_rses = [r['rse_id'] for r in get_dataset_locks(scope, name, session=session)]

            # Select the target RSE for this rule
            try:
                target_rse_exp = select_target_rse(current_rse=rse,
                                                   rse_expression=rse_expression,
                                                   subscription_id=subscription_id,
                                                   rse_attributes=rse_attributes,
                                                   other_rses=other_rses,
                                                   exclude_expression=exclude_expression,
                                                   force_expression=force_expression,
                                                   session=session)
                # Rebalance this rule
                if not dry_run:
                    child_rule_id = rebalance_rule(parent_rule_id=rule_id,
                                                   activity='Data Rebalancing',
                                                   rse_expression=target_rse_exp,
                                                   priority=priority,
                                                   source_replica_expression=source_replica_expression,
                                                   comment=comment)
                else:
                    child_rule_id = ''
            except (InsufficientTargetRSEs, DuplicateRule, RuleNotFound):
                continue
            print '%s:%s %s %d %s %s' % (scope, name, str(rule_id), int(bytes / 1E9), target_rse_exp, child_rule_id)
            rebalanced_bytes += bytes
            rebalanced_files += length
            rebalanced_datasets.append((scope, name, bytes, length, target_rse_exp, rule_id, child_rule_id))
        except Exception as error:
            print 'Exception %s occured while rebalancing %s:%s, rule_id: %s!' % (str(error), scope, name, str(rule_id))
            raise error

    print 'BB8 is rebalancing %d Gb of data (%d rules)' % (int(rebalanced_bytes / 1E9), len(rebalanced_datasets))
    return rebalanced_datasets
