# Copyright 2016-2018 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2017
# - Vincent Garonne <vgaronne@gmail.com>, 2016-2018
# - Tomas Javurek <tomas.javurek@cern.ch>, 2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2019
#
# PY3K COMPATIBLE

from __future__ import print_function, division

import logging
import sys

from datetime import datetime

from sqlalchemy import and_

from rucio.core.lock import get_dataset_locks, get_replica_locks
from rucio.core.rule import get_rule, add_rule, update_rule
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse import add_rse_attribute, list_rse_attributes, get_rse_id, get_rse_name, update_rse
from rucio.core.rse_selector import RSESelector
from rucio.common.config import config_get
from rucio.common.exception import (InsufficientTargetRSEs, RuleNotFound, DuplicateRule,
                                    InsufficientAccountLimit)
from rucio.common.types import InternalAccount

from rucio.daemons.bb8.common import _list_rebalance_rule_candidates_dump

from rucio.db.sqla.session import transactional_session
from rucio.db.sqla import models
from rucio.db.sqla.constants import RuleGrouping

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rebalance_rule(parent_rule, activity, rse_expression, priority, source_replica_expression='*\\bb8-enabled=false', comment=None):
    """
    Rebalance a replication rule to a new RSE

    :param parent_rule:                Replication rule to be rebalanced.
    :param activity:                   Activity to be used for the rebalancing.
    :param rse_expression:             RSE expression of the new rule.
    :param priority:                   Priority of the newly created rule.
    :param source_replica_expression:  Source replica expression of the new rule.
    :param comment:                    Comment to set on the new rules.
    :returns:                          The new child rule id.
    """

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

    # check if concurrent replica at target rse does not exist
    concurrent_replica = False
    try:
        for lock in get_dataset_locks(parent_rule['scope'], parent_rule['name']):
            if lock['rse'] == rse_expression:
                concurrent_replica = True
    except Exception as error:
        concurrent_replica = True
        print('Exception: get_dataset_locks not feasible for %s %s:' % (parent_rule['scope'], parent_rule['name']))
        raise error
    if concurrent_replica:
        return 'Concurrent replica exists at target rse!'
    print(concurrent_replica)

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
                          ignore_account_limit=True,
                          priority=priority)[0]

    update_rule(rule_id=parent_rule['id'], options={'child_rule_id': child_rule, 'lifetime': 0})
    return child_rule


@transactional_session
def list_rebalance_rule_candidates(rse, session=None):
    """
    List the rebalance rule candidates based on the agreed on specification

    :param rse:          RSE of the source.
    :param mode:         Rebalancing mode.
    :param session:      DB Session.
    """

    rse_id = get_rse_id(rse)

    # if dumps are available for the site, use dumps
    try:
        summary = _list_rebalance_rule_candidates_dump(rse, 'decommission')
    except Exception as e:  # NOQA, pylint: disable=W0612
        print('Can\'t get the dataset dump for RSE %s. Fetching from the database, this could take a while.' % (rse))
        summary = []
    if len(summary) > 0:
        return summary
    else:
        # this query will take some time in the real db
        query = session.query(models.ReplicaLock.scope,
                              models.ReplicaLock.name,
                              models.ReplicationRule.id,
                              models.ReplicationRule.rse_expression,
                              models.ReplicationRule.subscription_id,
                              models.DataIdentifier.bytes,
                              models.DataIdentifier.length,
                              models.ReplicaLock.bytes).\
            join(models.ReplicationRule, models.ReplicationRule.id == models.ReplicaLock.rule_id).\
            join(models.DataIdentifier, and_(models.ReplicaLock.scope == models.DataIdentifier.scope, models.ReplicaLock.name == models.DataIdentifier.name)).\
            filter(models.DatasetLock.rse_id == rse_id)

        summary = query.order_by(models.DataIdentifier.bytes).all()
        return summary


@transactional_session
def select_target_rse(parent_rule, current_rse, rse_expression, subscription_id, rse_attributes, other_rses=[], exclude_expression=None, force_expression=None, session=None):
    """
    Select a new target RSE for a rebalanced rule.

    :param parent_rule           rule that is rebalanced.
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
    try:
        rses = parse_expression(expression=rse_expression, session=session)
    except Exception as error:  # NOQA, pylint: disable=W0612
        pass
    # TODO: dest rse selection should be configurable, there might be cases when tier is not defined, or concept of DATADISKS is not present.
    if force_expression is not None:
        if parent_rule['grouping'] != RuleGrouping.NONE:
            rses = parse_expression(expression='(%s)\\%s' % (force_expression, target_rse), filter={'availability_write': True}, session=session)
        else:
            # in order to avoid replication of the part of distributed dataset not present at rabalanced rse -> rses in force_expression
            # this will be extended with development of delayed rule
            rses = parse_expression(expression='((%s)|(%s))\\%s' % (force_expression, rse_expression, target_rse), filter={'availability_write': True}, session=session)
    elif len(rses) > 1:
        # Just define the RSE Expression without the current_rse
        return '(%s)\\%s' % (rse_expression, target_rse)
    elif rse_attributes['tier'] is True or int(rse_attributes['tier']) == 1:
        # Tier 1 should go to another Tier 1
        rses = parse_expression(expression='(tier=1&type=DATADISK)\\%s' % target_rse, filter={'availability_write': True}, session=session)
    elif int(rse_attributes['tier']) == 2:
        # Tier 2 should go to another Tier 2
        rses = parse_expression(expression='(tier=2&type=DATADISK)\\%s' % target_rse, filter={'availability_write': True}, session=session)
    elif int(rse_attributes['tier']) == 3:
        # Tier 3 will go to Tier 2, since we don't have enough t3s
        rses = parse_expression(expression='((tier=2&type=DATADISK)\\datapolicynucleus=1)\\%s' % target_rse, filter={'availability_write': True}, session=session)
    rseselector = RSESelector(account=InternalAccount('ddmadmin'), rses=rses, weight=None, copies=1, ignore_account_limit=True, session=session)
    return get_rse_name([rse_id for rse_id, _, _ in rseselector.select_rse(size=0, preferred_rse_ids=[], blacklist=other_rses)][0], session=session)


@transactional_session
def decommission_rse(rse, dry_run=False, exclude_expression=None, comment=None, force_expression=None, mode=None, priority=3, source_replica_expression='*\\bb8-enabled=false', session=None):
    """
    Move data out from an RSE in order to decommission it.

    :param rse:                        RSE to rebalance data from.
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
    rse_id = get_rse_id(rse=rse)
    rse_attributes = list_rse_attributes(rse_id=rse_id, session=session)
    if 'decommissioned' in rse_attributes.keys():
        print('RSE %s already in decommissioning process.' % rse)
        print('Execute:')
        print('    # rucio-mandalorian %s --get-report' % rse)
        print('in order to check the progress of the decommissioning process.')
        return
    if not dry_run:
        # Avoid new data to go to the decommissioned RSE
        update_rse(rse_id, {'availability_write': False})
        add_rse_attribute(rse_id=rse_id, key='decommissioned', value='True')

    print('***************************')
    print('Mandalorian - Execution Summary')
    print('Mode:    %s' % ('STANDARD' if mode is None else mode.upper()))
    print('Dry Run: %s' % (dry_run))
    print('***************************')

    print('scope:name rule_id bytes(Gb) target_rse child_rule_id, grouping')

    for scope, name, rule_id, rse_expression, subscription_id, bytes, length, fsize in list(set(list_rebalance_rule_candidates(rse=rse))):
        if force_expression is not None and subscription_id is not None:
            continue

        try:
            rule = get_rule(rule_id=rule_id)
            other_rses = [r['rse_id'] for r in get_replica_locks(scope, name, session=session)]
            # Select the target RSE for this rule
            try:
                target_rse_exp = select_target_rse(parent_rule=rule,
                                                   current_rse=rse,
                                                   rse_expression=rse_expression,
                                                   subscription_id=subscription_id,
                                                   rse_attributes=rse_attributes,
                                                   other_rses=other_rses,
                                                   exclude_expression=exclude_expression,
                                                   force_expression=force_expression,
                                                   session=session)
                # Rebalance this rule
                if not dry_run:
                    child_rule_id = rebalance_rule(parent_rule=rule,
                                                   activity='Data rebalancing',  # Should have it's own activity?
                                                   rse_expression=target_rse_exp,
                                                   priority=priority,
                                                   source_replica_expression=source_replica_expression,
                                                   comment=comment)
                else:
                    child_rule_id = ''
            except (InsufficientTargetRSEs, DuplicateRule, RuleNotFound, InsufficientAccountLimit):
                continue
            print('%s:%s %s %d %s %s %s' % (scope, name, str(rule_id), bytes, target_rse_exp, child_rule_id, rule['grouping']))
            if 'Concurrent' in str(child_rule_id):
                print(str(child_rule_id))
                continue
            rebalanced_bytes += bytes
            rebalanced_files += 0 if length is None else length
            rebalanced_datasets.append((scope, name, bytes, length, target_rse_exp, rule_id, child_rule_id))
        except Exception as error:
            print('Exception %s occured while rebalancing %s:%s, rule_id: %s' % (str(error.args), scope, name, str(rule_id)))
            raise error

    print('The Mandalorian is moving %d Gb of data (%d rules) from RSE %s' % (rebalanced_bytes, len(rebalanced_datasets), rse))
    return rebalanced_datasets
