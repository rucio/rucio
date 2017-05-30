# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2017
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2017

import logging
import sys

from ConfigParser import NoOptionError
from copy import deepcopy
from datetime import datetime, timedelta
from re import match
from string import Template

from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import and_, or_, bindparam, text, true, null

import rucio.core.did
import rucio.core.lock  # import get_replica_locks, get_files_and_replica_locks_of_dataset
import rucio.core.replica  # import get_and_lock_file_replicas, get_and_lock_file_replicas_for_dataset
import rucio.common.policy  # import get_scratch_policy, define_eol

from rucio.common.config import config_get
from rucio.common.exception import (InvalidRSEExpression, InvalidReplicationRule, InsufficientAccountLimit,
                                    DataIdentifierNotFound, RuleNotFound, InputValidationError,
                                    ReplicationRuleCreationTemporaryFailed, InsufficientTargetRSEs, RucioException,
                                    InvalidRuleWeight, StagingAreaRuleRequiresLifetime, DuplicateRule,
                                    InvalidObject, RSEBlacklisted, RuleReplaceFailed, RequestNotFound,
                                    ManualRuleApprovalBlocked, UnsupportedOperation)
from rucio.common.schema import validate_schema
from rucio.common.utils import str_to_date, sizefmt
from rucio.core import account_counter, rse_counter
from rucio.core.account import get_account
from rucio.core.lifetime_exception import define_eol
from rucio.core.message import add_message
from rucio.core.monitor import record_timer_block
from rucio.core.rse import get_rse_name, list_rse_attributes, get_rse
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.request import get_request_by_did, queue_requests, cancel_request_did, update_requests_priority
from rucio.core.rse_selector import RSESelector
from rucio.core.rule_grouping import apply_rule_grouping, repair_stuck_locks_and_apply_rule_grouping, create_transfer_dict
from rucio.db.sqla import models
from rucio.db.sqla.constants import (LockState, ReplicaState, RuleState, RuleGrouping,
                                     DIDAvailability, DIDReEvaluation, DIDType,
                                     RequestType, RuleNotification, OBSOLETE, RSEType)
from rucio.db.sqla.session import read_session, transactional_session, stream_session

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


@transactional_session
def add_rule(dids, account, copies, rse_expression, grouping, weight, lifetime, locked, subscription_id,
             source_replica_expression=None, activity='User Subscriptions', notify=None, purge_replicas=False,
             ignore_availability=False, comment=None, ask_approval=False, asynchronous=False, ignore_account_limit=False,
             priority=3, split_container=False, session=None):
    """
    Adds a replication rule for every did in dids

    :param dids:                       List of data identifiers.
    :param account:                    Account issuing the rule.
    :param copies:                     The number of replicas.
    :param rse_expression:             RSE expression which gets resolved into a list of rses.
    :param grouping:                   ALL -  All files will be replicated to the same RSE.
                                       DATASET - All files in the same dataset will be replicated to the same RSE.
                                       NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
    :param weight:                     Weighting scheme to be used.
    :param lifetime:                   The lifetime of the replication rule in seconds.
    :param locked:                     If the rule is locked.
    :param subscription_id:            The subscription_id, if the rule is created by a subscription.
    :param source_replica_expression:  Only use replicas as source from this RSEs.
    :param activity:                   Activity to be passed on to the conveyor.
    :param notify:                     Notification setting of the rule ('Y', 'N', 'C'; None = 'N').
    :param purge_replicas:             Purge setting if a replica should be directly deleted after the rule is deleted.
    :param ignore_availability:        Option to ignore the availability of RSEs.
    :param comment:                    Comment about the rule.
    :param ask_approval:               Ask for approval for this rule.
    :param asynchronous:               Create replication rule asynchronously by the judge-injector.
    :param ignore_account_limit:       Ignore quota and create the rule outside of the account limits.
    :param priority:                   Priority of the rule and the transfers which should be submitted.
    :param split_container:            Should a container rule be split into individual dataset rules.
    :param session:                    The database session in use.
    :returns:                          A list of created replication rule ids.
    :raises:                           InvalidReplicationRule, InsufficientAccountLimit, InvalidRSEExpression, DataIdentifierNotFound, ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight,
                                       StagingAreaRuleRequiresLifetime, DuplicateRule, RSEBlacklisted, ScratchDiskLifetimeConflict, ManualRuleApprovalBlocked
    """
    rule_ids = []

    with record_timer_block('rule.add_rule'):
        # 1. Resolve the rse_expression into a list of RSE-ids
        with record_timer_block('rule.add_rule.parse_rse_expression'):
            if ignore_availability:
                rses = parse_expression(rse_expression, session=session)
            else:
                rses = parse_expression(rse_expression, filter={'availability_write': True}, session=session)

            if lifetime is None:  # Check if one of the rses is a staging area
                if [rse for rse in rses if rse.get('staging_area', False)]:
                    raise StagingAreaRuleRequiresLifetime()

            # Check SCRATCHDISK Policy
            lifetime = rucio.common.policy.get_scratch_policy(account, rses, lifetime, session=session)

            # Auto-lock rules for TAPE rses
            if not locked and lifetime is None:
                if [rse for rse in rses if rse.get('rse_type', RSEType.DISK) == RSEType.TAPE]:
                    locked = True

            # Block manual approval if RSE does not allow it
            if ask_approval:
                for rse in rses:
                    if list_rse_attributes(rse=None, rse_id=rse['id'], session=session).get('block_manual_approval', False):
                        raise ManualRuleApprovalBlocked()

            if source_replica_expression:
                source_rses = parse_expression(source_replica_expression, session=session)
            else:
                source_rses = []

        # 2. Create the rse selector
        with record_timer_block('rule.add_rule.create_rse_selector'):
            rseselector = RSESelector(account=account, rses=rses, weight=weight, copies=copies, ignore_account_limit=ask_approval or ignore_account_limit, session=session)

        expires_at = datetime.utcnow() + timedelta(seconds=lifetime) if lifetime is not None else None

        if notify == 'Y':
            notify = RuleNotification.YES
        elif notify == 'C':
            notify = RuleNotification.CLOSE
        else:
            notify = RuleNotification.NO

        for elem in dids:
            # 3. Get the did
            with record_timer_block('rule.add_rule.get_did'):
                try:
                    did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == elem['scope'],
                                                                      models.DataIdentifier.name == elem['name']).one()
                except NoResultFound:
                    raise DataIdentifierNotFound('Data identifier %s:%s is not valid.' % (elem['scope'], elem['name']))
                except TypeError as error:
                    raise InvalidObject(error.args)

            # 3.5 Get the lifetime
            eol_at = define_eol(elem['scope'], elem['name'], rses, session=session)

            # 4. Create the replication rule
            with record_timer_block('rule.add_rule.create_rule'):
                if grouping == 'ALL':
                    grouping = RuleGrouping.ALL
                elif grouping == 'NONE':
                    grouping = RuleGrouping.NONE
                else:
                    grouping = RuleGrouping.DATASET

                new_rule = models.ReplicationRule(account=account,
                                                  name=elem['name'],
                                                  scope=elem['scope'],
                                                  did_type=did.did_type,
                                                  copies=copies,
                                                  rse_expression=rse_expression,
                                                  locked=locked,
                                                  grouping=grouping,
                                                  expires_at=expires_at,
                                                  weight=weight,
                                                  source_replica_expression=source_replica_expression,
                                                  activity=activity,
                                                  subscription_id=subscription_id,
                                                  notification=notify,
                                                  purge_replicas=purge_replicas,
                                                  ignore_availability=ignore_availability,
                                                  comments=comment,
                                                  ignore_account_limit=ignore_account_limit,
                                                  priority=priority,
                                                  split_container=split_container,
                                                  eol_at=eol_at)
                try:
                    new_rule.save(session=session)
                except IntegrityError as error:
                    if match('.*ORA-00001.*', str(error.args[0]))\
                       or match('.*IntegrityError.*UNIQUE constraint failed.*', str(error.args[0]))\
                       or match('.*1062.*Duplicate entry.*for key.*', str(error.args[0]))\
                       or match('.*sqlite3.IntegrityError.*are not unique.*', error.args[0]):
                        raise DuplicateRule()
                    raise InvalidReplicationRule(error.args[0])
                rule_ids.append(new_rule.id)

            if ask_approval:
                new_rule.state = RuleState.WAITING_APPROVAL
                # Block manual approval for multi-rse rules
                if len(rses) > 1:
                    raise InvalidReplicationRule('Ask approval is not allowed for rules with multiple RSEs')
                if len(rses) == 1 and not did.is_open and did.bytes is not None and did.length is not None:
                    # This rule can be considered for auto-approval:
                    rse_attr = list_rse_attributes(rse=None, rse_id=rses[0]['id'], session=session)
                    auto_approve = False
                    if 'auto_approve_bytes' in rse_attr and 'auto_approve_files' in rse_attr:
                        if did.bytes < int(rse_attr.get('auto_approve_bytes')) and did.length < int(rse_attr.get('auto_approve_bytes')):
                            auto_approve = True
                    elif did.bytes < int(rse_attr.get('auto_approve_bytes', -1)):
                        auto_approve = True
                    elif did.length < int(rse_attr.get('auto_approve_files', -1)):
                        auto_approve = True
                    if auto_approve:
                        logging.debug("Auto approving rule %s" % str(new_rule.id))
                        logging.debug("Created rule %s for injection" % str(new_rule.id))
                        approve_rule(rule_id=new_rule.id, notify_approvers=False, session=session)
                        continue
                logging.debug("Created rule %s in waiting for approval" % (str(new_rule.id)))
                __create_rule_approval_email(rule=new_rule, session=session)
                continue

            # Force ASYNC mode for large rules
            if did.length >= 10000:
                asynchronous = True
                logging.debug("Forced injection of rule %s" % (str(new_rule.id)))

            if asynchronous:
                # TODO: asynchronous mode only available for closed dids (on the whole tree?)
                new_rule.state = RuleState.INJECT
                logging.debug("Created rule %s for injection" % (str(new_rule.id)))
                continue

            # If Split Container is chosen, the rule will be processed ASYNC
            if split_container and did.did_type == DIDType.CONTAINER:
                new_rule.state = RuleState.INJECT
                logging.debug("Created rule %s for injection due to Split Container mode" % (str(new_rule.id)))
                continue

            # 5. Resolve the did to its contents
            with record_timer_block('rule.add_rule.resolve_dids_to_locks_replicas'):
                # Get all Replicas, not only the ones interesting for the rse_expression
                datasetfiles, locks, replicas, source_replicas = __resolve_did_to_locks_and_replicas(did=did,
                                                                                                     nowait=False,
                                                                                                     restrict_rses=[rse['id'] for rse in rses],
                                                                                                     source_rses=[rse['id'] for rse in source_rses],
                                                                                                     session=session)

            sumfiles = sum([len(x['files']) for x in datasetfiles])
            if sumfiles > 30000:
                logging.warning('Rule %s for %s:%s involves %d files' % (str(new_rule.id), new_rule.scope, new_rule.name, sumfiles))

            # 6. Apply the replication rule to create locks, replicas and transfers
            with record_timer_block('rule.add_rule.create_locks_replicas_transfers'):
                try:
                    __create_locks_replicas_transfers(datasetfiles=datasetfiles,
                                                      locks=locks,
                                                      replicas=replicas,
                                                      source_replicas=source_replicas,
                                                      rseselector=rseselector,
                                                      rule=new_rule,
                                                      preferred_rse_ids=[],
                                                      source_rses=[rse['id'] for rse in source_rses],
                                                      session=session)
                except IntegrityError as error:
                    raise ReplicationRuleCreationTemporaryFailed(error.args[0])

            if new_rule.locks_stuck_cnt > 0:
                new_rule.state = RuleState.STUCK
                new_rule.error = 'MissingSourceReplica'
                if new_rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=new_rule.id).update({'state': LockState.STUCK})
            elif new_rule.locks_replicating_cnt == 0:
                new_rule.state = RuleState.OK
                if new_rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=new_rule.id).update({'state': LockState.OK})
                    session.flush()
                    generate_message_for_dataset_ok_callback(rule=new_rule, session=session)
                if new_rule.notification == RuleNotification.YES:
                    generate_email_for_rule_ok_notification(rule=new_rule, session=session)
            else:
                new_rule.state = RuleState.REPLICATING
                if new_rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=new_rule.id).update({'state': LockState.REPLICATING})

            # Add rule to History
            insert_rule_history(rule=new_rule, recent=True, longterm=True, session=session)

            logging.info("Created rule %s [%d/%d/%d] for did %s:%s in state %s" % (str(new_rule.id), new_rule.locks_ok_cnt, new_rule.locks_replicating_cnt, new_rule.locks_stuck_cnt, new_rule.scope, new_rule.name, str(new_rule.state)))

    return rule_ids


@transactional_session
def add_rules(dids, rules, session=None):
    """
    Adds a list of replication rules to every did in dids

    :params dids:    List of data identifiers.
    :param rules:    List of dictionaries defining replication rules.
                     {account, copies, rse_expression, grouping, weight, lifetime, locked, subscription_id, source_replica_expression, activity, notifiy, purge_replicas}
    :param session:  The database session in use.
    :returns:        Dictionary (scope, name) with list of created rule ids
    :raises:         InvalidReplicationRule, InsufficientAccountLimit, InvalidRSEExpression, DataIdentifierNotFound, ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight,
                     StagingAreaRuleRequiresLifetime, DuplicateRule, RSEBlacklisted, ScratchDiskLifetimeConflict, ManualRuleApprovalBlocked
    """

    with record_timer_block('rule.add_rules'):
        rule_ids = {}

        # 1. Fetch the RSEs from the RSE expression to restrict further queries just on these RSEs
        restrict_rses = []
        all_source_rses = []
        with record_timer_block('rule.add_rules.parse_rse_expressions'):
            for rule in rules:
                if rule.get('ignore_availability'):
                    restrict_rses.extend(parse_expression(rule['rse_expression'], session=session))
                else:
                    restrict_rses.extend(parse_expression(rule['rse_expression'], filter={'availability_write': True}, session=session))
            restrict_rses = list(set([rse['id'] for rse in restrict_rses]))

            for rule in rules:
                if rule.get('source_replica_expression'):
                    all_source_rses.extend(parse_expression(rule.get('source_replica_expression'), session=session))
            all_source_rses = list(set([rse['id'] for rse in all_source_rses]))

        for elem in dids:
            rule_ids[(elem['scope'], elem['name'])] = []
            # 2. Get the did
            with record_timer_block('rule.add_rules.get_did'):
                try:
                    did = session.query(models.DataIdentifier).filter(
                        models.DataIdentifier.scope == elem['scope'],
                        models.DataIdentifier.name == elem['name']).one()
                except NoResultFound:
                    raise DataIdentifierNotFound('Data identifier %s:%s is not valid.' % (elem['scope'], elem['name']))
                except TypeError as error:
                    raise InvalidObject(error.args)

            # 3. Resolve the did into its contents
            with record_timer_block('rule.add_rules.resolve_dids_to_locks_replicas'):
                # Get all Replicas, not only the ones interesting for the rse_expression
                datasetfiles, locks, replicas, source_replicas = __resolve_did_to_locks_and_replicas(did=did,
                                                                                                     nowait=False,
                                                                                                     restrict_rses=restrict_rses,
                                                                                                     source_rses=all_source_rses,
                                                                                                     session=session)

            for rule in rules:
                with record_timer_block('rule.add_rules.add_rule'):
                    # 4. Resolve the rse_expression into a list of RSE-ids
                    if rule.get('ignore_availability'):
                        rses = parse_expression(rule['rse_expression'], session=session)
                    else:
                        rses = parse_expression(rule['rse_expression'], filter={'availability_write': True}, session=session)

                    if rule.get('lifetime', None) is None:  # Check if one of the rses is a staging area
                        if [rse for rse in rses if rse.get('staging_area', False)]:
                            raise StagingAreaRuleRequiresLifetime()

                    # Check SCRATCHDISK Policy
                    rule['lifetime'] = rucio.common.policy.get_scratch_policy(rule.get('account'), rses, rule.get('lifetime', None), session=session)

                    # 4.5 Get the lifetime
                    eol_at = define_eol(did.scope, did.name, rses, session=session)

                    # Auto-lock rules for TAPE rses
                    if not rule.get('locked', False) and rule.get('lifetime', None) is None:
                        if [rse for rse in rses if rse.get('rse_type', RSEType.DISK) == RSEType.TAPE]:
                            rule['locked'] = True

                    # Block manual approval if RSE does not allow it
                    if rule.get('ask_approval', False):
                        for rse in rses:
                            if list_rse_attributes(rse=None, rse_id=rse['id'], session=session).get('block_manual_approval', False):
                                raise ManualRuleApprovalBlocked()

                    if rule.get('source_replica_expression'):
                        source_rses = parse_expression(rule.get('source_replica_expression'), session=session)
                    else:
                        source_rses = []

                    # 5. Create the RSE selector
                    with record_timer_block('rule.add_rules.create_rse_selector'):
                        rseselector = RSESelector(account=rule['account'], rses=rses, weight=rule.get('weight'), copies=rule['copies'], ignore_account_limit=rule.get('ask_approval', False), session=session)

                    # 4. Create the replication rule
                    with record_timer_block('rule.add_rules.create_rule'):
                        if rule.get('grouping') == 'ALL':
                            grouping = RuleGrouping.ALL
                        elif rule.get('grouping') == 'NONE':
                            grouping = RuleGrouping.NONE
                        else:
                            grouping = RuleGrouping.DATASET
                        expires_at = datetime.utcnow() + timedelta(seconds=rule.get('lifetime')) if rule.get('lifetime') is not None else None
                        notify = rule.get('notify')
                        if notify == 'Y':
                            notify = RuleNotification.YES
                        elif notify == 'C':
                            notify = RuleNotification.CLOSE
                        else:
                            notify = RuleNotification.NO

                        new_rule = models.ReplicationRule(account=rule['account'],
                                                          name=did.name,
                                                          scope=did.scope,
                                                          did_type=did.did_type,
                                                          copies=rule['copies'],
                                                          rse_expression=rule['rse_expression'],
                                                          locked=rule.get('locked'),
                                                          grouping=grouping,
                                                          expires_at=expires_at,
                                                          weight=rule.get('weight'),
                                                          source_replica_expression=rule.get('source_replica_expression'),
                                                          activity=rule.get('activity'),
                                                          subscription_id=rule.get('subscription_id'),
                                                          notification=notify,
                                                          purge_replicas=rule.get('purge_replicas', False),
                                                          ignore_availability=rule.get('ignore_availability', False),
                                                          comments=rule.get('comment', None),
                                                          priority=rule.get('priority', 3),
                                                          split_container=rule.get('split_container', False),
                                                          eol_at=eol_at)
                        try:
                            new_rule.save(session=session)
                        except IntegrityError as error:
                            if match('.*ORA-00001.*', str(error.args[0])):
                                raise DuplicateRule()
                            elif str(error.args[0]) == '(IntegrityError) UNIQUE constraint failed: rules.scope, rules.name, rules.account, rules.rse_expression, rules.copies':
                                raise DuplicateRule()
                            raise InvalidReplicationRule(error.args[0])

                        rule_ids[(did.scope, did.name)].append(new_rule.id)

                    if rule.get('ask_approval', False):
                        new_rule.state = RuleState.WAITING_APPROVAL
                        # Block manual approval for multi-rse rules
                        if len(rses) > 1:
                            raise InvalidReplicationRule('Ask approval is not allowed for rules with multiple RSEs')
                        if len(rses) == 1 and not did.is_open and did.bytes is not None and did.length is not None:
                            # This rule can be considered for auto-approval:
                            rse_attr = list_rse_attributes(rse=None, rse_id=rses[0]['id'], session=session)
                            auto_approve = False
                            if 'auto_approve_bytes' in rse_attr and 'auto_approve_files' in rse_attr:
                                if did.bytes < int(rse_attr.get('auto_approve_bytes')) and did.length < int(rse_attr.get('auto_approve_bytes')):
                                    auto_approve = True
                            elif did.bytes < int(rse_attr.get('auto_approve_bytes', -1)):
                                auto_approve = True
                            elif did.length < int(rse_attr.get('auto_approve_files', -1)):
                                auto_approve = True
                            if auto_approve:
                                logging.debug("Auto approving rule %s" % str(new_rule.id))
                                logging.debug("Created rule %s for injection" % str(new_rule.id))
                                approve_rule(rule_id=new_rule.id, notify_approvers=False, session=session)
                                continue
                        logging.debug("Created rule %s in waiting for approval" % str(new_rule.id))
                        __create_rule_approval_email(rule=new_rule, session=session)
                        continue

                    if rule.get('asynchronous', False):
                        new_rule.state = RuleState.INJECT
                        logging.debug("Created rule %s for injection" % str(new_rule.id))
                        continue

                    if rule.get('split_container', False) and did.did_type == DIDType.CONTAINER:
                        new_rule.state = RuleState.INJECT
                        logging.debug("Created rule %s for injection due to Split Container mode" % str(new_rule.id))
                        continue

                    # 5. Apply the replication rule to create locks, replicas and transfers
                    with record_timer_block('rule.add_rules.create_locks_replicas_transfers'):
                        try:
                            __create_locks_replicas_transfers(datasetfiles=datasetfiles,
                                                              locks=locks,
                                                              replicas=replicas,
                                                              source_replicas=source_replicas,
                                                              rseselector=rseselector,
                                                              rule=new_rule,
                                                              preferred_rse_ids=[],
                                                              source_rses=[rse['id'] for rse in source_rses],
                                                              session=session)
                        except IntegrityError as error:
                            raise ReplicationRuleCreationTemporaryFailed(error.args[0])

                    if new_rule.locks_stuck_cnt > 0:
                        new_rule.state = RuleState.STUCK
                        new_rule.error = 'MissingSourceReplica'
                        if new_rule.grouping != RuleGrouping.NONE:
                            session.query(models.DatasetLock).filter_by(rule_id=new_rule.id).update({'state': LockState.STUCK})
                    elif new_rule.locks_replicating_cnt == 0:
                        new_rule.state = RuleState.OK
                        if new_rule.grouping != RuleGrouping.NONE:
                            session.query(models.DatasetLock).filter_by(rule_id=new_rule.id).update({'state': LockState.OK})
                            session.flush()
                            generate_message_for_dataset_ok_callback(rule=new_rule, session=session)
                        if new_rule.notification == RuleNotification.YES:
                            generate_email_for_rule_ok_notification(rule=new_rule, session=session)
                    else:
                        new_rule.state = RuleState.REPLICATING
                        if new_rule.grouping != RuleGrouping.NONE:
                            session.query(models.DatasetLock).filter_by(rule_id=new_rule.id).update({'state': LockState.REPLICATING})

                    # Add rule to History
                    insert_rule_history(rule=new_rule, recent=True, longterm=True, session=session)

                    logging.info("Created rule %s [%d/%d/%d] in state %s" % (str(new_rule.id), new_rule.locks_ok_cnt, new_rule.locks_replicating_cnt, new_rule.locks_stuck_cnt, str(new_rule.state)))

    return rule_ids


@transactional_session
def inject_rule(rule_id, session=None):
    """
    Inject a replication rule.

    :param rule_id:    The id of the rule to inject.
    :param new_owner:  The new owner of the rule.
    :param session:    The database session in use.
    :raises:           InvalidReplicationRule, InsufficientAccountLimit, InvalidRSEExpression, DataId
    """
    try:
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rule_id).with_for_update(nowait=True).one()
    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))

    # Special R2D2 container handling
    if (rule.did_type == DIDType.CONTAINER and '.r2d2_request.' in rule.name) or (rule.split_container and rule.did_type == DIDType.CONTAINER):
        logging.debug("Creating dataset rules for Split Container rule %s" % (str(rule.id)))
        # Get all child datasets and put rules on them
        dids = [{'scope': dataset['scope'], 'name': dataset['name']} for dataset in rucio.core.did.list_child_datasets(scope=rule.scope, name=rule.name, session=session)]
        dids = [did for did in dids if session.query(models.ReplicationRule).filter_by(scope=did['scope'], name=did['name'], account=rule.account, rse_expression=rule.rse_expression).count() == 0]
        if rule.expires_at:
            lifetime = (rule.expires_at - datetime.utcnow()).days * 24 * 3600 + (rule.expires_at - datetime.utcnow()).seconds
        else:
            lifetime = None
        if rule.notification == RuleNotification.YES:
            notify = 'Y'
        elif rule.notification == RuleNotification.CLOSE:
            notify = 'C'
        else:
            notify = 'N'
        add_rule(dids=dids,
                 account=rule.account,
                 copies=rule.copies,
                 rse_expression=rule.rse_expression,
                 grouping='DATASET',
                 weight=None,
                 lifetime=lifetime,
                 locked=False,
                 subscription_id=None,
                 activity=rule.activity,
                 notify=notify,
                 comment=rule.comments,
                 asynchronous=True,
                 ignore_availability=rule.ignore_availability,
                 ignore_account_limit=True,
                 priority=rule.priority,
                 split_container=rule.split_container,
                 session=session)
        rule.delete(session=session)
        return

    # 1. Resolve the rse_expression into a list of RSE-ids
    with record_timer_block('rule.add_rule.parse_rse_expression'):
        if rule.ignore_availability:
            rses = parse_expression(rule.rse_expression, session=session)
        else:
            rses = parse_expression(rule.rse_expression, filter={'availability_write': True}, session=session)

        if rule.source_replica_expression:
            source_rses = parse_expression(rule.source_replica_expression, session=session)
        else:
            source_rses = []

    # 2. Create the rse selector
    with record_timer_block('rule.add_rule.create_rse_selector'):
        rseselector = RSESelector(account=rule['account'], rses=rses, weight=rule.weight, copies=rule.copies, ignore_account_limit=rule.ignore_account_limit, session=session)

    # 3. Get the did
    with record_timer_block('rule.add_rule.get_did'):
        try:
            did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == rule.scope,
                                                              models.DataIdentifier.name == rule.name).one()
        except NoResultFound:
            raise DataIdentifierNotFound('Data identifier %s:%s is not valid.' % (rule.scope, rule.name))
        except TypeError as error:
            raise InvalidObject(error.args)

    # 5. Resolve the did to its contents
    with record_timer_block('rule.add_rule.resolve_dids_to_locks_replicas'):
        # Get all Replicas, not only the ones interesting for the rse_expression
        datasetfiles, locks, replicas, source_replicas = __resolve_did_to_locks_and_replicas(did=did,
                                                                                             nowait=True,
                                                                                             restrict_rses=[rse['id'] for rse in rses],
                                                                                             source_rses=[rse['id'] for rse in source_rses],
                                                                                             session=session)

    # 6. Apply the replication rule to create locks, replicas and transfers
    with record_timer_block('rule.add_rule.create_locks_replicas_transfers'):
        try:
            __create_locks_replicas_transfers(datasetfiles=datasetfiles,
                                              locks=locks,
                                              replicas=replicas,
                                              source_replicas=source_replicas,
                                              rseselector=rseselector,
                                              rule=rule,
                                              preferred_rse_ids=[],
                                              source_rses=[rse['id'] for rse in source_rses],
                                              session=session)
        except IntegrityError as error:
            raise ReplicationRuleCreationTemporaryFailed(error.args[0])

        if rule.locks_stuck_cnt > 0:
            rule.state = RuleState.STUCK
            rule.error = 'MissingSourceReplica'
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
        elif rule.locks_replicating_cnt == 0:
            rule.state = RuleState.OK
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})
                session.flush()
                generate_message_for_dataset_ok_callback(rule=rule, session=session)
            if rule.notification == RuleNotification.YES:
                generate_email_for_rule_ok_notification(rule=rule, session=session)
            # Try to release potential parent rules
            release_parent_rule(child_rule_id=rule.id, session=session)
        else:
            rule.state = RuleState.REPLICATING
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.REPLICATING})

        # Add rule to History
        insert_rule_history(rule=rule, recent=True, longterm=True, session=session)

        logging.debug("Created rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))


@stream_session
def list_rules(filters={}, session=None):
    """
    List replication rules.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.
    :raises:        RucioException
    """

    query = session.query(models.ReplicationRule)
    if filters:
        for (key, value) in filters.items():
            if key == 'created_before':
                query = query.filter(models.ReplicationRule.created_at <= str_to_date(value))
                continue
            elif key == 'created_after':
                query = query.filter(models.ReplicationRule.created_at >= str_to_date(value))
                continue
            elif key == 'updated_before':
                query = query.filter(models.ReplicationRule.updated_at <= str_to_date(value))
                continue
            elif key == 'updated_after':
                query = query.filter(models.ReplicationRule.updated_at >= str_to_date(value))
                continue
            elif key == 'state':
                if isinstance(value, basestring):
                    value = RuleState.from_string(value)
                else:
                    try:
                        value = RuleState.from_sym(value)
                    except ValueError:
                        pass
            elif key == 'did_type' and isinstance(value, basestring):
                value = DIDType.from_string(value)
            elif key == 'grouping' and isinstance(value, basestring):
                value = RuleGrouping.from_string(value)
            query = query.filter(getattr(models.ReplicationRule, key) == value)

    try:
        for rule in query.yield_per(5):
            d = {}
            for column in rule.__table__.columns:
                d[column.name] = getattr(rule, column.name)
            yield d
    except StatementError:
        raise RucioException('Badly formatted input (IDs?)')


@stream_session
def list_rule_history(rule_id, session=None):
    """
    List the rule history of a rule.

    :param rule_id: The id of the rule.
    :param session: The database session in use.
    :raises:        RucioException
    """

    query = session.query(models.ReplicationRuleHistoryRecent.updated_at,
                          models.ReplicationRuleHistoryRecent.state,
                          models.ReplicationRuleHistoryRecent.locks_ok_cnt,
                          models.ReplicationRuleHistoryRecent.locks_stuck_cnt,
                          models.ReplicationRuleHistoryRecent.locks_replicating_cnt).filter_by(id=rule_id).order_by(models.ReplicationRuleHistoryRecent.updated_at)

    try:
        for rule in query.yield_per(5):
            yield {'updated_at': rule[0], 'state': rule[1], 'locks_ok_cnt': rule[2], 'locks_stuck_cnt': rule[3], 'locks_replicating_cnt': rule[4]}
    except StatementError:
        raise RucioException('Badly formatted input (IDs?)')


@stream_session
def list_rule_full_history(scope, name, session=None):
    """
    List the rule history of a DID.

    :param scope: The scope of the DID.
    :param name: The name of the DID.
    :param session: The database session in use.
    :raises:        RucioException
    """

    query = session.query(models.ReplicationRuleHistory.id,
                          models.ReplicationRuleHistory.created_at,
                          models.ReplicationRuleHistory.updated_at,
                          models.ReplicationRuleHistory.rse_expression,
                          models.ReplicationRuleHistory.state,
                          models.ReplicationRuleHistory.account,
                          models.ReplicationRuleHistory.locks_ok_cnt,
                          models.ReplicationRuleHistory.locks_stuck_cnt,
                          models.ReplicationRuleHistory.locks_replicating_cnt).\
        with_hint(models.ReplicationRuleHistory, "INDEX(RULES_HISTORY_SCOPENAME_IDX)", 'oracle').\
        filter(models.ReplicationRuleHistory.scope == scope, models.ReplicationRuleHistory.name == name).\
        order_by(models.ReplicationRuleHistory.created_at, models.ReplicationRuleHistory.updated_at)

    for rule in query.yield_per(5):
        yield {'rule_id': rule[0], 'created_at': rule[1], 'updated_at': rule[2], 'rse_expression': rule[3], 'state': rule[4],
               'account': rule[5], 'locks_ok_cnt': rule[6], 'locks_stuck_cnt': rule[7], 'locks_replicating_cnt': rule[8]}


@stream_session
def list_associated_rules_for_file(scope, name, session=None):
    """
    List replication rules a file is affected from.

    :param scope:   Scope of the file.
    :param name:    Name of the file.
    :param session: The database session in use.
    :raises:        RucioException
    """

    query = session.query(models.ReplicationRule).\
        with_hint(models.ReplicaLock, "INDEX(LOCKS LOCKS_PK)", 'oracle').\
        join(models.ReplicaLock, models.ReplicationRule.id == models.ReplicaLock.rule_id).\
        filter(models.ReplicaLock.scope == scope, models.ReplicaLock.name == name).distinct()
    try:
        for rule in query.yield_per(5):
            d = {}
            for column in rule.__table__.columns:
                d[column.name] = getattr(rule, column.name)
            yield d
    except StatementError:
        raise RucioException('Badly formatted input (IDs?)')


@transactional_session
def delete_rule(rule_id, purge_replicas=None, soft=False, delete_parent=False, nowait=False, session=None):
    """
    Delete a replication rule.

    :param rule_id:         The rule to delete.
    :param purge_replicas:  Purge the replicas immediately.
    :param soft:            Only perform a soft deletion.
    :param delete_parent:   Delete rules even if they have a child_rule_id set.
    :param nowait:          Nowait parameter for the FOR UPDATE statement.
    :param session:         The database session in use.
    :raises:                RuleNotFound if no Rule can be found.
    :raises:                UnsupportedOperation if the Rule is locked.
    """

    with record_timer_block('rule.delete_rule'):
        try:
            rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rule_id).with_for_update(nowait=nowait).one()
        except NoResultFound:
            raise RuleNotFound('No rule with the id %s found' % (rule_id))
        if rule.locked:
            raise UnsupportedOperation('The replication rule is locked and has to be unlocked before it can be deleted.')

        if rule.child_rule_id is not None and not delete_parent:
            raise UnsupportedOperation('The replication rule has a child rule and thus cannot be deleted.')

        if purge_replicas is not None:
            rule.purge_replicas = purge_replicas

        if soft:
            if rule.expires_at:
                rule.expires_at = min(datetime.utcnow() + timedelta(seconds=3600), rule.expires_at)
            else:
                rule.expires_at = datetime.utcnow() + timedelta(seconds=3600)
            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
            return

        locks = session.query(models.ReplicaLock).filter(models.ReplicaLock.rule_id == rule_id).with_for_update(nowait=nowait).yield_per(100)

        # Remove locks, set tombstone if applicable
        transfers_to_delete = []  # [{'scope': , 'name':, 'rse_id':}]
        account_counter_decreases = {}  # {'rse_id': [file_size, file_size, file_size]}

        for lock in locks:
            if __delete_lock_and_update_replica(lock=lock, purge_replicas=rule.purge_replicas, nowait=nowait, session=session):
                transfers_to_delete.append({'scope': lock.scope, 'name': lock.name, 'rse_id': lock.rse_id})
            if lock.rse_id not in account_counter_decreases:
                account_counter_decreases[lock.rse_id] = []
            account_counter_decreases[lock.rse_id].append(lock.bytes)

        # Delete the DatasetLocks
        session.query(models.DatasetLock).filter(models.DatasetLock.rule_id == rule_id).delete(synchronize_session=False)

        # Decrease account_counters
        for rse_id in account_counter_decreases.keys():
            account_counter.decrease(rse_id=rse_id, account=rule.account, files=len(account_counter_decreases[rse_id]), bytes=sum(account_counter_decreases[rse_id]), session=session)

        # Try to release potential parent rules
        release_parent_rule(child_rule_id=rule.id, remove_parent_expiration=True, session=session)

        # Insert history
        insert_rule_history(rule=rule, recent=False, longterm=True, session=session)

        session.flush()
        rule.delete(session=session)

        for transfer in transfers_to_delete:
            cancel_request_did(scope=transfer['scope'], name=transfer['name'], dest_rse_id=transfer['rse_id'], session=session)


@transactional_session
def repair_rule(rule_id, session=None):
    """
    Repair a STUCK replication rule.

    :param rule_id:   The rule to repair.
    :param session:   The database session in use.
    """

    # Rule error cases:
    # (A) A rule get's an exception on rule-creation. This can only be the MissingSourceReplica exception.
    # (B) A rule get's an error when re-evaluated: InvalidRSEExpression, InvalidRuleWeight, InsufficientTargetRSEs, RSEBlacklisted
    #     InsufficientAccountLimit. The re-evaluation has to be done again and potential missing locks have to be
    #     created.
    # (C) Transfers fail and mark locks (and the rule) as STUCK. All STUCK locks have to be repaired.
    # (D) Files are declared as BAD.

    # start_time = time.time()
    try:
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rule_id).with_for_update(nowait=True).one()
        rule.updated_at = datetime.utcnow()

        # Check if rule is longer than 2 weeks in STUCK
        if rule.stuck_at is None:
            rule.stuck_at = datetime.utcnow()
        if rule.stuck_at < (datetime.utcnow() - timedelta(days=14)):
            rule.state = RuleState.SUSPENDED
            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
            logging.info('Replication rule %s has been SUSPENDED' % (rule_id))
            return

        # Evaluate the RSE expression to see if there is an alternative RSE anyway
        try:
            rses = parse_expression(rule.rse_expression, session=session)
            if rule.ignore_availability:
                target_rses = parse_expression(rule.rse_expression, session=session)
            else:
                target_rses = parse_expression(rule.rse_expression, filter={'availability_write': True}, session=session)
            if rule.source_replica_expression:
                source_rses = parse_expression(rule.source_replica_expression, session=session)
            else:
                source_rses = []
        except (InvalidRSEExpression, RSEBlacklisted) as error:
            rule.state = RuleState.STUCK
            rule.error = (str(error)[:245] + '...') if len(str(error)) > 245 else str(error)
            rule.save(session=session)
            # Insert rule history
            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
            logging.debug('%s while repairing rule %s' % (str(error), rule_id))
            return

        # Create the RSESelector
        try:
            rseselector = RSESelector(account=rule.account,
                                      rses=target_rses,
                                      weight=rule.weight,
                                      copies=rule.copies,
                                      ignore_account_limit=rule.ignore_account_limit,
                                      session=session)
        except (InvalidRuleWeight, InsufficientTargetRSEs, InsufficientAccountLimit) as error:
            rule.state = RuleState.STUCK
            rule.error = (str(error)[:245] + '...') if len(str(error)) > 245 else str(error)
            rule.save(session=session)
            # Insert rule history
            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
            logging.debug('%s while repairing rule %s' % (type(error).__name__, rule_id))
            return

        # Reset the counters
        logging.debug("Resetting counters for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))
        rule.locks_ok_cnt = 0
        rule.locks_replicating_cnt = 0
        rule.locks_stuck_cnt = 0
        rule_counts = session.query(models.ReplicaLock.state, func.count(models.ReplicaLock.state)).filter(models.ReplicaLock.rule_id == rule.id).group_by(models.ReplicaLock.state).all()
        for count in rule_counts:
            if count[0] == LockState.OK:
                rule.locks_ok_cnt = count[1]
            elif count[0] == LockState.REPLICATING:
                rule.locks_replicating_cnt = count[1]
            elif count[0] == LockState.STUCK:
                rule.locks_stuck_cnt = count[1]
        logging.debug("Finished resetting counters for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

        # Get the did
        did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == rule.scope,
                                                          models.DataIdentifier.name == rule.name).one()

        # Detect if there is something wrong with the dataset and
        # make the decisison on soft or hard repair.
        hard_repair = False
        if did.did_type != DIDType.FILE:
            nr_files = rucio.core.did.get_did(scope=rule.scope, name=rule.name, dynamic=True, session=session)['length']
        else:
            nr_files = 1
        if nr_files * rule.copies != (rule.locks_ok_cnt + rule.locks_stuck_cnt + rule.locks_replicating_cnt):
            hard_repair = True
            logging.debug('Repairing rule %s in HARD mode.' % str(rule.id))
        elif rule.locks_stuck_cnt > 200:
            hard_repair = True
            logging.debug('Repairing rule %s in HARD mode.' % str(rule.id))
        elif rule.copies > 1 and rule.grouping == RuleGrouping.NONE:
            hard_repair = True
            logging.debug('Repairing rule %s in HARD mode.' % str(rule.id))

        # Resolve the did to its contents
        datasetfiles, locks, replicas, source_replicas = __resolve_did_to_locks_and_replicas(did=did,
                                                                                             nowait=True,
                                                                                             restrict_rses=[rse['id'] for rse in rses],
                                                                                             source_rses=[rse['id'] for rse in source_rses],
                                                                                             only_stuck=not hard_repair,
                                                                                             session=session)

        session.flush()

        # 1. Try to find missing locks and create them based on grouping
        if did.did_type != DIDType.FILE and hard_repair:
            try:
                __find_missing_locks_and_create_them(datasetfiles=datasetfiles,
                                                     locks=locks,
                                                     replicas=replicas,
                                                     source_replicas=source_replicas,
                                                     rseselector=rseselector,
                                                     rule=rule,
                                                     source_rses=[rse['id'] for rse in source_rses],
                                                     session=session)
            except (InsufficientAccountLimit, InsufficientTargetRSEs) as error:
                rule.state = RuleState.STUCK
                rule.error = (str(error)[:245] + '...') if len(str(error)) > 245 else str(error)
                rule.save(session=session)
                # Insert rule history
                insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
                # Try to update the DatasetLocks
                if rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                logging.debug('%s while repairing rule %s' % (type(error).__name__, rule_id))
                return

            session.flush()

        # 2. Try to find surplus locks and remove them
        if hard_repair:
            __find_surplus_locks_and_remove_them(datasetfiles=datasetfiles,
                                                 locks=locks,
                                                 replicas=replicas,
                                                 source_replicas=source_replicas,
                                                 rseselector=rseselector,
                                                 rule=rule,
                                                 source_rses=[rse['id'] for rse in source_rses],
                                                 session=session)

            session.flush()

        # 3. Try to find STUCK locks and repair them based on grouping
        try:
            __find_stuck_locks_and_repair_them(datasetfiles=datasetfiles,
                                               locks=locks,
                                               replicas=replicas,
                                               source_replicas=source_replicas,
                                               rseselector=rseselector,
                                               rule=rule,
                                               source_rses=[rse['id'] for rse in source_rses],
                                               session=session)
        except (InsufficientAccountLimit, InsufficientTargetRSEs) as error:
            rule.state = RuleState.STUCK
            rule.error = (str(error)[:245] + '...') if len(str(error)) > 245 else str(error)
            rule.save(session=session)
            # Insert rule history
            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
            logging.debug('%s while repairing rule %s' % (type(error).__name__, rule_id))
            return

        # Delete Datasetlocks which are not relevant anymore
        validated_datasetlock_rse_ids = [rse_id[0] for rse_id in session.query(models.ReplicaLock.rse_id).filter(models.ReplicaLock.rule_id == rule.id).group_by(models.ReplicaLock.rse_id).all()]
        dataset_locks = session.query(models.DatasetLock).filter_by(rule_id=rule.id).all()
        for dataset_lock in dataset_locks:
            if dataset_lock.rse_id not in validated_datasetlock_rse_ids:
                dataset_lock.delete(session=session)

        if rule.locks_stuck_cnt != 0:
            logging.info('Rule %s [%d/%d/%d] state=STUCK' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))
            rule.state = RuleState.STUCK
            # Insert rule history
            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
            # TODO: Increase some kind of Stuck Counter here, The rule should at some point be SUSPENDED
            return

        rule.stuck_at = None

        if rule.locks_replicating_cnt > 0:
            logging.info('Rule %s [%d/%d/%d] state=REPLICATING' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))
            rule.state = RuleState.REPLICATING
            rule.error = None
            # Insert rule history
            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.REPLICATING})
            return

        rule.state = RuleState.OK
        rule.error = None
        # Insert rule history
        insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
        logging.info('Rule %s [%d/%d/%d] state=OK' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

        if rule.grouping != RuleGrouping.NONE:
            session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})
            session.flush()
            generate_message_for_dataset_ok_callback(rule=rule, session=session)
        if rule.notification == RuleNotification.YES:
            generate_email_for_rule_ok_notification(rule=rule, session=session)
        # Try to release potential parent rules
        rucio.core.rule.release_parent_rule(child_rule_id=rule.id, session=session)

        return

    except NoResultFound:
        # The rule has been deleted in the meanwhile
        return


@read_session
def get_rule(rule_id, session=None):
    """
    Get a specific replication rule.

    :param rule_id: The rule_id to select.
    :param session: The database session in use.
    :raises:        RuleNotFound if no Rule can be found.
    """

    try:
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()
        d = {}
        for column in rule.__table__.columns:
            d[column.name] = getattr(rule, column.name)
        return d

    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))
    except StatementError:
        raise RucioException('Badly formatted rule id (%s)' % (rule_id))


@transactional_session
def update_rule(rule_id, options, session=None):
    """
    Update a rules options.

    :param rule_id:     The rule_id to lock.
    :param options:     Dictionary of options
    :param session:     The database session in use.
    :raises:            RuleNotFound if no Rule can be found, InputValidationError if invalid option is used, ScratchDiskLifetimeConflict if wrong ScratchDiskLifetime is used.
    """

    valid_options = ['locked', 'lifetime', 'account', 'state', 'activity', 'source_replica_expression', 'cancel_requests', 'priority', 'child_rule_id', 'eol_at']

    for key in options:
        if key not in valid_options:
            raise InputValidationError('%s is not a valid option to set.' % key)

    try:
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()
        for key in options:
            if key == 'lifetime':
                # Check SCRATCHDISK Policy
                rses = parse_expression(rule.rse_expression, session=session)
                rucio.common.policy.get_scratch_policy(rule.account, rses, options['lifetime'], session=session)
                rule.expires_at = datetime.utcnow() + timedelta(seconds=options['lifetime']) if options['lifetime'] is not None else None
            if key == 'source_replica_expression':
                rule.source_replica_expression = options['source_replica_expression']

            if key == 'activity':
                validate_schema('activity', options['activity'])
                rule.activity = options['activity']
                # Cancel transfers and re-submit them:
                for lock in session.query(models.ReplicaLock).filter_by(rule_id=rule.id, state=LockState.REPLICATING).all():
                    cancel_request_did(scope=lock.scope, name=lock.name, dest_rse_id=lock.rse_id, session=session)
                    md5, bytes, adler32 = session.query(models.RSEFileAssociation.md5, models.RSEFileAssociation.bytes, models.RSEFileAssociation.adler32).filter(models.RSEFileAssociation.scope == lock.scope,
                                                                                                                                                                  models.RSEFileAssociation.name == lock.name,
                                                                                                                                                                  models.RSEFileAssociation.rse_id == lock.rse_id).one()
                    session.flush()
                    queue_requests(requests=[create_transfer_dict(dest_rse_id=lock.rse_id,
                                                                  request_type=RequestType.TRANSFER,
                                                                  scope=lock.scope, name=lock.name, rule=rule, lock=lock, bytes=bytes, md5=md5, adler32=adler32,
                                                                  ds_scope=rule.scope, ds_name=rule.name, lifetime=None, activity=rule.activity, session=session)], session=session)

            elif key == 'account':
                # Check if the account exists
                get_account(options['account'], session=session)
                # Update locks
                locks = session.query(models.ReplicaLock).filter_by(rule_id=rule.id).all()
                counter_rses = {}
                for lock in locks:
                    if lock.rse_id in counter_rses:
                        counter_rses[lock.rse_id].append(lock.bytes)
                    else:
                        counter_rses[lock.rse_id] = [lock.bytes]
                session.query(models.ReplicaLock).filter_by(rule_id=rule.id).update({'account': options['account']})
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'account': options['account']})
                # Update counters
                for rse_id in counter_rses:
                    account_counter.decrease(rse_id=rse_id, account=rule.account, files=len(counter_rses[rse_id]), bytes=sum(counter_rses[rse_id]), session=session)
                    account_counter.increase(rse_id=rse_id, account=options['account'], files=len(counter_rses[rse_id]), bytes=sum(counter_rses[rse_id]), session=session)
                # Update rule
                rule.account = options['account']
                session.flush()

            elif key == 'state':
                if options.get('cancel_requests', False):
                    rule_ids_to_stuck = set()
                    for lock in session.query(models.ReplicaLock).filter_by(rule_id=rule.id, state=LockState.REPLICATING).all():
                        # Set locks to stuck:
                        for l in session.query(models.ReplicaLock).filter_by(scope=lock.scope, name=lock.name, rse_id=lock.rse_id, state=LockState.REPLICATING).all():
                            l.state = LockState.STUCK
                            rule_ids_to_stuck.add(l.rule_id)
                        cancel_request_did(scope=lock.scope, name=lock.name, dest_rse_id=lock.rse_id, session=session)
                        replica = session.query(models.RSEFileAssociation).filter(
                            models.RSEFileAssociation.scope == lock.scope,
                            models.RSEFileAssociation.name == lock.name,
                            models.RSEFileAssociation.rse_id == lock.rse_id).one()
                        replica.state = ReplicaState.UNAVAILABLE
                    # Set rules and DATASETLOCKS to STUCK:
                    for rid in rule_ids_to_stuck:
                        session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rid,
                                                                     models.ReplicationRule.state != RuleState.SUSPENDED).update({'state': RuleState.STUCK})
                        session.query(models.DatasetLock).filter_by(rule_id=rid).update({'state': LockState.STUCK})

                if options['state'].lower() == 'suspended':
                    rule.state = RuleState.SUSPENDED

                elif options['state'].lower() == 'stuck':
                    rule.state = RuleState.STUCK
                    rule.stuck_at = datetime.utcnow()
                    if not options.get('cancel_requests', False):
                        session.query(models.ReplicaLock).filter_by(rule_id=rule.id, state=LockState.REPLICATING).update({'state': LockState.STUCK})
                        session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})

            elif key == 'cancel_requests':
                pass

            elif key == 'priority':
                try:
                    rule.priority = options[key]
                    update_requests_priority(priority=options[key], filter={'rule_id': rule_id}, session=session)
                except Exception:
                    raise UnsupportedOperation('The FTS Requests are already in a final state.')

            elif key == 'child_rule_id':
                # Check if the child rule has the same scope/name as the parent rule
                child_rule = session.query(models.ReplicationRule).filter_by(id=options[key]).one()
                if rule.scope != child_rule.scope or rule.name != child_rule.name:
                    raise InputValidationError('Parent and child rule must be set on the same dataset.')
                if child_rule.state != RuleState.OK:
                    rule.child_rule_id = options[key]

            else:
                setattr(rule, key, options[key])

            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)

    except IntegrityError as error:
        if match('.*ORA-00001.*', str(error.args[0]))\
           or match('.*IntegrityError.*UNIQUE constraint failed.*', str(error.args[0]))\
           or match('.*1062.*Duplicate entry.*for key.*', str(error.args[0]))\
           or match('.*sqlite3.IntegrityError.*are not unique.*', error.args[0]):
            raise DuplicateRule()
        else:
            raise error
    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))
    except StatementError:
        raise RucioException('Badly formatted rule id (%s)' % (rule_id))


@transactional_session
def reduce_rule(rule_id, copies, exclude_expression=None, session=None):
    """
    Reduce the number of copies for a rule by atomically replacing the rule.

    :param rule_id:             Rule to be reduced.
    :param copies:              Number of copies of the new rule.
    :param exclude_expression:  RSE Expression of RSEs to exclude.
    :param session:             The DB Session.
    :raises:                    RuleReplaceFailed, RuleNotFound
    """
    try:
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()

        if copies >= rule.copies:
            raise RuleReplaceFailed('Copies of the new rule must be smaller than the old rule.')

        if rule.state != RuleState.OK:
            raise RuleReplaceFailed('The source rule must be in state OK.')

        if exclude_expression:
            rse_expression = '(' + rule.rse_expression + ')' + '\\' + '(' + exclude_expression + ')'
        else:
            rse_expression = rule.rse_expression

        if rule.grouping == RuleGrouping.ALL:
            grouping = 'ALL'
        elif rule.grouping == RuleGrouping.NONE:
            grouping = 'NONE'
        else:
            grouping = 'DATASET'

        if rule.expires_at:
            lifetime = (rule.expires_at - datetime.utcnow()).days * 24 * 3600 + (rule.expires_at - datetime.utcnow()).seconds
        else:
            lifetime = None

        if rule.notification == RuleNotification.YES:
            notify = 'Y'
        elif rule.notification == RuleNotification.CLOSE:
            notify = 'C'
        else:
            notify = 'N'

        new_rule_id = add_rule(dids=[{'scope': rule.scope, 'name': rule.name}],
                               account=rule.account,
                               copies=copies,
                               rse_expression=rse_expression,
                               grouping=grouping,
                               weight=rule.weight,
                               lifetime=lifetime,
                               locked=rule.locked,
                               subscription_id=rule.subscription_id,
                               source_replica_expression=rule.source_replica_expression,
                               activity=rule.activity,
                               notify=notify,
                               purge_replicas=rule.purge_replicas,
                               ignore_availability=rule.ignore_availability,
                               session=session)

        session.flush()

        new_rule = session.query(models.ReplicationRule).filter_by(id=new_rule_id[0]).one()

        if new_rule.state != RuleState.OK:
            raise RuleReplaceFailed('The replacement of the rule failed.')

        delete_rule(rule_id=rule_id,
                    session=session)

        return new_rule_id[0]

    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))


@transactional_session
def re_evaluate_did(scope, name, rule_evaluation_action, session=None):
    """
    Re-Evaluates a did.

    :param scope:                   The scope of the did to be re-evaluated.
    :param name:                    The name of the did to be re-evaluated.
    :param rule_evaluation_action:  The Rule evaluation action.
    :param session:                 The database session in use.
    :raises:                        DataIdentifierNotFound
    """

    try:
        did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == scope,
                                                          models.DataIdentifier.name == name).one()
    except NoResultFound:
        raise DataIdentifierNotFound()

    if rule_evaluation_action == DIDReEvaluation.ATTACH:
        __evaluate_did_attach(did, session=session)
    else:
        __evaluate_did_detach(did, session=session)

    # Update size and length of did
    if session.bind.dialect.name == 'oracle':
        stmt = session.query(func.sum(models.DataIdentifierAssociation.bytes),
                             func.count(1)).\
            with_hint(models.DataIdentifierAssociation,
                      "index(CONTENTS CONTENTS_PK)", 'oracle').\
            filter(models.DataIdentifierAssociation.scope == scope,
                   models.DataIdentifierAssociation.name == name)
        for bytes, length in stmt:
            did.bytes = bytes
            did.length = length

    # Add an updated_col_rep
    if did.did_type == DIDType.DATASET:
        models.UpdatedCollectionReplica(scope=scope,
                                        name=name,
                                        did_type=did.did_type).save(session=session)


@read_session
def get_updated_dids(total_workers, worker_number, limit=100, blacklisted_dids=[], session=None):
    """
    Get updated dids.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of dids to return.
    :param blacklisted_dids:   Blacklisted dids to filter.
    :param session:            Database session in use.
    """
    query = session.query(models.UpdatedDID.id,
                          models.UpdatedDID.scope,
                          models.UpdatedDID.name,
                          models.UpdatedDID.rule_evaluation_action)

    if total_workers > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('worker_number', worker_number),
                          bindparam('total_workers', total_workers)]
            query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_workers + 1, worker_number))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers + 1, worker_number))

    if limit:
        fetched_dids = query.order_by(models.UpdatedDID.created_at).limit(limit).all()
        filtered_dids = [did for did in fetched_dids if (did.scope, did.name) not in blacklisted_dids]
        if len(fetched_dids) == limit and len(filtered_dids) == 0:
            return get_updated_dids(total_workers=total_workers,
                                    worker_number=worker_number,
                                    limit=None,
                                    blacklisted_dids=blacklisted_dids,
                                    session=session)
        else:
            return filtered_dids
    else:
        return [did for did in query.order_by(models.UpdatedDID.created_at).all() if (did.scope, did.name) not in blacklisted_dids]


@read_session
def get_rules_beyond_eol(date_check, worker_number, total_workers, session):
    """
    Get rules which have eol_at before a certain date.

    :param date_check:         The reference date that should be compared to eol_at.
    :param worker_number:      id of the executing worker.
    :param total_workers:      Number of total workers.
    :param session:            Database session in use.
    """
    query = session.query(models.ReplicationRule.scope,
                          models.ReplicationRule.name,
                          models.ReplicationRule.rse_expression,
                          models.ReplicationRule.locked,
                          models.ReplicationRule.id,
                          models.ReplicationRule.eol_at,
                          models.ReplicationRule.expires_at).\
        filter(models.ReplicationRule.eol_at < date_check)

    if session.bind.dialect.name == 'oracle':
        bindparams = [bindparam('worker_number', worker_number),
                      bindparam('total_workers', total_workers)]
        query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
    elif session.bind.dialect.name == 'mysql':
        query = query.filter('mod(md5(name), %s) = %s' % (total_workers + 1, worker_number))
    elif session.bind.dialect.name == 'postgresql':
        query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers + 1, worker_number))
    return [rule for rule in query.all()]


@read_session
def get_expired_rules(total_workers, worker_number, limit=100, blacklisted_rules=[], session=None):
    """
    Get expired rules.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of rules to return.
    :param backlisted_rules:   List of blacklisted rules.
    :param session:            Database session in use.
    """

    query = session.query(models.ReplicationRule.id, models.ReplicationRule.rse_expression).filter(models.ReplicationRule.expires_at < datetime.utcnow(),
                                                                                                   models.ReplicationRule.locked == False,
                                                                                                   models.ReplicationRule.child_rule_id == None).\
        with_hint(models.ReplicationRule, "index(rules RULES_EXPIRES_AT_IDX)", 'oracle').\
        order_by(models.ReplicationRule.expires_at)  # NOQA

    if session.bind.dialect.name == 'oracle':
        bindparams = [bindparam('worker_number', worker_number),
                      bindparam('total_workers', total_workers)]
        query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
    elif session.bind.dialect.name == 'mysql':
        query = query.filter('mod(md5(name), %s) = %s' % (total_workers + 1, worker_number))
    elif session.bind.dialect.name == 'postgresql':
        query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers + 1, worker_number))

    if limit:
        fetched_rules = query.limit(limit).all()
        filtered_rules = [rule for rule in fetched_rules if rule[0] not in blacklisted_rules]
        if len(fetched_rules) == limit and len(filtered_rules) == 0:
            return get_expired_rules(total_workers=total_workers,
                                     worker_number=worker_number,
                                     limit=None,
                                     blacklisted_rules=blacklisted_rules,
                                     session=session)
        else:
            return filtered_rules
    else:
        return [rule for rule in query.all() if rule[0] not in blacklisted_rules]


@read_session
def get_injected_rules(total_workers, worker_number, limit=100, blacklisted_rules=[], session=None):
    """
    Get rules to be injected.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of rules to return.
    :param blacklisted_rules:  Blacklisted rules not to include.
    :param session:            Database session in use.
    """

    if session.bind.dialect.name == 'oracle':
        query = session.query(models.ReplicationRule.id).\
            with_hint(models.ReplicationRule, "index(rules RULES_INJECTIONSTATE_IDX)", 'oracle').\
            filter(text("(CASE when rules.state='I' THEN rules.state ELSE null END)= 'I' ")).\
            filter(models.ReplicationRule.state == RuleState.INJECT).\
            order_by(models.ReplicationRule.created_at)
    else:
        query = session.query(models.ReplicationRule.id).\
            with_hint(models.ReplicationRule, "index(rules RULES_INJECTIONSTATE_IDX)", 'oracle').\
            filter(models.ReplicationRule.state == RuleState.INJECT).\
            order_by(models.ReplicationRule.created_at)

    if session.bind.dialect.name == 'oracle':
        bindparams = [bindparam('worker_number', worker_number),
                      bindparam('total_workers', total_workers)]
        query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
    elif session.bind.dialect.name == 'mysql':
        query = query.filter('mod(md5(name), %s) = %s' % (total_workers + 1, worker_number))
    elif session.bind.dialect.name == 'postgresql':
        query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers + 1, worker_number))

    if limit:
        fetched_rules = query.limit(limit).all()
        filtered_rules = [rule for rule in fetched_rules if rule[0] not in blacklisted_rules]
        if len(fetched_rules) == limit and len(filtered_rules) == 0:
            return get_injected_rules(total_workers=total_workers,
                                      worker_number=worker_number,
                                      limit=None,
                                      blacklisted_rules=blacklisted_rules,
                                      session=session)
        else:
            return filtered_rules
    else:
        return [rule for rule in query.all() if rule[0] not in blacklisted_rules]


@read_session
def get_stuck_rules(total_workers, worker_number, delta=600, limit=10, blacklisted_rules=[], session=None):
    """
    Get stuck rules.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param delta:              Delta in seconds to select rules in.
    :param limit:              Maximum number of rules to select.
    :param blacklisted_rules:  Blacklisted rules to filter out.
    :param session:            Database session in use.
    """
    if session.bind.dialect.name == 'oracle':
        query = session.query(models.ReplicationRule.id).\
            with_hint(models.ReplicationRule, "index(rules RULES_STUCKSTATE_IDX)", 'oracle').\
            filter(text("(CASE when rules.state='S' THEN rules.state ELSE null END)= 'S' ")).\
            filter(models.ReplicationRule.state == RuleState.STUCK).\
            filter(models.ReplicationRule.updated_at < datetime.utcnow() - timedelta(seconds=delta)).\
            filter(or_(models.ReplicationRule.expires_at == null(),
                       models.ReplicationRule.expires_at > datetime.utcnow(),
                       models.ReplicationRule.locked == true())).\
            order_by(models.ReplicationRule.updated_at)  # NOQA
    else:
        query = session.query(models.ReplicationRule.id).\
            with_hint(models.ReplicationRule, "index(rules RULES_STUCKSTATE_IDX)", 'oracle').\
            filter(models.ReplicationRule.state == RuleState.STUCK).\
            filter(models.ReplicationRule.updated_at < datetime.utcnow() - timedelta(seconds=delta)).\
            filter(or_(models.ReplicationRule.expires_at == null(),
                       models.ReplicationRule.expires_at > datetime.utcnow(),
                       models.ReplicationRule.locked == true())).\
            order_by(models.ReplicationRule.updated_at)

    if session.bind.dialect.name == 'oracle':
        bindparams = [bindparam('worker_number', worker_number),
                      bindparam('total_workers', total_workers)]
        query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
    elif session.bind.dialect.name == 'mysql':
        query = query.filter('mod(md5(name), %s) = %s' % (total_workers + 1, worker_number))
    elif session.bind.dialect.name == 'postgresql':
        query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers + 1, worker_number))

    if limit:
        fetched_rules = query.limit(limit).all()
        filtered_rules = [rule for rule in fetched_rules if rule[0] not in blacklisted_rules]
        if len(fetched_rules) == limit and len(filtered_rules) == 0:
            return get_stuck_rules(total_workers=total_workers,
                                   worker_number=worker_number,
                                   delta=delta,
                                   limit=None,
                                   blacklisted_rules=blacklisted_rules,
                                   session=session)
        else:
            return filtered_rules
    else:
        return [rule for rule in query.all() if rule[0] not in blacklisted_rules]


@transactional_session
def delete_duplicate_updated_dids(scope, name, rule_evaluation_action, id, session=None):
    """
    Delete all the duplicate scope, name, rule_evaluation entries but the one specified by id.

    :param scope:                   Scope of the duplicate rows.
    :param name:                    Name of the duplicate rows.
    :param rule_evaluation_action:  Rule evaluation action of the duplicate rows.
    :param id:                      Id of the row not to delete.
    :param session:                 The database session in use.
    """
    session.query(models.UpdatedDID).filter(models.UpdatedDID.scope == scope,
                                            models.UpdatedDID.name == name,
                                            models.UpdatedDID.rule_evaluation_action == rule_evaluation_action,
                                            models.UpdatedDID.created_at < datetime.utcnow() - timedelta(seconds=60),
                                            models.UpdatedDID.id != id).delete(synchronize_session=False)


@transactional_session
def delete_updated_did(id, scope, name, session=None):
    """
    Delete an updated_did by id.

    :param id:                      Id of the row not to delete.
    :param session:                 The database session in use.
    """
    session.query(models.UpdatedDID).filter(models.UpdatedDID.id == id).delete()


@transactional_session
def update_rules_for_lost_replica(scope, name, rse_id, nowait=False, session=None):
    """
    Update rules if a file replica is lost.

    :param scope:          Scope of the replica.
    :param name:           Name of the replica.
    :param rse_id:         RSE id of the replica.
    :param nowait:         Nowait parameter for the FOR UPDATE statement.
    :param session:        The database session in use.
    """

    locks = session.query(models.ReplicaLock).filter(models.ReplicaLock.scope == scope, models.ReplicaLock.name == name, models.ReplicaLock.rse_id == rse_id).with_for_update(nowait=nowait).all()
    replica = session.query(models.RSEFileAssociation).filter(models.RSEFileAssociation.scope == scope, models.RSEFileAssociation.name == name, models.RSEFileAssociation.rse_id == rse_id).with_for_update(nowait=nowait).one()
    rse = get_rse_name(rse_id, session=session)

    datasets = []
    parent_dids = rucio.core.did.list_parent_dids(scope=scope, name=name, session=session)
    for p in parent_dids:
        if {'name': p['name'], 'scope': p['scope']} not in datasets:
            datasets.append({'name': p['name'], 'scope': p['scope']})

    for lock in locks:
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == lock.rule_id).with_for_update(nowait=nowait).one()
        rule_state_before = rule.state
        replica.lock_cnt -= 1
        if lock.state == LockState.OK:
            rule.locks_ok_cnt -= 1
        elif lock.state == LockState.REPLICATING:
            rule.locks_replicating_cnt -= 1
        elif lock.state == LockState.STUCK:
            rule.locks_stuck_cnt -= 1
        account_counter.decrease(rse_id=rse_id, account=rule.account, files=1, bytes=lock.bytes, session=session)
        if rule.state == RuleState.SUSPENDED:
            pass
        elif rule.state == RuleState.STUCK:
            pass
        elif rule.locks_replicating_cnt == 0 and rule.locks_stuck_cnt == 0:
            rule.state = RuleState.OK
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})
                session.flush()
                if rule_state_before != RuleState.OK:
                    generate_message_for_dataset_ok_callback(rule=rule, session=session)
                    generate_email_for_rule_ok_notification(rule=rule, session=session)
            # Try to release potential parent rules
            release_parent_rule(child_rule_id=rule.id, session=session)
        # Insert rule history
        insert_rule_history(rule=rule, recent=True, longterm=False, session=session)

        session.delete(lock)

    if replica.lock_cnt == 0:
        replica.tombstone = OBSOLETE
        replica.state = ReplicaState.UNAVAILABLE
        session.query(models.DataIdentifier).filter_by(scope=scope, name=name).update({'availability': DIDAvailability.LOST})
        for dts in datasets:
            logging.info('File %s:%s bad at site %s is completely lost from dataset %s:%s. Will be marked as LOST and detached' % (scope, name, rse, dts['scope'], dts['name']))
            rucio.core.did.detach_dids(scope=dts['scope'], name=dts['name'], dids=[{'scope': scope, 'name': name}], session=session)
            add_message('LOST', {'scope': scope,
                                 'name': name,
                                 'dataset_name': dts['name'],
                                 'dataset_scope': dts['scope']},
                        session=session)
    else:
        # This should never happen
        raise RucioException('Problem with the locks')


@transactional_session
def update_rules_for_bad_replica(scope, name, rse_id, nowait=False, session=None):
    """
    Update rules if a file replica is bad and has to be recreated.

    :param scope:          Scope of the replica.
    :param name:           Name of the replica.
    :param rse_id:         RSE id of the replica.
    :param nowait:         Nowait parameter for the FOR UPDATE statement.
    :param session:        The database session in use.
    """

    locks = session.query(models.ReplicaLock).filter(models.ReplicaLock.scope == scope, models.ReplicaLock.name == name, models.ReplicaLock.rse_id == rse_id).with_for_update(nowait=nowait).all()
    replica = session.query(models.RSEFileAssociation).filter(models.RSEFileAssociation.scope == scope, models.RSEFileAssociation.name == name, models.RSEFileAssociation.rse_id == rse_id).with_for_update(nowait=nowait).one()
    rse = get_rse_name(rse_id, session=session)

    nlock = 0
    datasets = []
    for lock in locks:
        nlock += 1
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == lock.rule_id).with_for_update(nowait=nowait).one()
        # If source replica expression exists, we remove it
        if rule.source_replica_expression:
            rule.source_replica_expression = None
        # Get the affected datasets
        ds_scope = rule.scope
        ds_name = rule.name
        dataset = '%s:%s' % (ds_scope, ds_name)
        if dataset not in datasets:
            datasets.append(dataset)
            logging.info('Recovering file %s:%s from dataset %s:%s at site %s' % (scope, name, ds_scope, ds_name, rse))
        # Insert a new row in the UpdateCollectionReplica table
        models.UpdatedCollectionReplica(scope=ds_scope,
                                        name=ds_name,
                                        did_type=rule.did_type,
                                        rse_id=lock.rse_id).save(flush=False, session=session)
        # Set the lock counters
        if lock.state == LockState.OK:
            rule.locks_ok_cnt -= 1
        elif lock.state == LockState.REPLICATING:
            rule.locks_replicating_cnt -= 1
        elif lock.state == LockState.STUCK:
            rule.locks_stuck_cnt -= 1
        rule.locks_replicating_cnt += 1
        # Generate the request
        try:
            get_request_by_did(scope, name, rse, session=session)
        except RequestNotFound:
            bytes = replica.bytes
            md5 = replica.md5
            adler32 = replica.adler32
            queue_requests(requests=[create_transfer_dict(dest_rse_id=rse_id,
                                                          request_type=RequestType.TRANSFER,
                                                          scope=scope, name=name, rule=rule, lock=lock, bytes=bytes, md5=md5, adler32=adler32,
                                                          ds_scope=ds_scope, ds_name=ds_name, lifetime=None, activity='Recovery', session=session)], session=session)
        lock.state = LockState.REPLICATING
        if rule.state == RuleState.SUSPENDED:
            pass
        elif rule.state == RuleState.STUCK:
            pass
        else:
            rule.state = RuleState.REPLICATING
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.REPLICATING})
        # Insert rule history
        insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
    if nlock:
        session.query(models.RSEFileAssociation).filter(models.RSEFileAssociation.scope == scope, models.RSEFileAssociation.name == name, models.RSEFileAssociation.rse_id == rse_id).update({'state': ReplicaState.COPYING})
    else:
        logging.info('File %s:%s at site %s has no locks. Will be deleted now.' % (scope, name, rse))
        tombstone = OBSOLETE
        session.query(models.RSEFileAssociation).filter(models.RSEFileAssociation.scope == scope, models.RSEFileAssociation.name == name, models.RSEFileAssociation.rse_id == rse_id).update({'state': ReplicaState.UNAVAILABLE, 'tombstone': tombstone})


@transactional_session
def generate_message_for_dataset_ok_callback(rule, session=None):
    """
    Generate (If necessary) a callback for a rule (DATASETLOCK_OK)

    :param rule:     The rule object.
    :param session:  The Database session
    """

    session.flush()

    if rule.state == RuleState.OK and rule.grouping != RuleGrouping.NONE:
        if rule.notification == RuleNotification.YES:
            dataset_locks = session.query(models.DatasetLock).filter_by(rule_id=rule.id).all()
            for dataset_lock in dataset_locks:
                add_message(event_type='DATASETLOCK_OK',
                            payload={'scope': dataset_lock.scope,
                                     'name': dataset_lock.name,
                                     'rse': get_rse_name(rse_id=dataset_lock.rse_id, session=session),
                                     'rule_id': rule.id},
                            session=session)
        elif rule.notification == RuleNotification.CLOSE:
            dataset_locks = session.query(models.DatasetLock).filter_by(rule_id=rule.id).all()
            for dataset_lock in dataset_locks:
                try:
                    did = rucio.core.did.get_did(scope=dataset_lock.scope, name=dataset_lock.name, session=session)
                    if not did['open']:
                        if did['length'] is None:
                            return
                        if did['length'] * rule.copies == rule.locks_ok_cnt:
                            add_message(event_type='DATASETLOCK_OK',
                                        payload={'scope': dataset_lock.scope,
                                                 'name': dataset_lock.name,
                                                 'rse': get_rse_name(rse_id=dataset_lock.rse_id, session=session),
                                                 'rule_id': rule.id},
                                        session=session)
                except DataIdentifierNotFound:
                    pass


@transactional_session
def generate_email_for_rule_ok_notification(rule, session=None):
    """
    Generate (If necessary) an eMail for a rule with notification mode Y.

    :param rule:     The rule object.
    :param session:  The Database session
    """

    session.flush()

    if rule.state == RuleState.OK and rule.notification == RuleNotification.YES:
        try:
            with open('%s/rule_ok_notification.tmpl' % config_get('common', 'mailtemplatedir'), 'r') as templatefile:
                template = Template(templatefile.read())
            email = get_account(account=rule.account, session=session).email
            if email:
                text = template.safe_substitute({'rule_id': str(rule.id),
                                                 'created_at': str(rule.created_at),
                                                 'expires_at': str(rule.expires_at),
                                                 'rse_expression': rule.rse_expression,
                                                 'comment': rule.comments,
                                                 'scope': rule.scope,
                                                 'name': rule.name,
                                                 'did_type': rule.did_type})
                add_message(event_type='email',
                            payload={'body': text,
                                     'to': [email],
                                     'subject': '[RUCIO] Replication rule %s has been succesfully transferred' % (str(rule.id))},
                            session=session)
        except (IOError, NoOptionError):
            pass


@transactional_session
def insert_rule_history(rule, recent=True, longterm=False, session=None):
    """
    Insert rule history to recent/longterm history.

    :param rule:      The rule object.
    :param recent:    Insert to recent table.
    :param longterm:  Insert to longterm table.
    :param session:   The Database session.
    """
    if recent:
        models.ReplicationRuleHistoryRecent(id=rule.id, subscription_id=rule.subscription_id, account=rule.account, scope=rule.scope, name=rule.name,
                                            did_type=rule.did_type, state=rule.state, error=rule.error, rse_expression=rule.rse_expression, copies=rule.copies,
                                            expires_at=rule.expires_at, weight=rule.weight, locked=rule.locked, locks_ok_cnt=rule.locks_ok_cnt,
                                            locks_replicating_cnt=rule.locks_replicating_cnt, locks_stuck_cnt=rule.locks_stuck_cnt, source_replica_expression=rule.source_replica_expression,
                                            activity=rule.activity, grouping=rule.grouping, notification=rule.notification, stuck_at=rule.stuck_at, purge_replicas=rule.purge_replicas,
                                            ignore_availability=rule.ignore_availability, ignore_account_limit=rule.ignore_account_limit, comments=rule.comments, created_at=rule.created_at,
                                            updated_at=rule.updated_at).save(session=session)
    if longterm:
        models.ReplicationRuleHistory(id=rule.id, subscription_id=rule.subscription_id, account=rule.account, scope=rule.scope, name=rule.name,
                                      did_type=rule.did_type, state=rule.state, error=rule.error, rse_expression=rule.rse_expression, copies=rule.copies,
                                      expires_at=rule.expires_at, weight=rule.weight, locked=rule.locked, locks_ok_cnt=rule.locks_ok_cnt,
                                      locks_replicating_cnt=rule.locks_replicating_cnt, locks_stuck_cnt=rule.locks_stuck_cnt, source_replica_expression=rule.source_replica_expression,
                                      activity=rule.activity, grouping=rule.grouping, notification=rule.notification, stuck_at=rule.stuck_at, purge_replicas=rule.purge_replicas,
                                      ignore_availability=rule.ignore_availability, ignore_account_limit=rule.ignore_account_limit, comments=rule.comments, created_at=rule.created_at,
                                      updated_at=rule.updated_at).save(session=session)


@transactional_session
def approve_rule(rule_id, approver=None, notify_approvers=True, session=None):
    """
    Approve a specific replication rule.

    :param rule_id:           The rule_id to approve.
    :param approver:          The account which is approving the rule.
    :param notify_approvers:  Notify the other approvers.
    :param session:           The database session in use.
    :raises:                  RuleNotFound if no Rule can be found.
    """

    try:
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()
        if rule.state == RuleState.WAITING_APPROVAL:
            rule.ignore_account_limit = True
            rule.state = RuleState.INJECT
            if approver:
                approver_email = get_account(account=approver, session=session).email
                if approver_email:
                    approver = '%s (%s)' % (approver, approver_email)
            else:
                approver = 'AUTOMATIC'
            with open('%s/rule_approved_user.tmpl' % config_get('common', 'mailtemplatedir'), 'r') as templatefile:
                template = Template(templatefile.read())
                email = get_account(account=rule.account, session=session).email
                if email:
                    text = template.safe_substitute({'rule_id': str(rule.id),
                                                     'expires_at': str(rule.expires_at),
                                                     'rse_expression': rule.rse_expression,
                                                     'comment': rule.comments,
                                                     'scope': rule.scope,
                                                     'name': rule.name,
                                                     'did_type': rule.did_type,
                                                     'approver': approver})
                    add_message(event_type='email',
                                payload={'body': text,
                                         'to': [email],
                                         'subject': '[RUCIO] Replication rule %s has been approved' % (str(rule.id))},
                                session=session)
            # Also notify the other approvers
            if notify_approvers:
                with open('%s/rule_approved_admin.tmpl' % config_get('common', 'mailtemplatedir'), 'r') as templatefile:
                    template = Template(templatefile.read())
                text = template.safe_substitute({'rule_id': str(rule.id),
                                                 'approver': approver})
                recipents = __create_recipents_list(rse_expression=rule.rse_expression, session=session)
                for recipent in recipents:
                    add_message(event_type='email',
                                payload={'body': text,
                                         'to': [recipent[0]],
                                         'subject': 'Re: [RUCIO] Request to approve replication rule %s' % (str(rule.id))},
                                session=session)
    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))
    except StatementError:
        raise RucioException('Badly formatted rule id (%s)' % (rule_id))


@transactional_session
def deny_rule(rule_id, approver=None, session=None):
    """
    Deny a specific replication rule.

    :param rule_id:   The rule_id to approve.
    :param approver:  The account which is denying the rule.
    :param session:   The database session in use.
    :raises:          RuleNotFound if no Rule can be found.
    """

    try:
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()
        if rule.state == RuleState.WAITING_APPROVAL:
            with open('%s/rule_denied_user.tmpl' % config_get('common', 'mailtemplatedir'), 'r') as templatefile:
                template = Template(templatefile.read())
            email = get_account(account=rule.account, session=session).email
            if approver:
                approver_email = get_account(account=approver, session=session).email
                if approver_email:
                    approver = '%s (%s)' % (approver, approver_email)
            else:
                approver = 'AUTOMATIC'
            if email:
                text = template.safe_substitute({'rule_id': str(rule.id),
                                                 'rse_expression': rule.rse_expression,
                                                 'comment': rule.comments,
                                                 'scope': rule.scope,
                                                 'name': rule.name,
                                                 'did_type': rule.did_type,
                                                 'approver': approver})
                add_message(event_type='email',
                            payload={'body': text,
                                     'to': [email],
                                     'subject': '[RUCIO] Replication rule %s has been denied' % (str(rule.id))},
                            session=session)
            delete_rule(rule_id=rule_id, session=session)
            # Also notify the other approvers
            with open('%s/rule_denied_admin.tmpl' % config_get('common', 'mailtemplatedir'), 'r') as templatefile:
                template = Template(templatefile.read())
            text = template.safe_substitute({'rule_id': str(rule.id),
                                             'approver': approver})
            recipents = __create_recipents_list(rse_expression=rule.rse_expression, session=session)
            for recipent in recipents:
                add_message(event_type='email',
                            payload={'body': text,
                                     'to': [recipent[0]],
                                     'subject': 'Re: [RUCIO] Request to approve replication rule %s' % (str(rule.id))},
                            session=session)
    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))
    except StatementError:
        raise RucioException('Badly formatted rule id (%s)' % (rule_id))


@transactional_session
def examine_rule(rule_id, session=None):
    """
    Examine a replication rule for transfer errors.

    :param rule_id:            Replication rule id
    :param session:            Session of the db.
    :returns:                  Dictionary of informations
    """
    result = {'rule_error': None,
              'transfers': []}

    try:
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()
        if rule.state == RuleState.OK:
            result['rule_error'] = 'This replication rule is OK'
        elif rule.state == RuleState.REPLICATING:
            result['rule_error'] = 'This replication rule is currently REPLICATING'
        elif rule.state == RuleState.SUSPENDED:
            result['rule_error'] = 'This replication rule is SUSPENDED'
        else:
            result['rule_error'] = rule.error
            # Get the stuck locks
            stuck_locks = session.query(models.ReplicaLock).filter_by(rule_id=rule_id, state=LockState.STUCK).all()
            for lock in stuck_locks:
                # Get the count of requests in the request_history for each lock
                transfers = session.query(models.Request.__history_mapper__.class_).filter_by(scope=lock.scope, name=lock.name, dest_rse_id=lock.rse_id).order_by(models.Request.__history_mapper__.class_.created_at.desc()).all()
                transfer_cnt = len(transfers)
                # Get the error of the last request that has been tried and also the SOURCE used for the last request
                last_error, last_source, last_time, sources = None, None, None, []
                if transfers:
                    last_request = transfers[0]
                    last_error = last_request.state
                    last_time = last_request.created_at
                    last_source = None if last_request.source_rse_id is None else get_rse_name(last_request.source_rse_id, session=session)
                    available_replicas = session.query(models.RSEFileAssociation).filter_by(scope=lock.scope, name=lock.name, state=ReplicaState.AVAILABLE).all()
                    for replica in available_replicas:
                        sources.append((get_rse(None, rse_id=replica.rse_id, session=session).rse,
                                        True if get_rse(None, rse_id=replica.rse_id, session=session).availability >= 4 else False))
                result['transfers'].append({'scope': lock.scope,
                                            'name': lock.name,
                                            'rse': get_rse_name(lock.rse_id, session=session),
                                            'attempts': transfer_cnt,
                                            'last_error': str(last_error),
                                            'last_source': last_source,
                                            'sources': sources,
                                            'last_time': last_time})
        return result
    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))
    except StatementError:
        raise RucioException('Badly formatted rule id (%s)' % (rule_id))


@transactional_session
def release_parent_rule(child_rule_id, remove_parent_expiration=False, session=None):
    """
    Release a potential parent rule, because the child_rule is OK.

    :param child_rule_id:             The child rule id.
    :param remove_parant_expiration:  If true, removes the expiration of the parent rule.
    :param session:                   The Database session
    """

    session.flush()

    parent_rules = session.query(models.ReplicationRule).filter_by(child_rule_id=child_rule_id).\
        with_hint(models.ReplicationRule, "index(RULES RULES_CHILD_RULE_ID_IDX)", 'oracle').all()
    for rule in parent_rules:
        if remove_parent_expiration:
            rule.expires_at = None
        rule.child_rule_id = None
        insert_rule_history(rule=rule, recent=True, longterm=False, session=session)


@transactional_session
def __find_missing_locks_and_create_them(datasetfiles, locks, replicas, source_replicas, rseselector, rule, source_rses, session=None):
    """
    Find missing locks for a rule and create them.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding locks.
    :param replicas:           Dict holding replicas.
    :param source_replicas:    Dict holding source replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule.
    :param source_rses:        RSE ids for eglible source RSEs.
    :param session:            Session of the db.
    :raises:                   InsufficientAccountLimit, IntegrityError, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    logging.debug("Finding missing locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

    mod_datasetfiles = []    # List of Datasets and their files in the Tree [{'scope':, 'name':, 'files': []}]
    # Files are in the format [{'scope':, 'name':, 'bytes':, 'md5':, 'adler32':}]

    for dataset in datasetfiles:
        mod_files = []
        preferred_rse_ids = []
        for file in dataset['files']:
            if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]) < rule.copies:
                mod_files.append(file)
            else:
                preferred_rse_ids = [lock.rse_id for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]
        if len(mod_files) > 0:
            logging.debug('Found missing locks for rule %s, creating them now' % str(rule.id))
            mod_datasetfiles.append({'scope': dataset['scope'], 'name': dataset['name'], 'files': mod_files})
            __create_locks_replicas_transfers(datasetfiles=mod_datasetfiles,
                                              locks=locks,
                                              replicas=replicas,
                                              source_replicas=source_replicas,
                                              rseselector=rseselector,
                                              rule=rule,
                                              preferred_rse_ids=preferred_rse_ids,
                                              source_rses=source_rses,
                                              session=session)

    logging.debug("Finished finding missing locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))


@transactional_session
def __find_surplus_locks_and_remove_them(datasetfiles, locks, replicas, source_replicas, rseselector, rule, source_rses, session=None):
    """
    Find surplocks locks for a rule and delete them.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding locks.
    :param replicas:           Dict holding replicas.
    :param source_replicas:    Dict holding all source replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule.
    :param source_rses:        RSE ids for eglible source RSEs.
    :param session:            Session of the db.
    :raises:                   InsufficientAccountLimit, IntegrityError, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    logging.debug("Finding surplus locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

    account_counter_decreases = {}  # {'rse_id': [file_size, file_size, file_size]}

    # Put all the files in one dictionary
    files = {}
    for ds in datasetfiles:
        for file in ds['files']:
            files[(file['scope'], file['name'])] = True

    for key in locks:
        if key not in files:
            # The lock needs to be removed
            for lock in deepcopy(locks[key]):
                if lock.rule_id == rule.id:
                    __delete_lock_and_update_replica(lock=lock, purge_replicas=rule.purge_replicas, nowait=True, session=session)
                    if lock.rse_id not in account_counter_decreases:
                        account_counter_decreases[lock.rse_id] = []
                    account_counter_decreases[lock.rse_id].append(lock.bytes)
                    if lock.state == LockState.OK:
                        rule.locks_ok_cnt -= 1
                    elif lock.state == LockState.REPLICATING:
                        rule.locks_replicating_cnt -= 1
                    elif lock.state == LockState.STUCK:
                        rule.locks_stuck_cnt -= 1
                    locks[key].remove(lock)

    logging.debug("Finished finding surplus locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))


@transactional_session
def __find_stuck_locks_and_repair_them(datasetfiles, locks, replicas, source_replicas, rseselector, rule, source_rses, session=None):
    """
    Find stuck locks for a rule and repair them.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding locks.
    :param replicas:           Dict holding replicas.
    :param source_replicas:    Dict holding source replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule.
    :param source_rses:        RSE ids of eglible source RSEs.
    :param session:            Session of the db.
    :raises:                   InsufficientAccountLimit, IntegrityError, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    logging.debug("Finding and repairing stuck locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

    replicas_to_create, locks_to_create, transfers_to_create,\
        locks_to_delete = repair_stuck_locks_and_apply_rule_grouping(datasetfiles=datasetfiles,
                                                                     locks=locks,
                                                                     replicas=replicas,
                                                                     source_replicas=source_replicas,
                                                                     rseselector=rseselector,
                                                                     rule=rule,
                                                                     source_rses=source_rses,
                                                                     session=session)
    # Add the replicas
    session.add_all([item for sublist in replicas_to_create.values() for item in sublist])
    session.flush()

    # Add the locks
    session.add_all([item for sublist in locks_to_create.values() for item in sublist])
    session.flush()

    # Increase rse_counters
    for rse_id in replicas_to_create.keys():
        rse_counter.increase(rse_id=rse_id, files=len(replicas_to_create[rse_id]), bytes=sum([replica.bytes for replica in replicas_to_create[rse_id]]), session=session)

    # Increase account_counters
    for rse_id in locks_to_create.keys():
        account_counter.increase(rse_id=rse_id, account=rule.account, files=len(locks_to_create[rse_id]), bytes=sum([lock.bytes for lock in locks_to_create[rse_id]]), session=session)

    # Decrease account_counters
    for rse_id in locks_to_delete:
        account_counter.decrease(rse_id=rse_id, account=rule.account, files=len(locks_to_delete[rse_id]), bytes=sum([lock.bytes for lock in locks_to_delete[rse_id]]), session=session)

    # Delete the locks:
    for lock in [item for sublist in locks_to_delete.values() for item in sublist]:
        session.delete(lock)

    # Add the transfers
    queue_requests(requests=transfers_to_create, session=session)
    session.flush()
    logging.debug("Finished finding and repairing stuck locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))


@transactional_session
def __evaluate_did_detach(eval_did, session=None):
    """
    Evaluate a parent did which has children removed.

    :param eval_did:  The did object in use.
    :param session:   The database session in use.
    """

    logging.info("Re-Evaluating did %s:%s for DETACH" % (eval_did.scope, eval_did.name))

    with record_timer_block('rule.evaluate_did_detach'):
        # Get all parent DID's
        parent_dids = rucio.core.did.list_all_parent_dids(scope=eval_did.scope, name=eval_did.name, session=session)

        # Get all RR from parents and eval_did
        rules = session.query(models.ReplicationRule).filter_by(scope=eval_did.scope, name=eval_did.name).with_for_update(nowait=True).all()
        for did in parent_dids:
            rules.extend(session.query(models.ReplicationRule).filter_by(scope=did['scope'], name=did['name']).with_for_update(nowait=True).all())

        # Iterate rules and delete locks
        transfers_to_delete = []  # [{'scope': , 'name':, 'rse_id':}]
        account_counter_decreases = {}  # {'rse_id': [file_size, file_size, file_size]}
        for rule in rules:
            # Get all the files covering this rule
            files = {}
            for file in rucio.core.did.list_files(scope=rule.scope, name=rule.name, session=session):
                files[(file['scope'], file['name'])] = True
            logging.debug("Removing locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))
            rule_locks_ok_cnt_before = rule.locks_ok_cnt
            query = session.query(models.ReplicaLock).filter_by(rule_id=rule.id)
            for lock in query:
                if (lock.scope, lock.name) not in files:
                    if __delete_lock_and_update_replica(lock=lock, purge_replicas=rule.purge_replicas, nowait=True, session=session):
                        transfers_to_delete.append({'scope': lock.scope, 'name': lock.name, 'rse_id': lock.rse_id})
                    if lock.rse_id not in account_counter_decreases:
                        account_counter_decreases[lock.rse_id] = []
                    account_counter_decreases[lock.rse_id].append(lock.bytes)
                    if lock.state == LockState.OK:
                        rule.locks_ok_cnt -= 1
                    elif lock.state == LockState.REPLICATING:
                        rule.locks_replicating_cnt -= 1
                    elif lock.state == LockState.STUCK:
                        rule.locks_stuck_cnt -= 1
            logging.debug("Finished removing locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

            if eval_did.did_type == DIDType.CONTAINER:
                # Get all datasets of eval_did
                child_datasets = {}
                for ds in rucio.core.did.list_child_datasets(scope=rule.scope, name=rule.name, session=session):
                    child_datasets[(ds['scope'], ds['name'])] = True
                logging.debug("Removing dataset_locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))
                query = session.query(models.DatasetLock).filter_by(rule_id=rule.id)
                for ds_lock in query:
                    if (ds_lock.scope, ds_lock.name) not in child_datasets:
                        ds_lock.delete(flush=False, session=session)
                logging.debug("Finished removing dataset_locks for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

            if rule.state == RuleState.SUSPENDED:
                pass
            elif rule.state == RuleState.STUCK:
                pass
            elif rule.locks_replicating_cnt == 0 and rule.locks_stuck_cnt == 0:
                rule.state = RuleState.OK
                if rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})
                    session.flush()
                    if rule_locks_ok_cnt_before != rule.locks_ok_cnt:
                        generate_message_for_dataset_ok_callback(rule=rule, session=session)
                        generate_email_for_rule_ok_notification(rule=rule, session=session)
                # Try to release potential parent rules
                release_parent_rule(child_rule_id=rule.id, session=session)

            # Insert rule history
            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)

        session.flush()

        # Decrease account_counters
        for rse_id in account_counter_decreases:
            account_counter.decrease(rse_id=rse_id, account=rule.account, files=len(account_counter_decreases[rse_id]), bytes=sum(account_counter_decreases[rse_id]), session=session)

        for transfer in transfers_to_delete:
            cancel_request_did(scope=transfer['scope'], name=transfer['name'], dest_rse_id=transfer['rse_id'], session=session)


@transactional_session
def __evaluate_did_attach(eval_did, session=None):
    """
    Evaluate a parent did which has new childs

    :param eval_did:  The did object in use.
    :param session:   The database session in use.
    :raises:          ReplicationRuleCreationTemporaryFailed
    """

    logging.info("Re-Evaluating did %s:%s for ATTACH" % (eval_did.scope, eval_did.name))

    with record_timer_block('rule.evaluate_did_attach'):
        # Get all parent DID's
        with record_timer_block('rule.evaluate_did_attach.list_parent_dids'):
            parent_dids = rucio.core.did.list_all_parent_dids(scope=eval_did.scope, name=eval_did.name, session=session)

        # Get immediate new child DID's
        with record_timer_block('rule.evaluate_did_attach.list_new_child_dids'):
            new_child_dids = session.query(models.DataIdentifierAssociation).filter(
                models.DataIdentifierAssociation.scope == eval_did.scope,
                models.DataIdentifierAssociation.name == eval_did.name,
                models.DataIdentifierAssociation.rule_evaluation == True).all()  # noqa

        if new_child_dids:
            # Get all unsuspended RR from parents and eval_did
            with record_timer_block('rule.evaluate_did_attach.get_rules'):
                rule_clauses = []
                for did in parent_dids:
                    rule_clauses.append(and_(models.ReplicationRule.scope == did['scope'],
                                             models.ReplicationRule.name == did['name']))
                rule_clauses.append(and_(models.ReplicationRule.scope == eval_did.scope,
                                         models.ReplicationRule.name == eval_did.name))
                rules = session.query(models.ReplicationRule).filter(
                    or_(*rule_clauses),
                    models.ReplicationRule.state != RuleState.SUSPENDED,
                    models.ReplicationRule.state != RuleState.WAITING_APPROVAL,
                    models.ReplicationRule.state != RuleState.INJECT).with_for_update(nowait=True).all()

            if rules:
                # Resolve the new_child_dids to its locks
                with record_timer_block('rule.evaluate_did_attach.resolve_did_to_locks_and_replicas'):
                    # Resolve the rules to possible target rses:
                    possible_rses = []
                    source_rses = []
                    for rule in rules:
                        try:
                            if rule.source_replica_expression:
                                source_rses.extend(parse_expression(rule.source_replica_expression, session=session))

                            # if rule.ignore_availability:
                            possible_rses.extend(parse_expression(rule.rse_expression, session=session))
                            # else:
                            #     possible_rses.extend(parse_expression(rule.rse_expression, filter={'availability_write': True}, session=session))
                        except (InvalidRSEExpression, RSEBlacklisted):
                            possible_rses = []

                    source_rses = list(set([rse['id'] for rse in source_rses]))
                    possible_rses = list(set([rse['id'] for rse in possible_rses]))

                    datasetfiles, locks, replicas, source_replicas = __resolve_dids_to_locks_and_replicas(dids=new_child_dids,
                                                                                                          nowait=True,
                                                                                                          restrict_rses=possible_rses,
                                                                                                          source_rses=source_rses,
                                                                                                          session=session)

                # Evaluate the replication rules
                with record_timer_block('rule.evaluate_did_attach.evaluate_rules'):
                    for rule in rules:
                        rule_locks_ok_cnt_before = rule.locks_ok_cnt

                        # 1. Resolve the rse_expression into a list of RSE-ids
                        try:
                            if rule.ignore_availability:
                                rses = parse_expression(rule.rse_expression, session=session)
                            else:
                                rses = parse_expression(rule.rse_expression, filter={'availability_write': True}, session=session)
                            source_rses = []
                            if rule.source_replica_expression:
                                source_rses = parse_expression(rule.source_replica_expression, session=session)
                        except (InvalidRSEExpression, RSEBlacklisted) as error:
                            rule.state = RuleState.STUCK
                            rule.error = (str(error)[:245] + '...') if len(str(error)) > 245 else str(error)
                            rule.save(session=session)
                            # Insert rule history
                            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
                            # Try to update the DatasetLocks
                            if rule.grouping != RuleGrouping.NONE:
                                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                            continue

                        # 2. Create the RSE Selector
                        try:
                            rseselector = RSESelector(account=rule.account,
                                                      rses=rses,
                                                      weight=rule.weight,
                                                      copies=rule.copies,
                                                      ignore_account_limit=rule.ignore_account_limit,
                                                      session=session)
                        except (InvalidRuleWeight, InsufficientTargetRSEs, InsufficientAccountLimit) as error:
                            rule.state = RuleState.STUCK
                            rule.error = (str(error)[:245] + '...') if len(str(error)) > 245 else str(error)
                            rule.save(session=session)
                            # Insert rule history
                            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
                            # Try to update the DatasetLocks
                            if rule.grouping != RuleGrouping.NONE:
                                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                            continue

                        # 3. Apply the Replication rule to the Files
                        preferred_rse_ids = []
                        # 3.1 Check if the dids in question are files added to a dataset with DATASET/ALL grouping
                        if new_child_dids[0].child_type == DIDType.FILE and rule.grouping != RuleGrouping.NONE:
                            # Are there any existing did's in this dataset
                            brother_did = session.query(models.DataIdentifierAssociation).filter(
                                models.DataIdentifierAssociation.scope == eval_did.scope,
                                models.DataIdentifierAssociation.name == eval_did.name).order_by(models.DataIdentifierAssociation.created_at).first()
                            if brother_did is not None:
                                # There are other files in the dataset
                                brother_locks = rucio.core.lock.get_replica_locks(scope=brother_did.child_scope,
                                                                                  name=brother_did.child_name,
                                                                                  nowait=True,
                                                                                  session=session)
                                preferred_rse_ids = [lock['rse_id'] for lock in brother_locks if lock['rse_id'] in [rse['id'] for rse in rses] and lock['rule_id'] == rule.id]
                        locks_stuck_before = rule.locks_stuck_cnt
                        try:
                            __create_locks_replicas_transfers(datasetfiles=datasetfiles,
                                                              locks=locks,
                                                              replicas=replicas,
                                                              source_replicas=source_replicas,
                                                              rseselector=rseselector,
                                                              rule=rule,
                                                              preferred_rse_ids=preferred_rse_ids,
                                                              source_rses=[rse['id'] for rse in source_rses],
                                                              session=session)
                        except (InsufficientAccountLimit, InsufficientTargetRSEs) as error:
                            rule.state = RuleState.STUCK
                            rule.error = (str(error)[:245] + '...') if len(str(error)) > 245 else str(error)
                            rule.save(session=session)
                            # Insert rule history
                            insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
                            # Try to update the DatasetLocks
                            if rule.grouping != RuleGrouping.NONE:
                                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                            continue

                        # 4. Update the Rule State
                        if rule.state == RuleState.STUCK:
                            pass
                        elif rule.locks_stuck_cnt > 0:
                            if locks_stuck_before != rule.locks_stuck_cnt:
                                rule.state = RuleState.STUCK
                                rule.error = 'MissingSourceReplica'
                                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                        elif rule.locks_replicating_cnt > 0:
                            rule.state = RuleState.REPLICATING
                            if rule.grouping != RuleGrouping.NONE:
                                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.REPLICATING})
                        elif rule.locks_replicating_cnt == 0 and rule.locks_stuck_cnt == 0:
                            rule.state = RuleState.OK
                            if rule.grouping != RuleGrouping.NONE:
                                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})
                                session.flush()
                                if rule_locks_ok_cnt_before < rule.locks_ok_cnt:
                                    generate_message_for_dataset_ok_callback(rule=rule, session=session)
                                    generate_email_for_rule_ok_notification(rule=rule, session=session)

                        # Insert rule history
                        insert_rule_history(rule=rule, recent=True, longterm=False, session=session)

            # Unflage the dids
            with record_timer_block('rule.evaluate_did_attach.update_did'):
                for did in new_child_dids:
                    did.rule_evaluation = None

        session.flush()


@transactional_session
def __resolve_did_to_locks_and_replicas(did, nowait=False, restrict_rses=None, source_rses=None, only_stuck=False, session=None):
    """
    Resolves a did to its constituent childs and reads the locks and replicas of all the constituent files.

    :param did:            The db object of the did the rule is applied on.
    :param nowait:         Nowait parameter for the FOR UPDATE statement.
    :param restrict_rses:  Possible rses of the rule, so only these replica/locks should be considered.
    :param source_rses:    Source rses for this rule. These replicas are not row-locked.
    :param only_stuck:     Get results only for STUCK locks, if True.
    :param session:        Session of the db.
    :returns:              (datasetfiles, locks, replicas)
    """

    datasetfiles = []     # List of Datasets and their files in the Tree [{'scope':, 'name':, 'files': []}]
    # Files are in the format [{'scope':, 'name':, 'bytes':, 'md5':, 'adler32':}]
    locks = {}            # {(scope,name): [SQLAlchemy]}
    replicas = {}         # {(scope, name): [SQLAlchemy]}
    source_replicas = {}  # {(scope, name): [rse_id]

    if did.did_type == DIDType.FILE:
        datasetfiles = [{'scope': None,
                         'name': None,
                         'files': [{'scope': did.scope,
                                    'name': did.name,
                                    'bytes': did.bytes,
                                    'md5': did.md5,
                                    'adler32': did.adler32}]}]
        locks[(did.scope, did.name)] = rucio.core.lock.get_replica_locks(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, session=session)
        replicas[(did.scope, did.name)] = rucio.core.replica.get_and_lock_file_replicas(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, session=session)
        if source_rses:
            source_replicas[(did.scope, did.name)] = rucio.core.replica.get_source_replicas(scope=did.scope, name=did.name, source_rses=source_rses, session=session)

    elif did.did_type == DIDType.DATASET and only_stuck:
        files = []
        locks = rucio.core.lock.get_files_and_replica_locks_of_dataset(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, only_stuck=True, session=session)
        for file in locks:
            file_did = rucio.core.did.get_did(scope=file[0], name=file[1], session=session)
            files.append({'scope': file[0], 'name': file[1], 'bytes': file_did['bytes'], 'md5': file_did['md5'], 'adler32': file_did['adler32']})
            replicas[(file[0], file[1])] = rucio.core.replica.get_and_lock_file_replicas(scope=file[0], name=file[1], nowait=nowait, restrict_rses=restrict_rses, session=session)
            if source_rses:
                source_replicas[(file[0], file[1])] = rucio.core.replica.get_source_replicas(scope=file[0], name=file[1], source_rses=source_rses, session=session)
        datasetfiles = [{'scope': did.scope,
                         'name': did.name,
                         'files': files}]

    elif did.did_type == DIDType.DATASET:
        files, replicas = rucio.core.replica.get_and_lock_file_replicas_for_dataset(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, session=session)
        if source_rses:
            source_replicas = rucio.core.replica.get_source_replicas_for_dataset(scope=did.scope, name=did.name, source_rses=source_rses, session=session)
        datasetfiles = [{'scope': did.scope,
                         'name': did.name,
                         'files': files}]
        locks = rucio.core.lock.get_files_and_replica_locks_of_dataset(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, session=session)

    elif did.did_type == DIDType.CONTAINER and only_stuck:

        for dataset in rucio.core.did.list_child_datasets(scope=did.scope, name=did.name, session=session):
            files = []
            tmp_locks = rucio.core.lock.get_files_and_replica_locks_of_dataset(scope=dataset['scope'], name=dataset['name'], nowait=nowait, restrict_rses=restrict_rses, only_stuck=True, session=session)
            locks = dict(locks.items() + tmp_locks.items())
            for file in tmp_locks:
                file_did = rucio.core.did.get_did(scope=file[0], name=file[1], session=session)
                files.append({'scope': file[0], 'name': file[1], 'bytes': file_did['bytes'], 'md5': file_did['md5'], 'adler32': file_did['adler32']})
                replicas[(file[0], file[1])] = rucio.core.replica.get_and_lock_file_replicas(scope=file[0], name=file[1], nowait=nowait, restrict_rses=restrict_rses, session=session)
                if source_rses:
                    source_replicas[(file[0], file[1])] = rucio.core.replica.get_source_replicas(scope=file[0], name=file[1], source_rses=source_rses, session=session)
            datasetfiles.append({'scope': dataset['scope'],
                                 'name': dataset['name'],
                                 'files': files})

    elif did.did_type == DIDType.CONTAINER:

        for dataset in rucio.core.did.list_child_datasets(scope=did.scope, name=did.name, session=session):
            files, tmp_replicas = rucio.core.replica.get_and_lock_file_replicas_for_dataset(scope=dataset['scope'], name=dataset['name'], nowait=nowait, restrict_rses=restrict_rses, session=session)
            if source_rses:
                tmp_source_replicas = rucio.core.replica.get_source_replicas_for_dataset(scope=dataset['scope'], name=dataset['name'], source_rses=source_rses, session=session)
                source_replicas = dict(source_replicas.items() + tmp_source_replicas.items())
            tmp_locks = rucio.core.lock.get_files_and_replica_locks_of_dataset(scope=dataset['scope'], name=dataset['name'], nowait=nowait, restrict_rses=restrict_rses, session=session)
            datasetfiles.append({'scope': dataset['scope'],
                                 'name': dataset['name'],
                                 'files': files})
            replicas = dict(replicas.items() + tmp_replicas.items())
            locks = dict(locks.items() + tmp_locks.items())

    else:
        raise InvalidReplicationRule('The did \"%s:%s\" has been deleted.' % (did.scope, did.name))

    return datasetfiles, locks, replicas, source_replicas


@transactional_session
def __resolve_dids_to_locks_and_replicas(dids, nowait=False, restrict_rses=[], source_rses=None, session=None):
    """
    Resolves a list of dids to its constituent childs and reads the locks and replicas of all the constituent files.

    :param dids:           The list of DIDAssociation objects.
    :param nowait:         Nowait parameter for the FOR UPDATE statement.
    :param restrict_rses:  Possible rses of the rule, so only these replica/locks should be considered.
    :param source_rses:    Source rses for this rule. These replicas are not row-locked.
    :param session:        Session of the db.
    :returns:              (datasetfiles, locks, replicas)
    """

    datasetfiles = []     # List of Datasets and their files in the Tree [{'scope':, 'name':, 'files': []}]
    # Files are in the format [{'scope':, 'name':, 'bytes':, 'md5':, 'adler32':}]
    locks = {}            # {(scope,name): [SQLAlchemy]}
    replicas = {}         # {(scope, name): [SQLAlchemy]}
    source_replicas = {}  # {(scope, name): [rse_id]

    if dids[0].child_type == DIDType.FILE:
        # All the dids will be files!
        # Prepare the datasetfiles
        files = []
        for did in dids:
            files.append({'scope': did.child_scope,
                          'name': did.child_name,
                          'bytes': did.bytes,
                          'md5': did.md5,
                          'adler32': did.adler32})
            locks[(did.child_scope, did.child_name)] = []
            replicas[(did.child_scope, did.child_name)] = []
            source_replicas[(did.child_scope, did.child_name)] = []
        datasetfiles = [{'scope': dids[0].scope, 'name': dids[0].name, 'files': files}]

        # Prepare the locks and files
        lock_clauses = []
        replica_clauses = []
        for did in dids:
            lock_clauses.append(and_(models.ReplicaLock.scope == did.child_scope,
                                     models.ReplicaLock.name == did.child_name))
            replica_clauses.append(and_(models.RSEFileAssociation.scope == did.child_scope,
                                        models.RSEFileAssociation.name == did.child_name))
        lock_clause_chunks = [lock_clauses[x:x + 10] for x in xrange(0, len(lock_clauses), 10)]
        replica_clause_chunks = [replica_clauses[x:x + 10] for x in xrange(0, len(replica_clauses), 10)]

        replicas_rse_clause = []
        source_replicas_rse_clause = []
        locks_rse_clause = []
        if restrict_rses:
            for rse_id in restrict_rses:
                replicas_rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
                locks_rse_clause.append(models.ReplicaLock.rse_id == rse_id)
        if source_rses:
            for rse_id in source_rses:
                source_replicas_rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)

        for lock_clause_chunk in lock_clause_chunks:
            if locks_rse_clause:
                tmp_locks = session.query(models.ReplicaLock).filter(or_(*lock_clause_chunk), or_(*locks_rse_clause))\
                    .with_hint(models.ReplicaLock, "index(LOCKS LOCKS_PK)", 'oracle')\
                    .with_for_update(nowait=nowait).all()
            else:
                tmp_locks = session.query(models.ReplicaLock).filter(or_(*lock_clause_chunk))\
                    .with_hint(models.ReplicaLock, "index(LOCKS LOCKS_PK)", 'oracle')\
                    .with_for_update(nowait=nowait).all()
            for lock in tmp_locks:
                if (lock.scope, lock.name) not in locks:
                    locks[(lock.scope, lock.name)] = [lock]
                else:
                    locks[(lock.scope, lock.name)].append(lock)

        for replica_clause_chunk in replica_clause_chunks:
            if replicas_rse_clause:
                tmp_replicas = session.query(models.RSEFileAssociation).filter(or_(*replica_clause_chunk), or_(*replicas_rse_clause), models.RSEFileAssociation.state != ReplicaState.BEING_DELETED)\
                    .with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle')\
                    .with_for_update(nowait=nowait).all()
            else:
                tmp_replicas = session.query(models.RSEFileAssociation).filter(or_(*replica_clause_chunk), models.RSEFileAssociation.state != ReplicaState.BEING_DELETED)\
                    .with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle')\
                    .with_for_update(nowait=nowait).all()
            for replica in tmp_replicas:
                if (replica.scope, replica.name) not in replicas:
                    replicas[(replica.scope, replica.name)] = [replica]
                else:
                    replicas[(replica.scope, replica.name)].append(replica)

        if source_rses:
            for replica_clause_chunk in replica_clause_chunks:
                tmp_source_replicas = session.query(models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.rse_id).\
                    filter(or_(*replica_clause_chunk), or_(*source_replicas_rse_clause), models.RSEFileAssociation.state == ReplicaState.AVAILABLE)\
                    .with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').all()
                for scope, name, rse_id in tmp_source_replicas:
                    if (scope, name) not in source_replicas:
                        source_replicas[(scope, name)] = [rse_id]
                    else:
                        source_replicas[(scope, name)].append(rse_id)
    else:
        # The evaluate_dids will be containers and/or datasets
        for did in dids:
            real_did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == did.child_scope, models.DataIdentifier.name == did.child_name).one()
            tmp_datasetfiles, tmp_locks, tmp_replicas, tmp_source_replicas = __resolve_did_to_locks_and_replicas(did=real_did,
                                                                                                                 nowait=nowait,
                                                                                                                 restrict_rses=restrict_rses,
                                                                                                                 source_rses=source_rses,
                                                                                                                 session=session)
            datasetfiles.extend(tmp_datasetfiles)
            locks = dict(locks.items() + tmp_locks.items())
            replicas = dict(replicas.items() + tmp_replicas.items())
            source_replicas = dict(source_replicas.items() + tmp_source_replicas.items())
    return datasetfiles, locks, replicas, source_replicas


@transactional_session
def __create_locks_replicas_transfers(datasetfiles, locks, replicas, source_replicas, rseselector, rule, preferred_rse_ids=[], source_rses=[], session=None):
    """
    Apply a created replication rule to a set of files

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding locks.
    :param replicas:           Dict holding replicas.
    :param source_replicas:    Dict holding source replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :raises:                   InsufficientAccountLimit, IntegrityError, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    logging.debug("Creating locks and replicas for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

    replicas_to_create, locks_to_create, transfers_to_create = apply_rule_grouping(datasetfiles=datasetfiles,
                                                                                   locks=locks,
                                                                                   replicas=replicas,
                                                                                   source_replicas=source_replicas,
                                                                                   rseselector=rseselector,
                                                                                   rule=rule,
                                                                                   preferred_rse_ids=preferred_rse_ids,
                                                                                   source_rses=source_rses,
                                                                                   session=session)
    # Add the replicas
    session.add_all([item for sublist in replicas_to_create.values() for item in sublist])
    session.flush()

    # Add the locks
    session.add_all([item for sublist in locks_to_create.values() for item in sublist])
    session.flush()

    # Increase rse_counters
    for rse_id in replicas_to_create.keys():
        rse_counter.increase(rse_id=rse_id, files=len(replicas_to_create[rse_id]), bytes=sum([replica.bytes for replica in replicas_to_create[rse_id]]), session=session)

    # Increase account_counters
    for rse_id in locks_to_create.keys():
        account_counter.increase(rse_id=rse_id, account=rule.account, files=len(locks_to_create[rse_id]), bytes=sum([lock.bytes for lock in locks_to_create[rse_id]]), session=session)

    # Add the transfers
    logging.debug("Rule %s  [%d/%d/%d] queued %d transfers" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt, len(transfers_to_create)))
    queue_requests(requests=transfers_to_create, session=session)
    session.flush()
    logging.debug("Finished creating locks and replicas for rule %s [%d/%d/%d]" % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))


@transactional_session
def __delete_lock_and_update_replica(lock, purge_replicas=False, nowait=False, session=None):
    """
    Delete a lock and update the associated replica.

    :param lock:            SQLAlchemy lock object.
    :param purge_replicas:  Purge setting of the rule.
    :param nowait:          The nowait option of the FOR UPDATE statement.
    :param session:         The database session in use.
    :returns:               True, if the lock was replicating and the associated transfer should be canceled; False otherwise.
    """

    logging.debug("Deleting lock %s:%s for rule %s" % (lock.scope, lock.name, str(lock.rule_id)))
    lock.delete(session=session, flush=False)
    try:
        replica = session.query(models.RSEFileAssociation).filter(
            models.RSEFileAssociation.scope == lock.scope,
            models.RSEFileAssociation.name == lock.name,
            models.RSEFileAssociation.rse_id == lock.rse_id).with_for_update(nowait=nowait).one()
        replica.lock_cnt -= 1
        if lock.state == LockState.REPLICATING and replica.lock_cnt == 0:
            replica.state = ReplicaState.UNAVAILABLE
        if replica.lock_cnt == 0:
            if purge_replicas:
                replica.tombstone = OBSOLETE
            elif replica.state == ReplicaState.UNAVAILABLE:
                replica.tombstone = OBSOLETE
            elif replica.accessed_at is not None:
                replica.tombstone = replica.accessed_at
            else:
                replica.tombstone = replica.created_at
        if lock.state == LockState.REPLICATING and replica.lock_cnt == 0:
            return True
    except NoResultFound:
        logging.error("Replica for lock %s:%s for rule %s on rse %s could not be found" % (lock.scope, lock.name, str(lock.rule_id), get_rse_name(lock.rse_id, session=session)))
    return False


@transactional_session
def __create_rule_approval_email(rule, session=None):
    """
    Create the rule notification email.

    :param rule:      The rule object.
    :param session:   The database session in use.
    """

    with open('%s/rule_approval_request.tmpl' % config_get('common', 'mailtemplatedir'), 'r') as templatefile:
        template = Template(templatefile.read())

    did = rucio.core.did.get_did(scope=rule.scope, name=rule.name, dynamic=True, session=session)
    rses = [rep['rse'] for rep in rucio.core.replica.list_dataset_replicas(scope=rule.scope, name=rule.name, session=session) if rep['state'] == ReplicaState.AVAILABLE]

    # Resolve recipents:
    recipents = __create_recipents_list(rse_expression=rule.rse_expression, session=session)

    for recipent in recipents:
        text = template.safe_substitute({'rule_id': str(rule.id),
                                         'created_at': str(rule.created_at),
                                         'expires_at': str(rule.expires_at),
                                         'account': rule.account,
                                         'email': get_account(account=rule.account, session=session).email,
                                         'rse_expression': rule.rse_expression,
                                         'comment': rule.comments,
                                         'scope': rule.scope,
                                         'name': rule.name,
                                         'did_type': rule.did_type,
                                         'length': '0' if did['length'] is None else str(did['length']),
                                         'bytes': '0' if did['bytes'] is None else sizefmt(did['bytes']),
                                         'closed': not did['open'],
                                         'complete_rses': ', '.join(rses),
                                         'approvers': ','.join([r[0] for r in recipents]),
                                         'approver': recipent[1]})

        add_message(event_type='email',
                    payload={'body': text,
                             'to': [recipent[0]],
                             'subject': '[RUCIO] Request to approve replication rule %s' % (str(rule.id))},
                    session=session)


@transactional_session
def __create_recipents_list(rse_expression, session=None):
    """
    Create a list of recipents for a notification email based on rse_expression.

    :param rse_exoression:  The rse_expression.
    :param session:         The database session in use.
    """

    recipents = []  # (eMail, account)

    # APPROVERS-LIST
    # If there are accounts in the approvers-list of any of the RSEs only these should be used
    for rse in parse_expression(rse_expression, session=session):
        rse_attr = list_rse_attributes(rse=rse['rse'], session=session)
        if rse_attr.get('rule_approvers'):
            for account in rse_attr.get('rule_approvers').split(','):
                try:
                    email = get_account(account=account, session=session).email
                    if email:
                        recipents.append((email, account))
                except:
                    pass

    # LOCALGROUPDISK/LOCALGROUPTAPE
    if not recipents:
        for rse in parse_expression(rse_expression, session=session):
            rse_attr = list_rse_attributes(rse=rse['rse'], session=session)
            if rse_attr.get('type', '') in ('LOCALGROUPDISK', 'LOCALGROUPTAPE'):
                accounts = session.query(models.AccountAttrAssociation.account).filter_by(key='country-%s' % rse_attr.get('country', ''),
                                                                                          value='admin').all()
                for account in accounts:
                    try:
                        email = get_account(account=account[0], session=session).email
                        if email:
                            recipents.append((email, account[0]))
                    except:
                        pass

    # GROUPDISK
    if not recipents:
        for rse in parse_expression(rse_expression, session=session):
            rse_attr = list_rse_attributes(rse=rse['rse'], session=session)
            if rse_attr.get('type', '') == 'GROUPDISK':
                accounts = session.query(models.AccountAttrAssociation.account).filter_by(key='group-%s' % rse_attr.get('physgroup', ''),
                                                                                          value='admin').all()
                for account in accounts:
                    try:
                        email = get_account(account=account[0], session=session).email
                        if email:
                            recipents.append((email, account[0]))
                    except:
                        pass

    # DDMADMIN as default
    if not recipents:
        recipents = [('atlas-adc-ddm-support@cern.ch', 'ddmadmin')]

    return list(set(recipents))
