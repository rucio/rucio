# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014

from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import and_, or_, bindparam, text

import rucio.core.did

from rucio.common.exception import (InvalidRSEExpression, InvalidReplicationRule, InsufficientAccountLimit,
                                    DataIdentifierNotFound, RuleNotFound,
                                    ReplicationRuleCreationFailed, InsufficientTargetRSEs, RucioException,
                                    AccessDenied, InvalidRuleWeight, StagingAreaRuleRequiresLifetime)
from rucio.core import account_counter, rse_counter
from rucio.core.lock import get_replica_locks, get_files_and_replica_locks_of_dataset
from rucio.core.monitor import record_timer_block
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.replica import get_and_lock_file_replicas, get_and_lock_file_replicas_for_dataset
from rucio.core.request import queue_requests, cancel_request_did
from rucio.core.rse_selector import RSESelector
from rucio.core.rule_grouping import apply_rule_grouping
from rucio.db import models
from rucio.db.constants import LockState, RuleState, RuleGrouping, DIDReEvaluation, DIDType, RequestType
from rucio.db.session import read_session, transactional_session, stream_session


@transactional_session
def add_rule(dids, account, copies, rse_expression, grouping, weight, lifetime, locked, subscription_id, session=None):
    """
    Adds a replication rule for every did in dids

    :param dids:             List of data identifiers.
    :param account:          Account issuing the rule.
    :param copies:           The number of replicas.
    :param rse_expression:   RSE expression which gets resolved into a list of rses.
    :param grouping:         ALL -  All files will be replicated to the same RSE.
                             DATASET - All files in the same dataset will be replicated to the same RSE.
                             NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
    :param weight:           Weighting scheme to be used.
    :param lifetime:         The lifetime of the replication rule in seconds.
    :param locked:           If the rule is locked.
    :param subscription_id:  The subscription_id, if the rule is created by a subscription.
    :param session:          The database session in use.
    :returns:                A list of created replication rule ids.
    :raises:                 InvalidReplicationRule, InsufficientAccountLimit, InvalidRSEExpression, DataIdentifierNotFound, ReplicationRuleCreationFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime
    """
    rule_ids = []

    with record_timer_block('rule.add_rule'):
        # 1. Resolve the rse_expression into a list of RSE-ids
        with record_timer_block('rule.add_rule.parse_rse_expression'):
            rses = parse_expression(rse_expression, session=session)

            if lifetime is None:  # Check if one of the rses is a staging area
                if [rse for rse in rses if rse.get('staging_area', False)]:
                    raise StagingAreaRuleRequiresLifetime()

        # 2. Create the rse selector
        with record_timer_block('rule.add_rule.create_rse_selector'):
            rseselector = RSESelector(account=account, rses=rses, weight=weight, copies=copies, session=session)

        expires_at = datetime.utcnow() + timedelta(seconds=lifetime) if lifetime is not None else None

        for elem in dids:
            # 3. Get the did
            with record_timer_block('rule.add_rule.get_did'):
                try:
                    did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == elem['scope'],
                                                                      models.DataIdentifier.name == elem['name']).one()
                except NoResultFound:
                    raise DataIdentifierNotFound('Data identifier %s:%s is not valid.' % (elem['scope'], elem['name']))

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
                                                  copies=copies,
                                                  rse_expression=rse_expression,
                                                  locked=locked,
                                                  grouping=grouping,
                                                  expires_at=expires_at,
                                                  weight=weight,
                                                  subscription_id=subscription_id)
                try:
                    new_rule.save(session=session)
                except IntegrityError, e:
                    raise InvalidReplicationRule(e.args[0])
                # except OperationalError, e:
                #    raise e

                rule_ids.append(new_rule.id)

            # 5. Resolve the did to its contents
            with record_timer_block('rule.add_rule.resolve_dids_to_locks_replicas'):
                datasetfiles, locks, replicas = __resolve_did_to_locks_and_replicas(did=did,
                                                                                    nowait=False,
                                                                                    restrict_rses=[rse['id'] for rse in rses],
                                                                                    session=session)

            # 6. Apply the replication rule to create locks, replicas and transfers
            with record_timer_block('rule.add_rule.create_locks_replicas_transfers'):
                __create_locks_replicas_transfers(datasetfiles=datasetfiles,
                                                  locks=locks,
                                                  replicas=replicas,
                                                  rseselector=rseselector,
                                                  rule=new_rule,
                                                  preferred_rse_ids=[],
                                                  session=session)

            if new_rule.locks_replicating_cnt == 0:
                new_rule.state = RuleState.OK
            else:
                new_rule.state = RuleState.REPLICATING

    return rule_ids


@transactional_session
def add_rules(dids, rules, session=None):
    """
    Adds a list of replication rules to every did in dids

    :params dids:    List of data identifiers.
    :param rules:    List of dictionaries defining replication rules.
                     {account, copies, rse_expression, grouping, weight, lifetime, locked, subscription_id}
    :param session:  The database session in use.
    :returns:        Dictionary (scope, name) with list of created rule ids
    :raises:         InvalidReplicationRule, InsufficientAccountLimit, InvalidRSEExpression, DataIdentifierNotFound, ReplicationRuleCreationFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime
    """

    with record_timer_block('rule.add_rules'):
        rule_ids = {}

        # 1. Fetch the RSEs from the RSE expression to restrict further queries just on these RSEs
        restrict_rses = []
        with record_timer_block('rule.add_rules.parse_rse_expressions'):
            for rule in rules:
                restrict_rses.extend(parse_expression(rule['rse_expression'], session=session))
            restrict_rses = list(set([rse['id'] for rse in restrict_rses]))

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

            # 3. Resolve the did into its contents
            with record_timer_block('rule.add_rules.resolve_dids_to_locks_replicas'):
                datasetfiles, locks, replicas = __resolve_did_to_locks_and_replicas(did=did,
                                                                                    nowait=False,
                                                                                    restrict_rses=restrict_rses,
                                                                                    session=session)

            for rule in rules:
                with record_timer_block('rule.add_rules.add_rule'):
                    # 4. Resolve the rse_expression into a list of RSE-ids
                    rses = parse_expression(rule['rse_expression'], session=session)

                    if rule.get('lifetime', None) is None:  # Check if one of the rses is a staging area
                        if [rse for rse in rses if rse.get('staging_area', False)]:
                            raise StagingAreaRuleRequiresLifetime()

                    # 5. Create the RSE selector
                    with record_timer_block('rule.add_rules.create_rse_selector'):
                        rseselector = RSESelector(account=rule['account'], rses=rses, weight=rule.get('weight'), copies=rule['copies'], session=session)

                    # 4. Create the replication rule
                    with record_timer_block('rule.add_rules.create_rule'):
                        if rule.get('grouping') == 'ALL':
                            grouping = RuleGrouping.ALL
                        elif rule.get('grouping') == 'NONE':
                            grouping = RuleGrouping.NONE
                        else:
                            grouping = RuleGrouping.DATASET
                        expires_at = datetime.utcnow() + timedelta(seconds=rule.get('lifetime')) if rule.get('lifetime') is not None else None
                        new_rule = models.ReplicationRule(account=rule['account'],
                                                          name=did.name,
                                                          scope=did.scope,
                                                          copies=rule['copies'],
                                                          rse_expression=rule['rse_expression'],
                                                          locked=rule.get('locked'),
                                                          grouping=grouping,
                                                          expires_at=expires_at,
                                                          weight=rule.get('weight'),
                                                          subscription_id=rule.get('subscription_id'))
                        try:
                            new_rule.save(session=session)
                        except IntegrityError, e:
                            raise InvalidReplicationRule(e.args[0])

                        rule_ids[(did.scope, did.name)].append(new_rule.id)

                    # 5. Apply the replication rule to create locks, replicas and transfers
                    with record_timer_block('rule.add_rules.create_locks_replicas_transfers'):
                        __create_locks_replicas_transfers(datasetfiles=datasetfiles,
                                                          locks=locks,
                                                          replicas=replicas,
                                                          rseselector=rseselector,
                                                          rule=new_rule,
                                                          preferred_rse_ids=[],
                                                          session=session)

                    if new_rule.locks_replicating_cnt == 0:
                        new_rule.state = RuleState.OK
                    else:
                        new_rule.state = RuleState.REPLICATING

    return rule_ids


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
        for (k, v) in filters.items():
            query = query.filter(getattr(models.ReplicationRule, k) == v)

    try:
        for rule in query.yield_per(5):
            d = {}
            for column in rule.__table__.columns:
                d[column.name] = getattr(rule, column.name)
            yield d
    except StatementError:
        raise RucioException('Badly formatted input (IDs?)')


@transactional_session
def delete_rule(rule_id, nowait=False, session=None):
    """
    Delete a replication rule.

    :param rule_id:   The rule to delete.
    :param nowait:    Nowait parameter for the FOR UPDATE statement.
    :param session:   The database session in use.
    :raises:          RuleNotFound if no Rule can be found.
    :raises:          AccessDenied if the Rule is locked.
    """

    with record_timer_block('rule.delete_rule'):
        try:
            rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rule_id).with_for_update(nowait=nowait).one()
        except NoResultFound:
            raise RuleNotFound('No rule with the id %s found' % (rule_id))
        if rule.locked:
            raise AccessDenied('The replication rule is locked and has to be unlocked before it can be deleted.')

        locks = session.query(models.ReplicaLock).filter(models.ReplicaLock.rule_id == rule_id).with_for_update(nowait=nowait).all()

        # Remove locks, set tombstone if applicable
        transfers_to_delete = []  # [{'scope': , 'name':, 'rse_id':}]
        account_counter_decreases = {}  # {'rse_id': [file_size, file_size, file_size]}

        for lock in locks:
            if __delete_lock_and_update_replica(lock=lock, nowait=nowait, session=session):
                transfers_to_delete.append({'scope': lock.scope, 'name': lock.name, 'rse_id': lock.rse_id})
            if lock.rse_id not in account_counter_decreases:
                account_counter_decreases[lock.rse_id] = []
            account_counter_decreases[lock.rse_id].append(lock.bytes)

        # Delete the DatasetLocks
        session.query(models.DatasetLock).filter(models.DatasetLock.rule_id == rule_id).delete(synchronize_session=False)

        # Decrease account_counters
        for rse_id in account_counter_decreases.keys():
            account_counter.decrease(rse_id=rse_id, account=rule.account, files=len(account_counter_decreases[rse_id]), bytes=sum(account_counter_decreases[rse_id]), session=session)

        session.flush()
        rule.delete(session=session)

        for transfer in transfers_to_delete:
            cancel_request_did(scope=transfer['scope'], name=transfer['name'], dest_rse=transfer['rse_id'], request_type=RequestType.TRANSFER)


@transactional_session
def repair_rule(rule_id, session=None):
    """
    Repair a STUCK replication rule.

    :param rule_id:   The rule to repair.
    :param session:   The database session in use.
    """

    # start_time = time.time()
    try:
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rule_id).with_for_update(nowait=True).one()
        # Identify what's wrong with the rule
        # (B) Rule is STUCK due to repeatedly failed transfers
        if rule.locks_stuck_cnt > 0:
            __repair_rule_with_stuck_locks(rule_obj=rule, session=session)
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
def update_lock_state(rule_id, lock_state, session=None):
    """
    Update lock state of a replication rule.

    :param rule_id:     The rule_id to lock.
    :param lock_state:  Boolean lock state.
    :param session:     The database session in use.
    :raises:            RuleNotFound if no Rule can be found.
    """

    try:
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()
        rule.locked = lock_state
    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))
    except StatementError:
        raise RucioException('Badly formatted rule id (%s)' % (rule_id))


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


@read_session
def get_updated_dids(total_workers, worker_number, limit=10, session=None):
    """
    Get updated dids.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of dids to return.
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
            query = query.filter('mod(md5(name), %s) = %s' % (total_workers, worker_number))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers, worker_number))

    return query.order_by(models.UpdatedDID.created_at).limit(limit).all()


@read_session
def get_expired_rules(total_workers, worker_number, limit=10, session=None):
    """
    Get expired rules.

    :param total_workers:      Number of total workers.
    :param worker_number:      id of the executing worker.
    :param limit:              Maximum number of rules to return.
    :param session:            Database session in use.
    """

    query = session.query(models.ReplicationRule.id).filter(models.ReplicationRule.expires_at < datetime.utcnow()).\
        with_hint(models.ReplicationRule, "index(rules RULES_EXPIRES_AT_IDX)", 'oracle').\
        order_by(models.ReplicationRule.expires_at)

    if session.bind.dialect.name == 'oracle':
        bindparams = [bindparam('worker_number', worker_number),
                      bindparam('total_workers', total_workers)]
        query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
    elif session.bind.dialect.name == 'mysql':
        query = query.filter('mod(md5(name), %s) = %s' % (total_workers, worker_number))
    elif session.bind.dialect.name == 'postgresql':
        query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_workers, worker_number))

    return query.limit(limit).all()


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
                                            models.UpdatedDID.id != id).delete(synchronize_session=False)


@transactional_session
def delete_updated_did(id, session=None):
    """
    Delete an updated_did by id.

    :param id:                      Id of the row not to delete.
    :param session:                 The database session in use.
    """
    session.query(models.UpdatedDID).filter(models.UpdatedDID.id == id).delete(synchronize_session=False)


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

    for lock in locks:
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == lock.rule_id).with_for_update(nowait=nowait).one()
        if lock.state == LockState.OK:
            rule.locks_ok_cnt -= 1
        elif lock.state == LockState.REPLICATING:
            rule.locks_replicating_cnt -= 1
        elif lock.state == LockState.STUCK:
            rule.locks_stuck_cnt -= 1
        account_counter.decrease(rse_id=rse_id, account=rule.account, files=1, bytes=lock.bytes, session=session)
        if rule.state == RuleState.SUSPENDED:
            continue
        elif rule.state == RuleState.STUCK:
            continue
        elif rule.locks_replicating_cnt == 0 and rule.locks_stuck_cnt == 0:
            rule.state == RuleState.OK
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})


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

    for lock in locks:
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == lock.rule_id).with_for_update(nowait=nowait).one()
        if lock.state == LockState.OK:
            rule.locks_ok_cnt -= 1
        elif lock.state == LockState.REPLICATING:
            rule.locks_replicating_cnt -= 1
        elif lock.state == LockState.STUCK:
            rule.locks_stuck_cnt -= 1
        rule.locks_replicating_cnt += 1
        queue_requests(requests=[{'dest_rse_id': rse_id,
                                  'scope': scope,
                                  'name': name,
                                  'rule_id': rule.id,
                                  'attributes': {},
                                  'request_type': RequestType.TRANSFER}], session=session)
        if rule.state == RuleState.SUSPENDED:
            continue
        elif rule.state == RuleState.STUCK:
            continue
        else:
            rule.state == RuleState.REPLICATING
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.REPLICATING})


@transactional_session
def __repair_rule_with_stuck_locks(rule_obj, session=None):
    """
    Repair a rule which has stuck replication locks.

    :param rule_obj:  The SQL Alchemy rule object.
    :param session:   The database session in use.
    """

    # Evaluate the RSE expression to see if there is an alternative RSE anyway
    # If not, the whole process can be stopped right now.

    # Get all STUCK locks
    stuck_locks = session.query(models.ReplicaLock).query(models.ReplicaLock.rule_id == rule_obj.id,
                                                          models.ReplicaLock.state == LockState.STUCK).\
        with_for_update(nowait=True).all()

    for stuck_lock in stuck_locks:
        print stuck_lock


@transactional_session
def __evaluate_did_detach(eval_did, session=None):
    """
    Evaluate a parent did which has children removed.

    :param eval_did:  The did object in use.
    :param session:   The database session in use.
    """

    with record_timer_block('rule.evaluate_did_detach'):
        # Get all parent DID's
        parent_dids = rucio.core.did.list_parent_dids(scope=eval_did.scope, name=eval_did.name, session=session)

        # Get all RR from parents and eval_did
        rules = session.query(models.ReplicationRule).filter_by(scope=eval_did.scope, name=eval_did.name).with_for_update(nowait=True).all()
        for did in parent_dids:
            rules.extend(session.query(models.ReplicationRule).filter_by(scope=did['scope'], name=did['name']).with_for_update(nowait=True).all())

        # Get all the files of eval_did
        files = {}
        for file in rucio.core.did.list_files(scope=eval_did.scope, name=eval_did.name, session=session):
            files[(file['scope'], file['name'])] = True

        # Iterate rules and delete locks
        transfers_to_delete = []  # [{'scope': , 'name':, 'rse_id':}]
        account_counter_decreases = {}  # {'rse_id': [file_size, file_size, file_size]}
        for rule in rules:
            query = session.query(models.ReplicaLock).filter_by(rule_id=rule.id)
            for lock in query:
                if (lock.scope, lock.name) not in files:
                    if __delete_lock_and_update_replica(lock=lock, nowait=True, session=session):
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
            if rule.state == RuleState.SUSPENDED:
                continue
            elif rule.state == RuleState.STUCK:
                continue
            elif rule.locks_replicating_cnt == 0 and rule.locks_stuck_cnt == 0:
                rule.state == RuleState.OK
                if rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})

        session.flush()

        # Decrease account_counters
        for rse_id in account_counter_decreases.keys():
            account_counter.decrease(rse_id=rse_id, account=rule.account, files=len(account_counter_decreases[rse_id]), bytes=sum(account_counter_decreases[rse_id]), session=session)

        for transfer in transfers_to_delete:
            cancel_request_did(scope=transfer['scope'], name=transfer['name'], dest_rse=transfer['rse_id'], request_type=RequestType.TRANSFER)


@transactional_session
def __evaluate_did_attach(eval_did, session=None):
    """
    Evaluate a parent did which has new childs

    :param eval_did:  The did object in use.
    :param session:   The database session in use.
    """

    with record_timer_block('rule.evaluate_did_attach'):
        # Get all parent DID's
        with record_timer_block('rule.evaluate_did_attach.list_parent_dids'):
            parent_dids = rucio.core.did.list_parent_dids(scope=eval_did.scope, name=eval_did.name, session=session)

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
                    models.ReplicationRule.state != RuleState.SUSPENDED).with_for_update(nowait=True).all()

            # Resolve the new_child_dids to its locks
            with record_timer_block('rule.evaluate_did_attach.resolve_did_to_locks_and_replicas'):
                # Resolve the rules to possible target rses:
                possible_rses = []
                if session.bind.dialect.name != 'sqlite':
                    session.begin_nested()
                try:
                    for rule in rules:
                        possible_rses.extend(parse_expression(rule.rse_expression, session=session))
                    possible_rses = list(set(possible_rses))
                except:
                    session.rollback()
                    possible_rses = []
                if session.bind.dialect.name != 'sqlite':
                    session.commit()

                datasetfiles, locks, replicas = __resolve_dids_to_locks_and_replicas(dids=new_child_dids,
                                                                                     nowait=True,
                                                                                     restrict_rses=[rse['id'] for rse in possible_rses],
                                                                                     session=session)

            # Evaluate the replication rules
            with record_timer_block('rule.evaluate_did_attach.evaluate_rules'):
                for rule in rules:
                    # 1. Resolve the rse_expression into a list of RSE-ids
                    if session.bind.dialect.name != 'sqlite':
                        session.begin_nested()
                    try:
                        rses = parse_expression(rule.rse_expression, session=session)
                    except (InvalidRSEExpression) as e:
                        session.rollback()
                        rule.state = RuleState.STUCK
                        rule.error = str(e)
                        rule.save(session=session)
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
                                                  session=session)
                    except (InvalidRuleWeight, InsufficientAccountLimit) as e:
                        session.rollback()
                        rule.state = RuleState.STUCK
                        rule.error = str(e)
                        rule.save(session=session)
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
                            models.DataIdentifierAssociation.name == eval_did.name,
                            models.DataIdentifierAssociation.rule_evaluation == False).first()   # noqa
                        if brother_did is not None:
                            # There are other files in the dataset
                            locks = get_replica_locks(scope=brother_did.child_scope,
                                                      name=brother_did.child_name,
                                                      rule_id=rule.id,
                                                      session=session)
                            preferred_rse_ids = [lock['rse_id'] for lock in locks]
                    try:
                        __create_locks_replicas_transfers(datasetfiles=datasetfiles,
                                                          locks=locks,
                                                          replicas=replicas,
                                                          rseselector=rseselector,
                                                          rule=rule,
                                                          preferred_rse_ids=preferred_rse_ids,
                                                          session=session)
                    except (InsufficientAccountLimit, ReplicationRuleCreationFailed, InsufficientTargetRSEs, InvalidReplicationRule) as e:
                        session.rollback()
                        rule.state = RuleState.STUCK
                        rule.error = str(e)
                        rule.save(session=session)
                        # Try to update the DatasetLocks
                        if rule.grouping != RuleGrouping.NONE:
                            session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                        continue

                    # 4. Update the Rule State
                    if rule.state == RuleState.STUCK:
                        pass
                    elif rule.locks_replicating_cnt > 0:
                        rule.state = RuleState.REPLICATING
                        if rule.grouping != RuleGrouping.NONE:
                            session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.REPLICATING})
                    elif rule.locks_replicating_cnt == 0 and rule.locks_stuck_cnt == 0:
                        rule.state = RuleState.OK
                        if rule.grouping != RuleGrouping.NONE:
                            session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})

                    if session.bind.dialect.name != 'sqlite':
                        session.commit()

            # Unflage the dids
            with record_timer_block('rule.evaluate_did_attach.update_did'):
                for did in new_child_dids:
                    did.rule_evaluation = None

        session.flush()


@transactional_session
def __resolve_did_to_locks_and_replicas(did, nowait=False, restrict_rses=None, session=None):
    """
    Resolves a did to its constituent childs and reads the locks and replicas of all the constituent files.

    :param did:            The db object of the did the rule is applied on.
    :param nowait:         Nowait parameter for the FOR UPDATE statement.
    :param restrict_rses:  Possible rses of the rule, so only these replica/locks should be considered.
    :param session:        Session of the db.
    :returns:              (datasetfiles, locks, replicas)
    """

    datasetfiles = []  # List of Datasets and their files in the Tree [{'scope':, 'name':, 'files': []}]
    # Files are in the format [{'scope':, 'name':, 'bytes':, 'md5':, 'adler32':}]
    locks = {}         # {(scope,name): [SQLAlchemy]}
    replicas = {}      # {(scope, name): [SQLAlchemy]}

    if did.did_type == DIDType.FILE:
        datasetfiles = [{'scope': None,
                         'name': None,
                         'files': [{'scope': did.scope,
                                    'name': did.name,
                                    'bytes': did.bytes,
                                    'md5': did.md5,
                                    'adler32': did.adler32}]}]
        locks[(did.scope, did.name)] = get_replica_locks(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, session=session)
        replicas[(did.scope, did.name)] = get_and_lock_file_replicas(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, session=session)

    elif did.did_type == DIDType.DATASET:
        files, replicas = get_and_lock_file_replicas_for_dataset(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, session=session)
        datasetfiles = [{'scope': did.scope,
                         'name': did.name,
                         'files': files}]
        locks = get_files_and_replica_locks_of_dataset(scope=did.scope, name=did.name, nowait=nowait, restrict_rses=restrict_rses, session=session)

    elif did.did_type == DIDType.CONTAINER:

        for dataset in rucio.core.did.list_child_datasets(scope=did.scope, name=did.name, session=session):
            files, tmp_replicas = get_and_lock_file_replicas_for_dataset(scope=dataset['scope'], name=dataset['name'], nowait=nowait, restrict_rses=restrict_rses, session=session)
            tmp_locks = get_files_and_replica_locks_of_dataset(scope=dataset['scope'], name=dataset['name'], nowait=nowait, restrict_rses=restrict_rses, session=session)
            datasetfiles.append({'scope': did.scope,
                                 'name': did.name,
                                 'files': files})
            replicas = dict(replicas.items() + tmp_replicas.items())
            locks = dict(locks.items() + tmp_locks.items())

    else:
        raise InvalidReplicationRule('The did \"%s:%s\" has been deleted.' % (did.scope, did.name))

    return datasetfiles, locks, replicas


@transactional_session
def __resolve_dids_to_locks_and_replicas(dids, nowait=False, restrict_rses=[], session=None):
    """
    Resolves a list of dids to its constituent childs and reads the locks and replicas of all the constituent files.

    :param dids:           The list of DIDAssociation objects.
    :param nowait:         Nowait parameter for the FOR UPDATE statement.
    :param restrict_rses:  Possible rses of the rule, so only these replica/locks should be considered.
    :param session:        Session of the db.
    :returns:              (datasetfiles, locks, replicas)
    """

    datasetfiles = []  # List of Datasets and their files in the Tree [{'scope':, 'name':, 'files': []}]
    # Files are in the format [{'scope':, 'name':, 'bytes':, 'md5':, 'adler32':}]
    locks = {}         # {(scope,name): [SQLAlchemy]}
    replicas = {}      # {(scope, name): [SQLAlchemy]}

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
        datasetfiles = [{'scope': dids[0].scope, 'name': dids[0].name, 'files': files}]

        # Prepare the locks and files
        lock_clauses = []
        replica_clauses = []
        for did in dids:
            lock_clauses.append(and_(models.ReplicaLock.scope == did.child_scope,
                                     models.ReplicaLock.name == did.child_name))
            replica_clauses.append(and_(models.RSEFileAssociation.scope == did.child_scope,
                                        models.RSEFileAssociation.name == did.child_name))
        lock_clause_chunks = [lock_clauses[x:x+10] for x in xrange(0, len(lock_clauses), 10)]
        replica_clause_chunks = [replica_clauses[x:x+10] for x in xrange(0, len(replica_clauses), 10)]

        replicas_rse_clause = []
        locks_rse_clause = []
        if restrict_rses:
            for rse_id in restrict_rses:
                replicas_rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
                locks_rse_clause.append(models.ReplicaLock.rse_id == rse_id)

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
                tmp_replicas = session.query(models.RSEFileAssociation).filter(or_(*replica_clause_chunk), or_(*replicas_rse_clause))\
                    .with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle')\
                    .with_for_update(nowait=nowait).all()
            else:
                tmp_replicas = session.query(models.RSEFileAssociation).filter(or_(*replica_clause_chunk))\
                    .with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle')\
                    .with_for_update(nowait=nowait).all()
            for replica in tmp_replicas:
                if (replica.scope, replica.name) not in replicas:
                    replicas[(replica.scope, replica.name)] = [replica]
                else:
                    replicas[(replica.scope, replica.name)].append(replica)
    else:
        # The evaluate_dids will be containers and/or datasets
        for did in dids:
            real_did = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == did.child_scope, models.DataIdentifier.name == did.child_name).one()
            tmp_datasetfiles, tmp_locks, tmp_replicas = __resolve_did_to_locks_and_replicas(did=real_did,
                                                                                            nowait=nowait,
                                                                                            restrict_rses=restrict_rses,
                                                                                            session=session)
            datasetfiles.extend(tmp_datasetfiles)
            locks = dict(locks.items() + tmp_locks.items())
            replicas = dict(replicas.items() + tmp_replicas.items())
    return datasetfiles, locks, replicas


@transactional_session
def __create_locks_replicas_transfers(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], session=None):
    """
    Apply a created replication rule to a set of files

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding locks.
    :param replicas:           Dict holding replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param session:            Session of the db.
    :raises:                   InsufficientAccountLimit, ReplicationRuleCreationFailed, InsufficientTargetRSEs, InvalidReplicationRule
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    replicas_to_create, locks_to_create, transfers_to_create = apply_rule_grouping(datasetfiles=datasetfiles,
                                                                                   locks=locks,
                                                                                   replicas=replicas,
                                                                                   rseselector=rseselector,
                                                                                   rule=rule,
                                                                                   preferred_rse_ids=preferred_rse_ids,
                                                                                   session=session)
    try:
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
        queue_requests(requests=transfers_to_create, session=session)
        session.flush()
    except (IntegrityError), e:
        raise ReplicationRuleCreationFailed(e.args[0])


@transactional_session
def __delete_lock_and_update_replica(lock, nowait=False, session=None):
    """
    Delete a lock and update the associated replica.

    :param lock:     SQLAlchemy lock object.
    :param nowait:   The nowait option of the FOR UPDATE statement.
    :param session:  The database session in use.
    :returns:        True, if the lock was replicating and the associated transfer should be canceled; False otherwise.
    """
    try:
        replica = session.query(models.RSEFileAssociation).filter(
            models.RSEFileAssociation.scope == lock.scope,
            models.RSEFileAssociation.name == lock.name,
            models.RSEFileAssociation.rse_id == lock.rse_id).with_for_update(nowait=nowait).one()
        replica.lock_cnt -= 1
        if replica.lock_cnt == 0:
            replica.tombstone = datetime.utcnow()
        lock.delete(session=session)
        if lock.state == LockState.REPLICATING and replica.lock_cnt == 0:
            return True
    except NoResultFound:
        pass
    return False
