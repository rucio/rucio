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
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import time

from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError, OperationalError, StatementError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import and_, or_, bindparam, text

import rucio.core.did

from rucio.common.exception import (InvalidRSEExpression, InvalidReplicationRule, InsufficientQuota,
                                    DataIdentifierNotFound, RuleNotFound,
                                    ReplicationRuleCreationFailed, InsufficientTargetRSEs, RucioException,
                                    AccessDenied, InvalidRuleWeight)
from rucio.core.account_counter import increase, decrease
from rucio.core.lock import get_replica_locks, get_files_and_replica_locks_of_dataset
from rucio.core.monitor import record_timer
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.request import queue_request, cancel_request_did
from rucio.core.rse_selector import RSESelector
from rucio.db import models
from rucio.db.constants import LockState, RuleState, RuleGrouping, DIDReEvaluation, DIDType, RequestType, ReplicaState
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
    :raises:                 InvalidReplicationRule, InsufficientQuota, InvalidRSEExpression, DataIdentifierNotFound, ReplicationRuleCreationFailed, InvalidRuleWeight
    """

    rule_start_time = time.time()

    # 1. Resolve the rse_expression into a list of RSE-ids
    rse_ids = parse_expression(rse_expression, session=session)
    selector = RSESelector(account=account, rse_ids=rse_ids, weight=weight, copies=copies, session=session)

    transfers_to_create = []
    rule_ids = []

    if lifetime is not None:
        expires_at = datetime.utcnow() + timedelta(seconds=lifetime)
    else:
        expires_at = None

    for elem in dids:
        # 2. Get and lock the did
        start_time = time.time()
        try:
            did = session.query(models.DataIdentifier).filter(
                models.DataIdentifier.scope == elem['scope'],
                models.DataIdentifier.name == elem['name']).one()
        except NoResultFound:
            raise DataIdentifierNotFound('Data identifier %s:%s is not valid.' % (elem['scope'], elem['name']))
        record_timer(stat='rule.lock_did', time=(time.time() - start_time)*1000)
        start_time = time.time()

        # 3. Create the replication rule
        if grouping == 'ALL':
            grouping = RuleGrouping.ALL
        elif grouping == 'NONE':
            grouping = RuleGrouping.NONE
        else:
            grouping = RuleGrouping.DATASET

        new_rule = models.ReplicationRule(account=account, name=elem['name'], scope=elem['scope'], copies=copies, rse_expression=rse_expression, locked=locked, grouping=grouping, expires_at=expires_at, weight=weight, subscription_id=subscription_id)
        try:
            new_rule.save(session=session)
        except IntegrityError, e:
            raise InvalidReplicationRule(e.args[0])
        except OperationalError, e:
            raise

        rule_id = new_rule.id
        rule_ids.append(rule_id)
        record_timer(stat='rule.create_rule', time=(time.time() - start_time)*1000)
        # 4. Resolve the did

        datasetfiles = __resolve_did_to_locks(did, lockmode='update', restrict_rses=rse_ids, session=session)
        # 5. Apply the replication rule to create locks and return a list of transfers
        transfers_to_create, locks_ok_cnt, locks_replicating_cnt = __apply_rule_to_files(datasetfiles=datasetfiles,
                                                                                         rseselector=selector,
                                                                                         account=account,
                                                                                         rule_id=rule_id,
                                                                                         copies=copies,
                                                                                         grouping=grouping,
                                                                                         session=session)
        new_rule.locks_ok_cnt = locks_ok_cnt
        new_rule.locks_replicating_cnt = locks_replicating_cnt
        if locks_replicating_cnt == 0:
            new_rule.state = RuleState.OK
        else:
            new_rule.state = RuleState.REPLICATING

    # 6. Create the transfers
    start_time = time.time()
    for transfer in transfers_to_create:
        queue_request(scope=transfer['scope'], name=transfer['name'], dest_rse_id=transfer['rse_id'], req_type=RequestType.TRANSFER, session=session)
    record_timer(stat='rule.queuing_transfers', time=(time.time() - start_time)*1000)
    record_timer(stat='rule.add_rule', time=(time.time() - rule_start_time)*1000)
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
    :raises:         InvalidReplicationRule, InsufficientQuota, InvalidRSEExpression, DataIdentifierNotFound, ReplicationRuleCreationFailed, InvalidRuleWeight
    """

    rule_ids = {}

    restrict_rses = []
    for rule in rules:
        restrict_rses.extend(parse_expression(rule['rse_expression'], session=session))

    for elem in dids:
        rule_ids[(elem['scope'], elem['name'])] = []
        # 1. Get and lock the dids
        try:
            did = session.query(models.DataIdentifier).filter(
                models.DataIdentifier.scope == elem['scope'],
                models.DataIdentifier.name == elem['name']).with_lockmode('update').one()
        except NoResultFound:
            raise DataIdentifierNotFound('Data identifier %s:%s is not valid.' % (elem['scope'], elem['name']))

        # 2. Resolve the did
        datasetfiles = __resolve_did_to_locks(did, lockmode='update', restrict_rses=restrict_rses, session=session)

        for rule in rules:
            rule_start_time = time.time()
            # 3. Resolve the rse_expression into a list of RSE-ids
            rse_ids = parse_expression(rule['rse_expression'], session=session)
            selector = RSESelector(account=rule['account'], rse_ids=rse_ids, weight=rule.get('weight'), copies=rule['copies'], session=session)

            # 4. Create the replication rule for every did
            if rule.get('grouping') == 'ALL':
                grouping = RuleGrouping.ALL
            elif rule.get('grouping') == 'NONE':
                grouping = RuleGrouping.NONE
            else:
                grouping = RuleGrouping.DATASET
            lifetime = rule.get('lifetime')
            if lifetime is not None:
                lifetime = datetime.utcnow() + timedelta(seconds=lifetime)
            new_rule = models.ReplicationRule(account=rule['account'],
                                              name=did.name,
                                              scope=did.scope,
                                              copies=rule['copies'],
                                              rse_expression=rule['rse_expression'],
                                              locked=rule.get('locked'),
                                              grouping=grouping,
                                              expires_at=lifetime,
                                              weight=rule.get('weight'),
                                              subscription_id=rule.get('subscription_id'))
            try:
                new_rule.save(session=session)
            except IntegrityError, e:
                raise InvalidReplicationRule(e.args[0])

            rule_id = new_rule.id
            rule_ids[(did.scope, did.name)].append(rule_id)
            # 5. Apply the replication rule to create locks and return a list of transfers
            transfers_to_create, locks_ok_cnt, locks_replicating_cnt = __apply_rule_to_files(datasetfiles=datasetfiles,
                                                                                             rseselector=selector,
                                                                                             account=rule['account'],
                                                                                             rule_id=rule_id,
                                                                                             copies=rule['copies'],
                                                                                             grouping=grouping,
                                                                                             session=session)
            new_rule.locks_ok_cnt = locks_ok_cnt
            new_rule.locks_replicating_cnt = locks_replicating_cnt
            if locks_replicating_cnt == 0:
                new_rule.state = RuleState.OK
            else:
                new_rule.state = RuleState.REPLICATING

            # 6. Create the transfers
            start_time = time.time()
            for transfer in transfers_to_create:
                queue_request(scope=transfer['scope'], name=transfer['name'], dest_rse_id=transfer['rse_id'], req_type=RequestType.TRANSFER, session=session)

            record_timer(stat='rule.queuing_transfers', time=(time.time() - start_time)*1000)
            record_timer(stat='rule.add_rule', time=(time.time() - rule_start_time)*1000)

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
def delete_rule(rule_id, lockmode='update', session=None):
    """
    Delete a replication rule.

    :param rule_id:   The rule to delete.
    :param lockmode:  The lockmode to be used by the session.
    :param session:   The database session in use.
    :raises:          RuleNotFound if no Rule can be found.
    :raises:          AccessDenied if the Rule is locked.
    """

    start_time = time.time()
    try:
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rule_id).with_lockmode(lockmode).one()
    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))
    if rule.locked:
        raise AccessDenied('The replication rule is locked and has to be unlocked before it can be deleted.')

    locks = session.query(models.ReplicaLock).filter(models.ReplicaLock.rule_id == rule_id).with_lockmode(lockmode).all()

    # Remove locks, set tombstone if applicable
    transfers_to_delete = []  # [{'scope': , 'name':, 'rse_id':}]
    account_counter_decreases = {}  # {'rse_id': [file_size, file_size, file_size]}

    for lock in locks:
        try:
            replica = session.query(models.RSEFileAssociation).filter(
                models.RSEFileAssociation.scope == lock.scope,
                models.RSEFileAssociation.name == lock.name,
                models.RSEFileAssociation.rse_id == lock.rse_id).with_lockmode(lockmode).one()

            replica.lock_cnt -= 1
            if replica.lock_cnt == 0:
                replica.tombstone = datetime.utcnow()
            if lock.state == LockState.REPLICATING and replica.lock_cnt == 0:
                transfers_to_delete.append({'scope': lock.scope, 'name': lock.name, 'rse_id': lock.rse_id})
        except NoResultFound:
            pass
        lock.delete(session=session)
        if lock.rse_id not in account_counter_decreases:
            account_counter_decreases[lock.rse_id] = []
        account_counter_decreases[lock.rse_id].append(lock.bytes)

    #Delete the DatasetLocks
    session.query(models.DatasetLock).filter(models.DatasetLock.rule_id == rule_id).delete(synchronize_session=False)

    # Decrease account_counters
    for rse_id in account_counter_decreases.keys():
        decrease(rse_id=rse_id, account=rule.account, delta=len(account_counter_decreases[rse_id]), bytes=sum(account_counter_decreases[rse_id]), session=session)

    session.flush()
    rule.delete(session=session)

    for transfer in transfers_to_delete:
        cancel_request_did(scope=transfer['scope'], name=transfer['name'], dest_rse=transfer['rse_id'], req_type=RequestType.TRANSFER)
    record_timer(stat='rule.delete_rule', time=(time.time() - start_time)*1000)


@transactional_session
def repair_rule(rule_id, session=None):
    """
    Repair a STUCK replication rule.

    :param rule_id:   The rule to repair.
    :param session:   The database session in use.
    """

    #start_time = time.time()
    try:
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rule_id).with_lockmode('update_nowait').one()
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
                          models.UpdatedDID.rule_evaluation_action).\
        order_by(models.UpdatedDID.created_at)

    if total_workers > 0:
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
        with_lockmode('update_nowait').all()

    for stuck_lock in stuck_locks:
        print stuck_lock


@transactional_session
def __evaluate_did_detach(eval_did, session=None):
    """
    Evaluate a parent did which has children removed.

    :param eval_did:  The did object in use.
    :param session:   The database session in use.
    """

    start_time = time.time()
    #Get all parent DID's
    parent_dids = rucio.core.did.list_parent_dids(scope=eval_did.scope, name=eval_did.name, session=session)

    #Get all RR from parents and eval_did
    rules = session.query(models.ReplicationRule).filter_by(scope=eval_did.scope, name=eval_did.name).all()
    for did in parent_dids:
        rules.extend(session.query(models.ReplicationRule).filter_by(scope=did['scope'], name=did['name']).all())

    #Get all the files of eval_did
    files = {}
    for file in rucio.core.did.list_files(scope=eval_did.scope, name=eval_did.name, session=session):
        files[(file['scope'], file['name'])] = True

    #Iterate rules and delete locks
    transfers_to_delete = []  # [{'scope': , 'name':, 'rse_id':}]
    for rule in rules:
        account_counter_decreases = {}  # {'rse_id': [file_size, file_size, file_size]}
        query = session.query(models.ReplicaLock).filter_by(rule_id=rule.id)
        for lock in query:
            if (lock.scope, lock.name) not in files:
                replica = session.query(models.RSEFileAssociation).filter(
                    models.RSEFileAssociation.scope == lock.scope,
                    models.RSEFileAssociation.name == lock.name,
                    models.RSEFileAssociation.rse_id == lock.rse_id).with_lockmode('update_nowait').one()
                replica.lock_cnt -= 1
                if lock.state == LockState.REPLICATING and replica.lock_cnt == 0:
                    transfers_to_delete.append({'scope': lock.scope, 'name': lock.name, 'rse_id': lock.rse_id})
                session.delete(lock)
                if replica.lock_cnt == 0:
                    replica.tombstone = datetime.utcnow()
                if lock.rse_id not in account_counter_decreases:
                    account_counter_decreases[lock.rse_id] = []
                account_counter_decreases[lock.rse_id].append(lock.bytes)
        # Decrease account_counters
        for rse_id in account_counter_decreases.keys():
            decrease(rse_id=rse_id, account=rule.account, delta=len(account_counter_decreases[rse_id]), bytes=sum(account_counter_decreases[rse_id]), session=session)

    session.flush()

    for transfer in transfers_to_delete:
        cancel_request_did(scope=transfer['scope'], name=transfer['name'], dest_rse=transfer['rse_id'], req_type=RequestType.TRANSFER)
    record_timer(stat='rule.evaluate_did_detach', time=(time.time() - start_time)*1000)


@transactional_session
def __evaluate_did_attach(eval_did, session=None):
    """
    Evaluate a parent did which has new childs

    :param eval_did:  The did object in use.
    :param session:   The database session in use.
    """

    start_time = time.time()
    #Get all parent DID's
    qtime = time.time()
    parent_dids = rucio.core.did.list_parent_dids(scope=eval_did.scope, name=eval_did.name, session=session)
    record_timer(stat='rule.opt_evaluate.list_parent_dids', time=(time.time() - qtime)*1000)

    #Get immediate child DID's
    qtime = time.time()
    new_child_dids = session.query(models.DataIdentifierAssociation).filter(
        models.DataIdentifierAssociation.scope == eval_did.scope,
        models.DataIdentifierAssociation.name == eval_did.name,
        models.DataIdentifierAssociation.rule_evaluation == True).all()  # noqa
    record_timer(stat='rule.opt_evaluate.list_child_dids', time=(time.time() - qtime)*1000)
    if new_child_dids:
        #Row-Lock all children of the evaluate_dids
        all_child_dscont = []
        if new_child_dids[0].child_type != DIDType.FILE:
            qtime = time.time()
            for did in new_child_dids:
                all_child_dscont.extend(rucio.core.did.list_child_dids(scope=did.child_scope, name=did.child_name, session=session))
            record_timer(stat='rule.opt_evaluate.list_child_dids2', time=(time.time() - qtime)*1000)

        #Get all unsuspended RR from parents and eval_did
        qtime = time.time()
        rule_clauses = []
        for did in parent_dids:
            rule_clauses.append(and_(models.ReplicationRule.scope == did['scope'],
                                     models.ReplicationRule.name == did['name']))
        rule_clauses.append(and_(models.ReplicationRule.scope == eval_did.scope,
                                 models.ReplicationRule.name == eval_did.name))
        rules = session.query(models.ReplicationRule).filter(or_(*rule_clauses),
                                                             models.ReplicationRule.state != RuleState.SUSPENDED).all()
        record_timer(stat='rule.opt_evaluate.get_rules', time=(time.time() - qtime)*1000)

        #Resolve the new_child_dids to its locks
        qtime = time.time()

        #Resolve the rules to possible target rses:
        possible_rses = []
        if session.bind.dialect.name != 'sqlite':
            session.begin_nested()
        try:
            for rule in rules:
                rse_ids = parse_expression(rule.rse_expression, session=session)
                possible_rses.extend(rse_ids)
        except:
            session.rollback()
            possible_rses = []
        if session.bind.dialect.name != 'sqlite':
            session.commit()

        if new_child_dids[0].child_type == DIDType.FILE:
            # All the evaluate_dids will be files!
            # Build the special files and datasetfiles object
            files = []
            lock_clauses = []
            replica_clauses = []
            dids = []
            for did in new_child_dids:
                lock_clauses.append(and_(models.ReplicaLock.scope == did.child_scope,
                                         models.ReplicaLock.name == did.child_name))
                replica_clauses.append(and_(models.RSEFileAssociation.scope == did.child_scope,
                                            models.RSEFileAssociation.name == did.child_name))
                dids.append(did)

            while len(dids) > 0:
                lock_clause = []
                replica_clause = []
                temp_dids = []
                while len(dids) > 0:
                    lock_clause.append(lock_clauses.pop())
                    replica_clause.append(replica_clauses.pop())
                    temp_dids.append(dids.pop())
                    if len(temp_dids) == 10:
                        break
                rse_clause1 = []
                rse_clause2 = []
                for rse_id in possible_rses:
                    rse_clause1.append(models.RSEFileAssociation.rse_id == rse_id)
                    rse_clause2.append(models.ReplicaLock.rse_id == rse_id)
                locks = session.query(models.ReplicaLock).filter(or_(*lock_clause), or_(*rse_clause2)).with_hint(models.ReplicaLock, "index(LOCKS LOCKS_PK)", 'oracle').with_lockmode('update_nowait').all()

                replicas = session.query(models.RSEFileAssociation).filter(or_(*replica_clause), or_(*rse_clause1)).with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').with_lockmode('update_nowait').all()

                for did in temp_dids:
                    files.append({'scope': did.child_scope,
                                  'name': did.child_name,
                                  'bytes': did.bytes,
                                  'locks': [{'rse_id': lock.rse_id, 'state': lock.state, 'rule_id': lock.rule_id} for lock in locks if lock.scope == did.child_scope and lock.name == did.child_name],
                                  'replicas': [replica for replica in replicas if replica.scope == did.child_scope and replica.name == did.child_name]})
            datasetfiles = [{'scope': None, 'name': None, 'files': files}]
        else:
            datasetfiles = []
            for did in new_child_dids:
                dsdid = session.query(models.DataIdentifier).filter(models.DataIdentifier.scope == did.child_scope, models.DataIdentifier.name == did.child_name).one()
                datasetfiles.extend(__resolve_did_to_locks(dsdid, lockmode='update_nowait', restrict_rses=possible_rses, session=session))
        record_timer(stat='rule.opt_evaluate.resolve_did_to_locks_and_replicas', time=(time.time() - qtime)*1000)

        qtime = time.time()
        for rule in rules:
            if session.bind.dialect.name != 'sqlite':
                session.begin_nested()
            # 1. Resolve the rse_expression into a list of RSE-ids
            try:
                rse_ids = parse_expression(rule.rse_expression, session=session)
            except (InvalidRSEExpression) as e:
                session.rollback()
                rule.state = RuleState.STUCK
                rule.error = str(e)
                rule.save(session=session)
                #Try to update the DatasetLocks
                if rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                continue

            # 2. Create the RSE Selector
            try:
                selector = RSESelector(account=rule.account,
                                       rse_ids=rse_ids,
                                       weight=rule.weight,
                                       copies=rule.copies,
                                       session=session)
            except (InvalidRuleWeight, InsufficientQuota) as e:
                session.rollback()
                rule.state = RuleState.STUCK
                rule.error = str(e)
                rule.save(session=session)
                #Try to update the DatasetLocks
                if rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                continue

            # 3. Apply the Replication rule to the Files
            preferred_rse_ids = []
            # 3.1 Check if the dids in question are files added to a dataset with DATASET/ALL grouping
            if new_child_dids[0].did_type == DIDType.FILE and rule.grouping != RuleGrouping.NONE:
                # Are there any existing did's in this dataset
                brother_did = session.query(models.DataIdentifierAssociation).filter(
                    models.DataIdentifierAssociation.scope == eval_did.scope,
                    models.DataIdentifierAssociation.name == eval_did.name,
                    models.DataIdentifierAssociation.rule_evaluation == True).first()   # noqa
                if brother_did is not None:
                    # There are other files in the dataset
                    locks = get_replica_locks(scope=brother_did.child_scope,
                                              name=brother_did.child_name,
                                              rule_id=rule.id,
                                              session=session)
                    preferred_rse_ids = [lock['rse_id'] for lock in locks]
            try:
                transfers, locks_ok_cnt, locks_replicating_cnt = __apply_rule_to_files(datasetfiles=datasetfiles,
                                                                                       rseselector=selector,
                                                                                       account=rule.account,
                                                                                       rule_id=rule.id,
                                                                                       copies=rule.copies,
                                                                                       grouping=rule.grouping,
                                                                                       preferred_rse_ids=preferred_rse_ids,
                                                                                       session=session)
                rule.locks_ok_cnt += locks_ok_cnt
                rule.locks_replicating_cnt += locks_replicating_cnt
            except (InsufficientQuota, ReplicationRuleCreationFailed, InsufficientTargetRSEs) as e:
                session.rollback()
                rule.state = RuleState.STUCK
                rule.error = str(e)
                rule.save(session=session)
                #Try to update the DatasetLocks
                if rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                continue

            # 4. Create Transfers
            if transfers:
                if rule.locks_stuck_cnt > 0:
                    rule.state = RuleState.STUCK
                    #Try to update the DatasetLocks
                    if rule.grouping != RuleGrouping.NONE:
                        session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
                else:
                    rule.state = RuleState.REPLICATING
                    #Try to update the DatasetLocks
                    if rule.grouping != RuleGrouping.NONE:
                        session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.REPLICATING})
                for transfer in transfers:
                    queue_request(scope=transfer['scope'], name=transfer['name'], dest_rse_id=transfer['rse_id'], req_type=RequestType.TRANSFER, session=session)
            else:
                rule.state = RuleState.OK
                #Try to update the DatasetLocks
                if rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})
            if session.bind.dialect.name != 'sqlite':
                session.commit()
        record_timer(stat='rule.opt_evaluate.evaluate_rules', time=(time.time() - qtime)*1000)
        qtime = time.time()
        for did in new_child_dids:
            did.rule_evaluation = None
        record_timer(stat='rule.opt_evaluate.update_did', time=(time.time() - qtime)*1000)

    session.flush()
    record_timer(stat='rule.evaluate_did_attach', time=(time.time() - start_time)*1000)


@transactional_session
def __resolve_did_to_locks(did, lockmode, restrict_rses=None, session=None):
    """
    Resolves a did to its constituent childs and reads the locks and replicas of all the constituent files.

    :param did:            The db object of the did the rule is applied on.
    :param lockmode:       Lockmode the session should use.
    :param restrict_rses:  Possible rses of the rule, so only these replica/locks should be considered.
    :param session:        Session of the db.
    :returns:              datasetfiles dict.
    """

    start_time = time.time()
    datasetfiles = []  # List of Datasets and their files in the Tree [{'scope':, 'name':, 'files':}]
                       # Files are in the format [{'scope': ,'name':, 'bytes':, 'locks': [{'rse_id':, 'state':, 'rule_id':}]}, 'replicas': [SQLALchemy Replica Objects]]

    # a) Resolve the did
    if did.did_type == DIDType.FILE:
        files = [{'scope': did.scope,
                  'name': did.name,
                  'bytes': did.bytes,
                  'locks': get_replica_locks(scope=did.scope, name=did.name, lockmode=lockmode, restrict_rses=restrict_rses, session=session),
                  'replicas': __get_and_lock_file_replicas(scope=did.scope, name=did.name, lockmode=lockmode, restrict_rses=restrict_rses, session=session)}]
        datasetfiles = [{'scope': None, 'name': None, 'files': files}]
    elif did.did_type == DIDType.DATASET:
        files = []
        tmp_locks = get_files_and_replica_locks_of_dataset(scope=did.scope, name=did.name, lockmode=lockmode, restrict_rses=restrict_rses, session=session)
        tmp_replicas = __get_and_lock_file_replicas_for_dataset(scope=did.scope, name=did.name, lockmode=lockmode, restrict_rses=restrict_rses, session=session)
        for lock in tmp_locks.values():
            tmp_replicas[(lock['scope'], lock['name'])]['locks'] = lock['locks']
        datasetfiles = [{'scope': did.scope, 'name': did.name, 'files': tmp_replicas.values()}]
    elif did.did_type == DIDType.CONTAINER:
        for dscont in rucio.core.did.list_child_dids(scope=did.scope, name=did.name, lockmode=None, session=session):
            tmp_locks = get_files_and_replica_locks_of_dataset(scope=dscont['scope'], name=dscont['name'], lockmode=lockmode, restrict_rses=restrict_rses, session=session)
            tmp_replicas = __get_and_lock_file_replicas_for_dataset(scope=dscont['scope'], name=dscont['name'], lockmode=lockmode, restrict_rses=restrict_rses, session=session)
            for lock in tmp_locks.values():
                tmp_replicas[(lock['scope'], lock['name'])]['locks'] = lock['locks']
            datasetfiles.append({'scope': dscont['scope'], 'name': dscont['name'], 'files': tmp_replicas.values()})
    else:
        raise InvalidReplicationRule('The did \"%s:%s\" has been deleted.' % (did.scope, did.name))
    record_timer(stat='rule.resolve_did_to_locks', time=(time.time() - start_time)*1000)
    return datasetfiles


@transactional_session
def __apply_rule_to_files(datasetfiles, rseselector, account, rule_id, copies, grouping, preferred_rse_ids=[], session=None):
    """
    Apply a created replication rule to a set of files

    :param datasetfiles:       Special dict holding all datasets and files.
    :param rseselector:        The RSESelector to be used.
    :param account:            The account.
    :param rule_id:            The rule_id.
    :param copies:             Number of copies.
    :param grouping:           The grouping to be used.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param session:            Session of the db.
    :returns:                  (List of transfers to create, #locks_ok_cnt, #locks_replicating_cnt)
    :raises:                   InsufficientQuota, ReplicationRuleCreationFailed, InsufficientTargetRSEs
    """

    start_time = time.time()
    locks_to_create = []      # DB Objects
    transfers_to_create = []  # [{'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']}]
    replicas_to_create = []   # DB Objects

    account_counter_increases = {}  # {'rse_id': [file_size, file_size, file_size]}

    locks_ok_cnt = 0
    locks_replicating_cnt = 0

    if grouping == RuleGrouping.NONE:
        # ########
        # # NONE #
        # ########
        for dataset in datasetfiles:
            for file in dataset['files']:
                if len([lock for lock in file['locks'] if lock['rule_id'] == rule_id]) == copies:
                    # Nothing to do as the file already has the requested amount of locks
                    continue
                if len(preferred_rse_ids) == 0:
                    rse_ids = rseselector.select_rse(file['bytes'], [replica.rse_id for replica in file['replicas']], [replica.rse_id for replica in file['replicas'] if replica.state == ReplicaState.BEING_DELETED])
                else:
                    rse_ids = rseselector.select_rse(file['bytes'], preferred_rse_ids, [replica.rse_id for replica in file['replicas'] if replica.state == ReplicaState.BEING_DELETED])
                for rse_id in rse_ids:
                    replica = [replica for replica in file['replicas'] if replica.rse_id == rse_id]
                    if len(replica) > 0:
                        replica = replica[0]
                        # A replica exists
                        if replica.state == ReplicaState.AVAILABLE:
                            # Replica is fully available
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.OK))
                            file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.OK})
                            replica.lock_cnt += 1
                            replica.tombstone = None
                            locks_ok_cnt += 1
                        else:
                            # Replica is not available at rse yet
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                            file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.REPLICATING})
                            replica.lock_cnt += 1
                            replica.tombstone = None
                            locks_replicating_cnt += 1
                    else:
                        # Replica has to be created
                        locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.REPLICATING})
                        replica = models.RSEFileAssociation(rse_id=rse_id, scope=file['scope'], name=file['name'], bytes=file['bytes'], lock_cnt=1, state=ReplicaState.UNAVAILABLE)
                        replicas_to_create.append(replica)
                        file['replicas'].append(replica)
                        transfers_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']})
                        locks_replicating_cnt += 1
                    # Update the account_counter icreases dict for later counter update
                    if rse_id not in account_counter_increases:
                        account_counter_increases[rse_id] = []
                    account_counter_increases[rse_id].append(file['bytes'])

    elif grouping == RuleGrouping.ALL:
        # #######
        # # ALL #
        # #######
        bytes = 0
        rse_coverage = {}  # {'rse_id': coverage }
        blacklist = set()
        for dataset in datasetfiles:
            for file in dataset['files']:
                bytes += file['bytes']
                for replica in file['replicas']:
                    if replica.rse_id in rse_coverage:
                        rse_coverage[replica.rse_id] += file['bytes']
                    else:
                        rse_coverage[replica.rse_id] = file['bytes']
                    if replica.state == ReplicaState.BEING_DELETED:
                        blacklist.add(replica.rse_id)
        if len(preferred_rse_ids) == 0:
            rse_ids = rseselector.select_rse(bytes, [x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)], list(blacklist))
        else:
            rse_ids = rseselector.select_rse(bytes, preferred_rse_ids, list(blacklist))
        for rse_id in rse_ids:
            for dataset in datasetfiles:
                dataset_is_replicating = False
                for file in dataset['files']:
                    if len([lock for lock in file['locks'] if lock['rule_id'] == rule_id]) == copies:
                        continue
                    replica = [replica for replica in file['replicas'] if replica.rse_id == rse_id]
                    if len(replica) > 0:
                        replica = replica[0]
                        # A replica exists
                        if replica.state == ReplicaState.AVAILABLE:
                            # Replica is fully available
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.OK))
                            file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.OK})
                            replica.lock_cnt += 1
                            replica.tombstone = None
                            locks_ok_cnt += 1
                        else:
                            # Replica is not available at rse yet
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                            dataset_is_replicating = True
                            file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.REPLICATING})
                            replica.lock_cnt += 1
                            replica.tombstone = None
                            locks_replicating_cnt += 1
                    else:
                        # Replica has to be created
                        locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        dataset_is_replicating = True
                        file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.REPLICATING})
                        replica = models.RSEFileAssociation(rse_id=rse_id, scope=file['scope'], name=file['name'], bytes=file['bytes'], lock_cnt=1, state=ReplicaState.UNAVAILABLE)
                        replicas_to_create.append(replica)
                        file['replicas'].append(replica)
                        transfers_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']})
                        locks_replicating_cnt += 1
                    # Update the account_counter icreases dict for later counter update
                    if rse_id not in account_counter_increases:
                        account_counter_increases[rse_id] = []
                    account_counter_increases[rse_id].append(file['bytes'])
                # Add a DatasetLock to the DB
                if dataset['scope'] is not None:
                    locks_to_create.append(models.DatasetLock(scope=dataset['scope'], name=dataset['name'], rule_id=rule_id, rse_id=rse_id, state=LockState.REPLICATING if dataset_is_replicating else LockState.OK, account=account))
    else:
        # ###########
        # # DATASET #
        # ###########
        for dataset in datasetfiles:
            dataset_is_replicating = False
            bytes = sum([file['bytes'] for file in dataset['files']])
            rse_coverage = {}  # {'rse_id': coverage }
            blacklist = set()
            for file in dataset['files']:
                for replica in file['replicas']:
                    if replica.rse_id in rse_coverage:
                        rse_coverage[replica.rse_id] += file['bytes']
                    else:
                        rse_coverage[replica.rse_id] = file['bytes']
                    if replica.state == ReplicaState.BEING_DELETED:
                        blacklist.add(replica.rse_id)
            if len(preferred_rse_ids) == 0:
                rse_ids = rseselector.select_rse(bytes, [x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)], list(blacklist))
            else:
                rse_ids = rseselector.select_rse(bytes, preferred_rse_ids, list(blacklist))
            for rse_id in rse_ids:
                for file in dataset['files']:
                    if len([lock for lock in file['locks'] if lock['rule_id'] == rule_id]) == copies:
                        continue
                    replica = [replica for replica in file['replicas'] if replica.rse_id == rse_id]
                    if len(replica) > 0:
                        replica = replica[0]
                        # A replica exists
                        if replica.state == ReplicaState.AVAILABLE:
                            # Replica is fully available
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.OK))
                            file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.OK})
                            replica.lock_cnt += 1
                            replica.tombstone = None
                            locks_ok_cnt += 1
                        else:
                            # Replica is not available at rse yet
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                            dataset_is_replicating = True
                            file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.REPLICATING})
                            replica.lock_cnt += 1
                            replica.tombstone = None
                            locks_replicating_cnt += 1
                    else:
                        # Replica has to be created
                        locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        dataset_is_replicating = True
                        file['locks'].append({'rse_id': rse_id, 'rule_id': rule_id, 'state': LockState.REPLICATING})
                        replica = models.RSEFileAssociation(rse_id=rse_id, scope=file['scope'], name=file['name'], bytes=file['bytes'], lock_cnt=1, state=ReplicaState.UNAVAILABLE)
                        replicas_to_create.append(replica)
                        file['replicas'].append(replica)
                        transfers_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']})
                        locks_replicating_cnt += 1
                    # Update the account_counter icreases dict for later counter update
                    if rse_id not in account_counter_increases:
                        account_counter_increases[rse_id] = []
                    account_counter_increases[rse_id].append(file['bytes'])
                # Add a DatasetLock to the DB
                if dataset['scope'] is not None:
                    locks_to_create.append(models.DatasetLock(scope=dataset['scope'], name=dataset['name'], rule_id=rule_id, rse_id=rse_id, state=LockState.REPLICATING if dataset_is_replicating else LockState.OK, account=account))
    # d) Put the locks to the DB, Put the Replicas in the DBreturn the transfers
    try:
        session.add_all(replicas_to_create)
        session.flush()
        session.add_all(locks_to_create)
        session.flush()
        # Increase account_counters
        for rse_id in account_counter_increases.keys():
            increase(rse_id=rse_id, account=account, delta=len(account_counter_increases[rse_id]), bytes=sum(account_counter_increases[rse_id]), session=session)
    except IntegrityError, e:
        raise ReplicationRuleCreationFailed(e.args[0])

    record_timer(stat='rule.apply_rule_to_files', time=(time.time() - start_time)*1000)
    return(transfers_to_create, locks_ok_cnt, locks_replicating_cnt)


@transactional_session
def __get_and_lock_file_replicas(scope, name, lockmode, restrict_rses=None, session=None):
    """
    Get file replicas for a specific scope:name.

    :param scope:          The scope of the did.
    :param name:           The name of the did.
    :param lockmode:       Lockmode the session has to use.
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session in use.
    :returns:              List of SQLAlchemy Replica Objects
    """

    query = session.query(models.RSEFileAssociation).filter_by(scope=scope, name=name)
    if restrict_rses is not None:
        if len(restrict_rses) < 10:
            rse_clause = []
            for rse_id in restrict_rses:
                rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
            if rse_clause:
                query = query.filter(or_(*rse_clause))
    if lockmode is not None:
        query = query.with_lockmode(lockmode)
    return query.all()


@transactional_session
def __get_and_lock_file_replicas_for_dataset(scope, name, lockmode, restrict_rses=None, session=None):
    """
    Get file replicas for all files of a dataset.

    :param scope:          The scope of the dataset.
    :param name:           The name of the dataset.
    :param lockmode:       Lockmode the session has to use.
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session in use.
    :returns:              List of dict.
    """

    files = {}

    query = session.query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.bytes,
                          models.RSEFileAssociation)\
        .outerjoin(models.RSEFileAssociation,
                   and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                        models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name))\
        .filter(models.DataIdentifierAssociation.scope == scope,
                models.DataIdentifierAssociation.name == name)

    if restrict_rses is not None:
        if len(restrict_rses) < 10:
            rse_clause = []
            for rse_id in restrict_rses:
                rse_clause.append(models.RSEFileAssociation.rse_id == rse_id)
            if rse_clause:
                query = session.query(models.DataIdentifierAssociation.child_scope,
                                      models.DataIdentifierAssociation.child_name,
                                      models.DataIdentifierAssociation.bytes,
                                      models.RSEFileAssociation)\
                    .outerjoin(models.RSEFileAssociation,
                               and_(models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                                    models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name,
                                    or_(*rse_clause)))\
                    .filter(models.DataIdentifierAssociation.scope == scope,
                            models.DataIdentifierAssociation.name == name)

    if lockmode is not None:
        query = query.with_lockmode(lockmode)

    for child_scope, child_name, bytes, replica in query:
        if replica is None:
            files[(child_scope, child_name)] = {'scope': child_scope, 'name': child_name, 'bytes': bytes, 'replicas': [], 'locks': []}
        else:
            if (child_scope, child_name) in files:
                files[(child_scope, child_name)]['replicas'].append(replica)
            else:
                files[(child_scope, child_name)] = {'scope': child_scope, 'name': child_name, 'bytes': bytes, 'replicas': [replica], 'locks': []}
    return files
