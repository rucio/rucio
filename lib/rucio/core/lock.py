# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import logging
from datetime import datetime

from sqlalchemy.exc import DatabaseError
from sqlalchemy.sql.expression import and_, or_

import rucio.core.rule
import rucio.core.did
from rucio.common.exception import DataIdentifierNotFound
from rucio.core.lifetime_exception import define_eol
from rucio.core.rse import get_rse_attribute, get_rse_name

from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import LockState, RuleState, RuleGrouping, DIDType, RuleNotification
from rucio.db.sqla.session import read_session, transactional_session, stream_session

from rucio.common.types import InternalScope


@stream_session
def get_dataset_locks(scope, name, session=None):
    """
    Get the dataset locks of a dataset

    :param scope:          Scope of the dataset.
    :param name:           Name of the dataset.
    :param session:        The db session.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """

    query = session.query(models.DatasetLock.rse_id,
                          models.DatasetLock.scope,
                          models.DatasetLock.name,
                          models.DatasetLock.rule_id,
                          models.DatasetLock.account,
                          models.DatasetLock.state,
                          models.DatasetLock.length,
                          models.DatasetLock.bytes,
                          models.DatasetLock.accessed_at).filter_by(scope=scope, name=name)

    for rse_id, scope, name, rule_id, account, state, length, bytes_, accessed_at in query.yield_per(500):
        yield {'rse_id': rse_id,
               'rse': get_rse_name(rse_id, session=session),
               'scope': scope,
               'name': name,
               'rule_id': rule_id,
               'account': account,
               'state': state,
               'length': length,
               'bytes': bytes_,
               'accessed_at': accessed_at}


@stream_session
def get_dataset_locks_bulk(dids, session=None):
    """
    Get the dataset locks of a list of datasets or containers, recursively

    :param dids:           List of dictionaries {"scope":scope(type:InternalScope), "name":name,
                           "type":did type(DIDType.DATASET or DIDType.CONTAINER)}, "type" is optional
    :param session:        The db session to use.
    :return:               Generator of lock_info dicts, may contain duplicates
    """

    for did in dids:
        scope = did["scope"]
        assert isinstance(scope, InternalScope)
        name = did["name"]
        did_type = did.get("type")
        if not did_type:
            try:
                did_info = rucio.core.did.get_did(scope, name, session=session)
            except DataIdentifierNotFound:
                continue
            did_type = did_info["type"]
        assert did_type in (DIDType.DATASET, DIDType.CONTAINER)
        if did_type == DIDType.DATASET:
            for lock_dict in get_dataset_locks(scope, name, session=session):
                yield lock_dict
        else:
            for dataset_info in rucio.core.did.list_child_datasets(scope, name, session=session):
                dataset_scope, dataset_name = dataset_info["scope"], dataset_info["name"]
                for lock_dict in get_dataset_locks(dataset_scope, dataset_name, session=session):
                    yield lock_dict


@stream_session
def get_dataset_locks_by_rse_id(rse_id, session=None):
    """
    Get the dataset locks of an RSE.

    :param rse_id:         RSE id to get the locks from.
    :param session:        The db session.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """
    query = session.query(models.DatasetLock.rse_id,
                          models.DatasetLock.scope,
                          models.DatasetLock.name,
                          models.DatasetLock.rule_id,
                          models.DatasetLock.account,
                          models.DatasetLock.state,
                          models.DatasetLock.length,
                          models.DatasetLock.bytes,
                          models.DatasetLock.accessed_at).filter_by(rse_id=rse_id).\
        with_hint(models.DatasetLock, "index(DATASET_LOCKS DATASET_LOCKS_RSE_ID_IDX)", 'oracle')

    for rse_id, scope, name, rule_id, account, state, length, bytes_, accessed_at in query.yield_per(500):
        yield {'rse_id': rse_id,
               'rse': get_rse_name(rse_id, session=session),
               'scope': scope,
               'name': name,
               'rule_id': rule_id,
               'account': account,
               'state': state,
               'length': length,
               'bytes': bytes_,
               'accessed_at': accessed_at}


@read_session
def get_replica_locks(scope, name, nowait=False, restrict_rses=None, session=None):
    """
    Get the active replica locks for a file

    :param scope:          Scope of the did.
    :param name:           Name of the did.
    :param nowait:         Nowait parameter for the FOR UPDATE statement.
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session.
    :return:               List of dicts {'rse': ..., 'state': ...}
    :raises:               NoResultFound
    """

    query = session.query(models.ReplicaLock).filter_by(scope=scope, name=name)
    if restrict_rses is not None:
        rse_clause = []
        for rse_id in restrict_rses:
            rse_clause.append(models.ReplicaLock.rse_id == rse_id)
        if rse_clause:
            query = query.filter(or_(*rse_clause))

    return query.with_for_update(nowait=nowait).all()


@read_session
def get_replica_locks_for_rule_id(rule_id, session=None):
    """
    Get the active replica locks for a rule_id.

    :param rule_id:        Filter on rule_id.
    :param session:        The db session.
    :return:               List of dicts {'scope':, 'name':, 'rse': ..., 'state': ...}
    :raises:               NoResultFound
    """

    locks = []

    query = session.query(models.ReplicaLock).filter_by(rule_id=rule_id)

    for row in query:
        locks.append({'scope': row.scope,
                      'name': row.name,
                      'rse_id': row.rse_id,
                      'rse': get_rse_name(rse_id=row.rse_id, session=session),
                      'state': row.state,
                      'rule_id': row.rule_id})

    return locks


@read_session
def get_replica_locks_for_rule_id_per_rse(rule_id, session=None):
    """
    Get the active replica locks for a rule_id per rse.

    :param rule_id:        Filter on rule_id.
    :param session:        The db session.
    :return:               List of dicts {'rse_id':, 'rse':}
    :raises:               NoResultFound
    """

    locks = []

    query = session.query(models.ReplicaLock.rse_id).filter_by(rule_id=rule_id).group_by(models.ReplicaLock.rse_id)

    for row in query:
        locks.append({'rse_id': row.rse_id,
                      'rse': get_rse_name(rse_id=row.rse_id, session=session)})

    return locks


@read_session
def get_files_and_replica_locks_of_dataset(scope, name, nowait=False, restrict_rses=None, only_stuck=False,
                                           total_threads=None, thread_id=None,
                                           session=None):
    """
    Get all the files of a dataset and, if existing, all locks of the file.

    :param scope:          Scope of the dataset
    :param name:           Name of the datset
    :param nowait:         Nowait parameter for the FOR UPDATE statement
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param only_stuck:     If true, only get STUCK locks.
    :param total_threads:  Total threads
    :param thread_id:      This thread
    :param session:        The db session.
    :return:               Dictionary with keys: (scope, name)
                           and as value: [LockObject]
    :raises:               NoResultFound
    """
    locks = {}
    if session.bind.dialect.name == 'postgresql':
        content_query = session.query(models.DataIdentifierAssociation.child_scope,
                                      models.DataIdentifierAssociation.child_name).\
            with_hint(models.DataIdentifierAssociation,
                      "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                      'oracle').\
            filter(models.DataIdentifierAssociation.scope == scope,
                   models.DataIdentifierAssociation.name == name)

        if total_threads and total_threads > 1:
            content_query = filter_thread_work(session=session, query=content_query, total_threads=total_threads,
                                               thread_id=thread_id, hash_variable='child_name')

        for child_scope, child_name in content_query.yield_per(1000):
            locks[(child_scope, child_name)] = []

        query = session.query(models.DataIdentifierAssociation.child_scope,
                              models.DataIdentifierAssociation.child_name,
                              models.ReplicaLock).\
            with_hint(models.DataIdentifierAssociation,
                      "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)",
                      'oracle').\
            filter(and_(models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                        models.DataIdentifierAssociation.child_name == models.ReplicaLock.name))\
            .filter(models.DataIdentifierAssociation.scope == scope,
                    models.DataIdentifierAssociation.name == name)

        if restrict_rses is not None:
            rse_clause = []
            for rse_id in restrict_rses:
                rse_clause.append(models.ReplicaLock.rse_id == rse_id)
            if rse_clause:
                query = session.query(models.DataIdentifierAssociation.child_scope,
                                      models.DataIdentifierAssociation.child_name,
                                      models.ReplicaLock).\
                    with_hint(models.DataIdentifierAssociation, "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)", 'oracle').\
                    filter(and_(models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                                models.DataIdentifierAssociation.child_name == models.ReplicaLock.name,
                                or_(*rse_clause)))\
                    .filter(models.DataIdentifierAssociation.scope == scope,
                            models.DataIdentifierAssociation.name == name)
    else:
        query = session.query(models.DataIdentifierAssociation.child_scope,
                              models.DataIdentifierAssociation.child_name,
                              models.ReplicaLock).\
            with_hint(models.DataIdentifierAssociation, "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)", 'oracle').\
            outerjoin(models.ReplicaLock,
                      and_(models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                           models.DataIdentifierAssociation.child_name == models.ReplicaLock.name))\
            .filter(models.DataIdentifierAssociation.scope == scope, models.DataIdentifierAssociation.name == name)

        if restrict_rses is not None:
            rse_clause = []
            for rse_id in restrict_rses:
                rse_clause.append(models.ReplicaLock.rse_id == rse_id)
            if rse_clause:
                query = session.query(models.DataIdentifierAssociation.child_scope,
                                      models.DataIdentifierAssociation.child_name,
                                      models.ReplicaLock).\
                    with_hint(models.DataIdentifierAssociation, "INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)", 'oracle').\
                    outerjoin(models.ReplicaLock,
                              and_(models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                                   models.DataIdentifierAssociation.child_name == models.ReplicaLock.name,
                                   or_(*rse_clause)))\
                    .filter(models.DataIdentifierAssociation.scope == scope,
                            models.DataIdentifierAssociation.name == name)

    if only_stuck:
        query = query.filter(models.ReplicaLock.state == LockState.STUCK)

    if total_threads and total_threads > 1:
        query = filter_thread_work(session=session, query=query, total_threads=total_threads,
                                   thread_id=thread_id, hash_variable='child_name')

    query = query.with_for_update(nowait=nowait, of=models.ReplicaLock.state)

    for child_scope, child_name, lock in query:
        if (child_scope, child_name) not in locks:
            if lock is None:
                locks[(child_scope, child_name)] = []
            else:
                locks[(child_scope, child_name)] = [lock]
        else:
            locks[(child_scope, child_name)].append(lock)

    return locks


@transactional_session
def successful_transfer(scope, name, rse_id, nowait, session=None, logger=logging.log):
    """
    Update the state of all replica locks because of an successful transfer

    :param scope:    Scope of the did
    :param name:     Name of the did
    :param rse_id:   RSE id
    :param nowait:   Nowait parameter for the for_update queries.
    :param session:  DB Session.
    """

    locks = session.query(models.ReplicaLock).with_for_update(nowait=nowait).filter_by(scope=scope, name=name, rse_id=rse_id)
    for lock in locks:
        if lock.state == LockState.OK:
            continue
        logger(logging.DEBUG, 'Marking lock %s:%s for rule %s on rse %s as OK' % (lock.scope, lock.name, str(lock.rule_id), get_rse_name(rse_id=lock.rse_id, session=session)))
        # Update the rule counters
        rule = session.query(models.ReplicationRule).with_for_update(nowait=nowait).filter_by(id=lock.rule_id).one()
        logger(logging.DEBUG, 'Updating rule counters for rule %s [%d/%d/%d]' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

        if lock.state == LockState.REPLICATING:
            rule.locks_replicating_cnt -= 1
        elif lock.state == LockState.STUCK:
            rule.locks_stuck_cnt -= 1
        rule.locks_ok_cnt += 1
        lock.state = LockState.OK
        logger(logging.DEBUG, 'Finished updating rule counters for rule %s [%d/%d/%d]' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

        # Insert UpdatedCollectionReplica
        if rule.did_type == DIDType.DATASET:
            models.UpdatedCollectionReplica(scope=rule.scope,
                                            name=rule.name,
                                            did_type=rule.did_type,
                                            rse_id=rse_id).save(flush=False, session=session)
        elif rule.did_type == DIDType.CONTAINER:
            # Resolve to all child datasets
            for dataset in rucio.core.did.list_child_datasets(scope=rule.scope, name=rule.name, session=session):
                models.UpdatedCollectionReplica(scope=dataset['scope'],
                                                name=dataset['name'],
                                                did_type=DIDType.DATASET,
                                                rse_id=rse_id).save(flush=False, session=session)

        # Update the rule state
        if rule.state == RuleState.SUSPENDED:
            pass
        elif rule.locks_stuck_cnt > 0:
            pass
        elif rule.locks_replicating_cnt == 0 and rule.state == RuleState.REPLICATING:
            rule.state = RuleState.OK
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                ds_locks = session.query(models.DatasetLock).with_for_update(nowait=nowait).filter_by(rule_id=rule.id)
                for ds_lock in ds_locks:
                    ds_lock.state = LockState.OK
                session.flush()
            rucio.core.rule.generate_rule_notifications(rule=rule, replicating_locks_before=rule.locks_replicating_cnt + 1, session=session)
            if rule.notification == RuleNotification.YES:
                rucio.core.rule.generate_email_for_rule_ok_notification(rule=rule, session=session)
            # Try to release potential parent rules
            rucio.core.rule.release_parent_rule(child_rule_id=rule.id, session=session)
        elif rule.locks_replicating_cnt > 0 and rule.state == RuleState.REPLICATING and rule.notification == RuleNotification.PROGRESS:
            rucio.core.rule.generate_rule_notifications(rule=rule, replicating_locks_before=rule.locks_replicating_cnt + 1, session=session)

        # Insert rule history
        rucio.core.rule.insert_rule_history(rule=rule, recent=True, longterm=False, session=session)
        session.flush()


@transactional_session
def failed_transfer(scope, name, rse_id, error_message=None, broken_rule_id=None, broken_message=None, nowait=True, session=None, logger=logging.log):
    """
    Update the state of all replica locks because of a failed transfer.
    If a transfer is permanently broken for a rule, the broken_rule_id should be filled which puts this rule into the SUSPENDED state.

    :param scope:           Scope of the did.
    :param name:            Name of the did.
    :param rse_id:          RSE id.
    :param error_message:   The error why this transfer failed.
    :param broken_rule_id:  Id of the rule which will be suspended.
    :param broken_message:  Error message for the suspended rule.
    :param nowait:          Nowait parameter for the for_update queries.
    :param session:         The database session in use.
    """

    staging_required = get_rse_attribute(rse_id, 'staging_required', session=session)
    if staging_required:
        rse_name = get_rse_name(rse_id=rse_id, session=session)
        logger(logging.DEBUG, f'Destination RSE {rse_name} is type staging_required so do not update other OK replica locks.')
        locks = session.query(models.ReplicaLock).with_for_update(nowait=nowait).filter_by(scope=scope, name=name, rse_id=rse_id, state=LockState.REPLICATING)
    else:
        locks = session.query(models.ReplicaLock).with_for_update(nowait=nowait).filter_by(scope=scope, name=name, rse_id=rse_id)

    for lock in locks:
        if lock.state == LockState.STUCK:
            continue
        logger(logging.DEBUG, 'Marking lock %s:%s for rule %s on rse %s as STUCK' % (lock.scope, lock.name, str(lock.rule_id), get_rse_name(rse_id=lock.rse_id, session=session)))
        # Update the rule counters
        rule = session.query(models.ReplicationRule).with_for_update(nowait=nowait).filter_by(id=lock.rule_id).one()
        logger(logging.DEBUG, 'Updating rule counters for rule %s [%d/%d/%d]' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))
        if lock.state == LockState.REPLICATING:
            rule.locks_replicating_cnt -= 1
        elif lock.state == LockState.OK:
            rule.locks_ok_cnt -= 1
        rule.locks_stuck_cnt += 1
        lock.state = LockState.STUCK
        logger(logging.DEBUG, 'Finished updating rule counters for rule %s [%d/%d/%d]' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

        # Update the rule state
        if rule.state == RuleState.SUSPENDED:
            pass
        elif lock.rule_id == broken_rule_id:
            rule.state = RuleState.SUSPENDED
            rule.error = (broken_message[:245] + '...') if len(broken_message) > 245 else broken_message
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                ds_locks = session.query(models.DatasetLock).with_for_update(nowait=nowait).filter_by(rule_id=rule.id)
                for ds_lock in ds_locks:
                    ds_lock.state = LockState.STUCK
        elif rule.locks_stuck_cnt > 0:
            if rule.state != RuleState.STUCK:
                rule.state = RuleState.STUCK
                # Try to update the DatasetLocks
                if rule.grouping != RuleGrouping.NONE:
                    ds_locks = session.query(models.DatasetLock).with_for_update(nowait=nowait).filter_by(rule_id=rule.id)
                    for ds_lock in ds_locks:
                        ds_lock.state = LockState.STUCK
            if rule.error != error_message:
                rule.error = (error_message[:245] + '...') if len(error_message) > 245 else error_message

        # Insert rule history
        rucio.core.rule.insert_rule_history(rule=rule, recent=True, longterm=False, session=session)


@transactional_session
def touch_dataset_locks(dataset_locks, session=None):
    """
    Update the accessed_at timestamp of the given dataset locks + eol_at.

    :param replicas: the list of dataset locks.
    :param session: The database session in use.

    :returns: True, if successful, False otherwise.
    """

    now = datetime.utcnow()
    for dataset_lock in dataset_locks:
        eol_at = define_eol(dataset_lock['scope'], dataset_lock['name'], rses=[{'id': dataset_lock['rse_id']}], session=session)
        try:
            session.query(models.DatasetLock).filter_by(scope=dataset_lock['scope'], name=dataset_lock['name'], rse_id=dataset_lock['rse_id']).\
                update({'accessed_at': dataset_lock.get('accessed_at') or now}, synchronize_session=False)
            for res in session.query(models.DatasetLock.rule_id).filter_by(scope=dataset_lock['scope'], name=dataset_lock['name'], rse_id=dataset_lock['rse_id']):
                session.query(models.ReplicationRule).filter_by(id=res[0]).update({'eol_at': eol_at}, synchronize_session=False)
        except DatabaseError:
            return False

    return True
