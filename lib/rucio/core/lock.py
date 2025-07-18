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
from typing import TYPE_CHECKING, Any, Optional, Union

from sqlalchemy.exc import DatabaseError
from sqlalchemy.sql.expression import and_, or_, select, true, update

import rucio.core.did
import rucio.core.rule
from rucio.common.constants import RseAttr
from rucio.common.exception import DataIdentifierNotFound
from rucio.common.types import InternalScope, LoggerFunction
from rucio.core.lifetime_exception import define_eol
from rucio.core.rse import get_rse_attribute, get_rse_name
from rucio.db.sqla import filter_thread_work, models
from rucio.db.sqla.constants import DIDType, LockState, RuleGrouping, RuleNotification, RuleState
from rucio.db.sqla.session import read_session, stream_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from sqlalchemy.orm import Session


@stream_session
def get_dataset_locks(scope: InternalScope, name: str, *, session: "Session") -> "Iterator[dict[str, Any]]":
    """
    Get the dataset locks of a dataset

    :param scope:          Scope of the dataset.
    :param name:           Name of the dataset.
    :param session:        The db session.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """

    stmt = select(
        models.DatasetLock.rse_id,
        models.DatasetLock.scope,
        models.DatasetLock.name,
        models.DatasetLock.rule_id,
        models.DatasetLock.account,
        models.DatasetLock.state,
        models.DatasetLock.length,
        models.DatasetLock.bytes,
        models.DatasetLock.accessed_at
    ).where(
        and_(models.DatasetLock.scope == scope,
             models.DatasetLock.name == name)
    )

    for rse_id, scope, name, rule_id, account, state, length, bytes_, accessed_at in session.execute(stmt).yield_per(500):
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
def get_dataset_locks_bulk(dids: "Iterable[dict[str, Any]]", *, session: "Session") -> "Iterator[dict[str, Any]]":
    """
    Get the dataset locks of a list of datasets or containers, recursively

    :param dids:           List of dictionaries {"scope":scope(type:InternalScope), "name":name,
                           "type":DID type(DIDType.DATASET or DIDType.CONTAINER)}, "type" is optional
    :param session:        The db session to use.
    :return:               Generator of lock_info dicts, may contain duplicates
    """

    for did in dids:
        scope = did["scope"]
        if not isinstance(scope, InternalScope):
            raise ValueError("Scope must be passed as an InternalScope object.")
        name = did["name"]
        did_type = did.get("type")
        if not did_type:
            try:
                did_info = rucio.core.did.get_did(scope, name, session=session)
            except DataIdentifierNotFound:
                continue
            did_type = did_info["type"]

        if did_type == DIDType.DATASET:
            for lock_dict in get_dataset_locks(scope, name, session=session):
                yield lock_dict
        elif did_type == DIDType.CONTAINER:
            for dataset_info in rucio.core.did.list_child_datasets(scope, name, session=session):
                dataset_scope, dataset_name = dataset_info["scope"], dataset_info["name"]
                for lock_dict in get_dataset_locks(dataset_scope, dataset_name, session=session):
                    yield lock_dict
        else:
            raise ValueError("Can only get locks for datasets and containers.")


@stream_session
def get_dataset_locks_by_rse_id(rse_id: str, *, session: "Session") -> "Iterator[dict[str, Any]]":
    """
    Get the dataset locks of an RSE.

    :param rse_id:         RSE id to get the locks from.
    :param session:        The db session.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """
    stmt = select(
        models.DatasetLock.rse_id,
        models.DatasetLock.scope,
        models.DatasetLock.name,
        models.DatasetLock.rule_id,
        models.DatasetLock.account,
        models.DatasetLock.state,
        models.DatasetLock.length,
        models.DatasetLock.bytes,
        models.DatasetLock.accessed_at
    ).with_hint(
        models.DatasetLock,
        'INDEX(DATASET_LOCKS DATASET_LOCKS_RSE_ID_IDX)',
        'oracle'
    ).where(
        models.DatasetLock.rse_id == rse_id
    )

    for rse_id, scope, name, rule_id, account, state, length, bytes_, accessed_at in session.execute(stmt).yield_per(500):
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
def get_replica_locks(scope: InternalScope, name: str, nowait: bool = False, restrict_rses: Optional["Iterable[str]"] = None, *, session: "Session") -> list[models.ReplicaLock]:
    """
    Get the active replica locks for a file

    :param scope:          Scope of the DID.
    :param name:           Name of the DID.
    :param nowait:         Nowait parameter for the FOR UPDATE statement.
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session.
    :return:               List of dicts {'rse': ..., 'state': ...}
    :raises:               NoResultFound
    """

    stmt = select(
        models.ReplicaLock
    ).where(
        and_(models.ReplicaLock.scope == scope,
             models.ReplicaLock.name == name)
    )
    if restrict_rses is not None:
        rse_clause = []
        for rse_id in restrict_rses:
            rse_clause.append(models.ReplicaLock.rse_id == rse_id)
        if rse_clause:
            stmt = stmt.where(
                or_(*rse_clause)
            )

    stmt = stmt.with_for_update(
        nowait=nowait
    )
    return list(session.execute(stmt).scalars().all())


@read_session
def get_replica_locks_for_rule_id(rule_id: str, *, session: "Session") -> list[dict[str, Any]]:
    """
    Get the active replica locks for a rule_id.

    :param rule_id:        Filter on rule_id.
    :param session:        The db session.
    :return:               List of dicts {'scope':, 'name':, 'rse': ..., 'state': ...}
    :raises:               NoResultFound
    """

    locks = []

    stmt = select(
        models.ReplicaLock
    ).where(
        models.ReplicaLock.rule_id == rule_id
    )

    for row in session.execute(stmt).scalars().all():
        locks.append({'scope': row.scope,
                      'name': row.name,
                      'rse_id': row.rse_id,
                      'rse': get_rse_name(rse_id=row.rse_id, session=session),
                      'state': row.state,
                      'rule_id': row.rule_id})

    return locks


@read_session
def get_replica_locks_for_rule_id_per_rse(rule_id: str, *, session: "Session") -> list[dict[str, str]]:
    """
    Get the active replica locks for a rule_id per rse.

    :param rule_id:        Filter on rule_id.
    :param session:        The db session.
    :return:               List of dicts {'rse_id':, 'rse':}
    :raises:               NoResultFound
    """

    locks = []

    stmt = select(
        models.ReplicaLock.rse_id
    ).where(
        models.ReplicaLock.rule_id == rule_id
    ).group_by(
        models.ReplicaLock.rse_id
    )

    for rse_id in session.execute(stmt).scalars().all():
        locks.append({'rse_id': rse_id,
                      'rse': get_rse_name(rse_id=rse_id, session=session)})

    return locks


@read_session
def get_files_and_replica_locks_of_dataset(scope: InternalScope, name: str, nowait: bool = False, restrict_rses: Optional["Iterable[str]"] = None, only_stuck: bool = False,
                                           total_threads: Optional[int] = None, thread_id: Optional[int] = None,
                                           *, session: "Session") -> dict[tuple[InternalScope, str], Union[models.ReplicaLock, list[models.ReplicaLock]]]:
    """
    Get all the files of a dataset and, if existing, all locks of the file.

    :param scope:          Scope of the dataset
    :param name:           Name of the dataset
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

    rse_clause = [true()]
    if restrict_rses is not None:
        rse_clause = [models.ReplicaLock.rse_id == rse_id for rse_id in restrict_rses]

    base_stmt = select(
        models.DataIdentifierAssociation.child_scope,
        models.DataIdentifierAssociation.child_name
    ).where(
        and_(models.DataIdentifierAssociation.scope == scope,
             models.DataIdentifierAssociation.name == name)
    )
    stmt = base_stmt.add_columns(
        models.ReplicaLock
    ).with_for_update(
        nowait=nowait,
        of=models.ReplicaLock.state
    )

    if session.bind.dialect.name == 'postgresql':
        if total_threads and total_threads > 1:
            base_stmt = filter_thread_work(session=session, query=base_stmt, total_threads=total_threads,
                                           thread_id=thread_id, hash_variable='child_name')

        for child_scope, child_name in session.execute(base_stmt).yield_per(1000):
            locks[(child_scope, child_name)] = []

        stmt = stmt.where(
            and_(models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                 models.DataIdentifierAssociation.child_name == models.ReplicaLock.name,
                 or_(*rse_clause))
        )
    else:
        stmt = stmt.with_hint(
            models.DataIdentifierAssociation,
            'INDEX_RS_ASC(CONTENTS CONTENTS_PK) NO_INDEX_FFS(CONTENTS CONTENTS_PK)',
            'oracle'
        ).outerjoin(
            models.ReplicaLock,
            and_(models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                 models.DataIdentifierAssociation.child_name == models.ReplicaLock.name,
                 or_(*rse_clause))
        )

    if only_stuck:
        stmt = stmt.where(
            models.ReplicaLock.state == LockState.STUCK
        )

    if total_threads and total_threads > 1:
        stmt = filter_thread_work(session=session, query=stmt, total_threads=total_threads,
                                  thread_id=thread_id, hash_variable='child_name')

    for child_scope, child_name, lock in session.execute(stmt).all():
        if (child_scope, child_name) not in locks:
            if lock is None:
                locks[(child_scope, child_name)] = []
            else:
                locks[(child_scope, child_name)] = [lock]
        else:
            locks[(child_scope, child_name)].append(lock)

    return locks


@transactional_session
def successful_transfer(scope: InternalScope, name: str, rse_id: str, nowait: bool, *, session: "Session", logger: LoggerFunction = logging.log) -> None:
    """
    Update the state of all replica locks because of an successful transfer

    :param scope:    Scope of the DID
    :param name:     Name of the DID
    :param rse_id:   RSE id
    :param nowait:   Nowait parameter for the for_update queries.
    :param session:  DB Session.
    """

    stmt = select(
        models.ReplicaLock
    ).where(
        and_(models.ReplicaLock.scope == scope,
             models.ReplicaLock.name == name,
             models.ReplicaLock.rse_id == rse_id)
    ).with_for_update(
        nowait=nowait
    )
    for lock in session.execute(stmt).scalars().all():
        if lock.state == LockState.OK:
            continue
        logger(logging.DEBUG, 'Marking lock %s:%s for rule %s on rse %s as OK' % (lock.scope, lock.name, str(lock.rule_id), get_rse_name(rse_id=lock.rse_id, session=session)))
        # Update the rule counters
        stmt = select(
            models.ReplicationRule
        ).where(
            models.ReplicationRule.id == lock.rule_id
        ).with_for_update(
            nowait=nowait
        )
        rule = session.execute(stmt).scalar_one()
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
                stmt = select(
                    models.DatasetLock
                ).where(
                    models.DatasetLock.rule_id == rule.id
                ).with_for_update(
                    nowait=nowait
                )
                for ds_lock in session.execute(stmt).scalars().all():
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
def failed_transfer(scope: InternalScope, name: str, rse_id: str, error_message: Optional[str] = None, broken_rule_id: Optional[str] = None,
                    broken_message: Optional[str] = None, nowait: bool = True, *, session: "Session", logger: LoggerFunction = logging.log) -> None:
    """
    Update the state of all replica locks because of a failed transfer.
    If a transfer is permanently broken for a rule, the broken_rule_id should be filled which puts this rule into the SUSPENDED state.

    :param scope:           Scope of the DID.
    :param name:            Name of the DID.
    :param rse_id:          RSE id.
    :param error_message:   The error why this transfer failed.
    :param broken_rule_id:  Id of the rule which will be suspended.
    :param broken_message:  Error message for the suspended rule.
    :param nowait:          Nowait parameter for the for_update queries.
    :param session:         The database session in use.
    """

    staging_required = get_rse_attribute(rse_id, RseAttr.STAGING_REQUIRED, session=session)
    if staging_required:
        rse_name = get_rse_name(rse_id=rse_id, session=session)
        logger(logging.DEBUG, f'Destination RSE {rse_name} is type staging_required so do not update other OK replica locks.')
        stmt = select(
            models.ReplicaLock
        ).where(
            and_(models.ReplicaLock.scope == scope,
                 models.ReplicaLock.name == name,
                 models.ReplicaLock.rse_id == rse_id,
                 models.ReplicaLock.state == LockState.REPLICATING)
        ).with_for_update(
            nowait=nowait
        )
    else:
        stmt = select(
            models.ReplicaLock
        ).where(
            and_(models.ReplicaLock.scope == scope,
                 models.ReplicaLock.name == name,
                 models.ReplicaLock.rse_id == rse_id)
        ).with_for_update(
            nowait=nowait
        )

    for lock in session.execute(stmt).scalars().all():
        if lock.state == LockState.STUCK:
            continue
        logger(logging.DEBUG, 'Marking lock %s:%s for rule %s on rse %s as STUCK' % (lock.scope, lock.name, str(lock.rule_id), get_rse_name(rse_id=lock.rse_id, session=session)))
        # Update the rule counters
        stmt = select(
            models.ReplicationRule
        ).where(
            models.ReplicationRule.id == lock.rule_id
        ).with_for_update(
            nowait=nowait
        )
        rule = session.execute(stmt).scalar_one()
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
            if broken_message is not None and len(broken_message) > 245:
                rule.error = (broken_message[:245] + '...')
            else:
                rule.error = broken_message
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                stmt = select(
                    models.DatasetLock
                ).where(
                    models.DatasetLock.rule_id == rule.id
                ).with_for_update(
                    nowait=nowait
                )
                for ds_lock in session.execute(stmt).scalars().all():
                    ds_lock.state = LockState.STUCK
        elif rule.locks_stuck_cnt > 0:
            if rule.state != RuleState.STUCK:
                rule.state = RuleState.STUCK
                # Try to update the DatasetLocks
                if rule.grouping != RuleGrouping.NONE:
                    stmt = select(
                        models.DatasetLock
                    ).where(
                        models.DatasetLock.rule_id == rule.id
                    ).with_for_update(
                        nowait=nowait
                    )
                    for ds_lock in session.execute(stmt).scalars().all():
                        ds_lock.state = LockState.STUCK
            if rule.error != error_message:
                if error_message is not None and len(error_message) > 245:
                    rule.error = (error_message[:245] + '...')
                else:
                    rule.error = error_message

        # Insert rule history
        rucio.core.rule.insert_rule_history(rule=rule, recent=True, longterm=False, session=session)


@transactional_session
def touch_dataset_locks(dataset_locks: "Iterable[dict[str, Any]]", *, session: "Session") -> bool:
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
            stmt = update(
                models.DatasetLock
            ).where(
                and_(models.DatasetLock.scope == dataset_lock['scope'],
                     models.DatasetLock.name == dataset_lock['name'],
                     models.DatasetLock.rse_id == dataset_lock['rse_id'])
            ).values({
                models.DatasetLock.accessed_at: dataset_lock.get('accessed_at') or now
            }).execution_options(
                synchronize_session=False
            )
            subq = select(
                models.DatasetLock.rule_id
            ).where(
                and_(models.DatasetLock.scope == dataset_lock['scope'],
                     models.DatasetLock.name == dataset_lock['name'],
                     models.DatasetLock.rse_id == dataset_lock['rse_id'])
            )

            stmt = update(
                models.ReplicationRule
            ).where(
                models.ReplicationRule.id.in_(subq)
            ).values({
                models.ReplicationRule.eol_at: eol_at
            }).execution_options(
                synchronize_session=False
            )
            session.execute(stmt)
        except DatabaseError:
            return False

    return True
