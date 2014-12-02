# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

import logging
import sys

from sqlalchemy.sql.expression import and_, or_

import rucio.core.rule

from rucio.common.config import config_get
from rucio.core.rse import get_rse_name
from rucio.db import models
from rucio.db.constants import LockState, RuleState, RuleGrouping
from rucio.db.session import read_session, transactional_session

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


@read_session
def get_dataset_locks(scope, name, session=None):
    """
    Get the dataset locks of a dataset

    :param scope:          Scope of the dataset.
    :param name:           Name of the dataset.
    :param session:        The db session.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """

    query = session.query(models.DatasetLock).filter_by(scope=scope, name=name)

    locks = []
    for row in query:
        locks.append({'rse_id': row.rse_id,
                      'rse': get_rse_name(row.rse_id, session=session),
                      'scope': row.scope,
                      'name': row.name,
                      'rule_id': row.rule_id,
                      'account': row.account,
                      'state': row.state})
    return locks


@read_session
def get_dataset_locks_by_rse_id(rse_id, session=None):
    """
    Get the dataset locks of an RSE.

    :param rse_id:         RSE id to get the locks from.
    :param session:        The db session.
    :return:               List of dicts {'rse_id': ..., 'state': ...}
    """

    query = session.query(models.DatasetLock).filter_by(rse_id=rse_id).\
        with_hint(models.DatasetLock, "index(DATASET_LOCKS DATASET_LOCKS_RSE_ID_IDX)", 'oracle')

    locks = []
    for row in query:
        locks.append({'rse_id': row.rse_id,
                      'rse': get_rse_name(row.rse_id, session=session),
                      'scope': row.scope,
                      'name': row.name,
                      'rule_id': row.rule_id,
                      'account': row.account,
                      'state': row.state})
    return locks


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
    Get the active replica locks for a rule_id

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
def get_files_and_replica_locks_of_dataset(scope, name, nowait=False, restrict_rses=None, session=None):
    """
    Get all the files of a dataset and, if existing, all locks of the file.

    :param scope:          Scope of the dataset
    :param name:           Name of the datset
    :param nowait:         Nowait parameter for the FOR UPDATE statement
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session.
    :return:               Dictionary with keys: (scope, name)
                           and as value: {'bytes':, 'locks: [{'rse_id':, 'state':}]}
    :raises:               NoResultFound
    """
    # with_hint(models.ReplicaLock, "INDEX(LOCKS LOCKS_PK)", 'oracle').\
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

    query = query.with_for_update(nowait=nowait)

    locks = {}

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
def successful_transfer(scope, name, rse_id, nowait, session=None):
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
        logging.debug('Marking lock %s:%s for rule %s on rse %s as OK' % (lock.scope, lock.name, str(lock.rule_id), str(lock.rse_id)))
        lock.state = LockState.OK

        # Update the rule counters
        rule = session.query(models.ReplicationRule).with_for_update(nowait=nowait).filter_by(id=lock.rule_id).one()
        logging.debug('Updating rule counters for rule %s [%d/%d/%d]' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))
        rule.locks_replicating_cnt -= 1
        rule.locks_ok_cnt += 1
        logging.debug('Finished updating rule counters for rule %s [%d/%d/%d]' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

        # Update the rule state
        if (rule.state == RuleState.SUSPENDED):
            continue
        elif (rule.error is not None):
            continue
        elif (rule.locks_stuck_cnt > 0):
            continue
        elif (rule.locks_replicating_cnt == 0):
            rule.state = RuleState.OK
            # Try to update the DatasetLocks
            if rule.grouping != RuleGrouping.NONE:
                session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.OK})
                session.flush()
                rucio.core.rule.generate_message_for_dataset_ok_callback(rule=rule, session=session)


@transactional_session
def failed_transfer(scope, name, rse_id, session=None):
    """
    Update the state of all replica locks because of a failed transfer

    :param scope:    Scope of the did.
    :param name:     Name of the did.
    :param rse_id:   RSE id.
    :param session:  The database session in use.
    """

    locks = session.query(models.ReplicaLock).with_for_update(nowait=True).filter_by(scope=scope, name=name, rse_id=rse_id)
    for lock in locks:
        if lock.state == LockState.STUCK:
            continue
        logging.debug('Marking lock %s:%s for rule %s on rse %s as STUCK' % (lock.scope, lock.name, str(lock.rule_id), str(lock.rse_id)))
        lock.state = LockState.STUCK

        # Update the rule counters
        rule = session.query(models.ReplicationRule).with_for_update(nowait=True).filter_by(id=lock.rule_id).one()
        logging.debug('Updating rule counters for rule %s [%d/%d/%d]' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))
        rule.locks_replicating_cnt -= 1
        rule.locks_stuck_cnt += 1
        logging.debug('Finished updating rule counters for rule %s [%d/%d/%d]' % (str(rule.id), rule.locks_ok_cnt, rule.locks_replicating_cnt, rule.locks_stuck_cnt))

        # Update the rule state
        if rule.state == RuleState.SUSPENDED:
            continue
        elif rule.error is not None:
            continue
        elif rule.locks_stuck_cnt > 0:
            if rule.state != RuleState.STUCK:
                rule.state = RuleState.STUCK
                # Try to update the DatasetLocks
                if rule.grouping != RuleGrouping.NONE:
                    session.query(models.DatasetLock).filter_by(rule_id=rule.id).update({'state': LockState.STUCK})
