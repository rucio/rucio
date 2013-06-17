# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import and_

from rucio.db import models
from rucio.db.constants import LockState
from rucio.db.session import read_session, transactional_session


@read_session
def get_replica_locks(scope, name, db_lock=True, session=None):
    """
    Get the active replica locks for a file

    :param scope:    Scope of the did.
    :param name:     Name of the did.
    :param db_lock:  If the database should lock the read rows.
    :param session:  The db session.
    :return:         List of dicts {'rse': ..., 'state': ...}
    :raises:         NoResultFound
    """

    rses = []
    try:
        query = session.query(models.ReplicaLock).filter_by(scope=scope, name=name)
        if db_lock:
            query = query.with_lockmode("update")
        for row in query:
            rses.append({'rse_id': row.rse_id, 'state': row.state, 'rule_id': row.rule_id})
    except NoResultFound:  # TODO: Actually raise the exception?
        rses = []
    return rses


@read_session
def get_replica_locks_for_rule(rule_id, db_lock=True, session=None):
    """
    Get the active replica locks for a file

    :param rule_id:  Filter on rule_id.
    :param db_lock:  If the database should lock the read rows.
    :param session:  The db session.
    :return:         List of dicts {'scope':, 'name':, 'rse': ..., 'state': ...}
    :raises:         NoResultFound
    """

    locks = []
    try:
        query = session.query(models.ReplicaLock).filter_by(rule_id=rule_id)
        if db_lock:
            query = query.with_lockmode("update")
        for row in query:
            locks.append({'scope': row.scope, 'name': row.name, 'rse_id': row.rse_id, 'state': row.state, 'rule_id': row.rule_id})
    except NoResultFound:  # TODO: Actually raise the exception?
        locks = []
    return locks


@read_session
def get_files_and_replica_locks_of_dataset(scope, name, db_lock=True, session=None):
    """
    Get all the files of a dataset and, if existing, all locks of the file.

    :param scope:    Scope of the dataset
    :param name:     Name of the datset
    :param db_lock:  If the database should lock the read rows.
    :param session:  The db session.
    :return:         Dictionary with keys: (scope, name)
                     and as value: {'bytes':, 'locks: [{'rse_id':, 'state':}]}
    :raises:         NoResultFound
    """
    files = {}
    query = session.query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.bytes,
                          models.ReplicaLock.rse_id,
                          models.ReplicaLock.state,
                          models.ReplicaLock.rule_id).outerjoin(models.ReplicaLock, and_(
                              models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                              models.DataIdentifierAssociation.child_name == models.ReplicaLock.name)).filter(
                                  models.DataIdentifierAssociation.scope == scope,
                                  models.DataIdentifierAssociation.name == name)
    if db_lock:
        query = query.with_lockmode('update')
    for child_scope, child_name, bytes, rse_id, state, rule_id in query:
        if rse_id is None:
            files[(child_scope, child_name)] = {'scope': child_scope, 'name': child_name, 'bytes': bytes, 'locks': []}
        else:
            if (child_scope, child_name) in files:
                files[(child_scope, child_name)]['locks'].append({'rse_id': rse_id, 'state': state, 'rule_id': rule_id})
            else:
                files[(child_scope, child_name)] = {'scope': child_scope, 'name': child_name, 'bytes': bytes, 'locks': [{'rse_id': rse_id, 'state': state, 'rule_id': rule_id}]}
    return files


@transactional_session
def successful_transfer(scope, name, rse_id, session=None):
    """
    Update the state of all replica locks because of an successful transfer

    :param scope:    Scope of the did
    :param name:     Name of the did
    :param rse_id:   RSE id
    """

    locks = session.query(models.ReplicaLock).with_lockmode('update').filter_by(scope=scope, name=name, rse_id=rse_id)
    for lock in locks:
        lock.state = LockState.OK
        # Check if the rule_id of the lock has any REPLICATING locks LEFT
        # TODO This query does not work with the new schema, as rule_id is not INDEXED on the locks table
        if session.query(models.ReplicaLock).filter(models.ReplicaLock.rule_id == lock.rule_id,
                                                    models.ReplicaLock.state != LockState.OK).count() == 0:
            session.query(models.ReplicationRule).filter_by(id=lock.rule_id).one().state = LockState.OK


@transactional_session
def failed_transfer(scope, name, rse_id, session=None):
    """
    Update the state of all replica locks because of a failed transfer

    :param scope:    Scope of the did
    :param name:     Name of the did
    :param rse_id:   RSE id
    """

    locks = session.query(models.ReplicaLock).with_lockmode('update').filter_by(scope=scope, name=name, rse_id=rse_id)
    for lock in locks:
        lock.state = LockState.STUCK
        # Check if the rule_id of the lock has any REPLICATING locks LEFT
        # TODO This query does not work with the new schema, as rule_id is not INDEXED on the locks table
        if session.query(models.ReplicaLock).filter(models.ReplicaLock.rule_id == lock.rule_id,
                                                    models.ReplicaLock.state != LockState.OK).count() == 0:
            session.query(models.ReplicationRule).filter_by(id=lock.rule_id).one().state = LockState.STUCK
