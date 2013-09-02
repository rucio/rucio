# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from sqlalchemy.sql.expression import and_, or_

from rucio.db import models
from rucio.db.constants import LockState, RuleState
from rucio.db.session import read_session, transactional_session


@read_session
def get_replica_locks(scope, name, lockmode, restrict_rses=None, session=None):
    """
    Get the active replica locks for a file

    :param scope:          Scope of the did.
    :param name:           Name of the did.
    :param lockmode:       The lockmode to be used by the session.
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session.
    :return:               List of dicts {'rse': ..., 'state': ...}
    :raises:               NoResultFound
    """

    rses = []

    query = session.query(models.ReplicaLock).filter_by(scope=scope, name=name)
    if restrict_rses is not None:
        rse_clause = []
        for rse_id in restrict_rses:
            rse_clause.append(models.ReplicaLock.rse_id == rse_id)
        if rse_clause:
            query = query.filter(or_(*rse_clause))
    if lockmode is not None:
        query = query.with_lockmode(lockmode)
    for row in query:
        rses.append({'rse_id': row.rse_id, 'state': row.state, 'rule_id': row.rule_id})

    return rses


@read_session
def get_replica_locks_for_rule(rule_id, lockmode, session=None):
    """
    Get the active replica locks for a file

    :param rule_id:        Filter on rule_id.
    :param lockmode:       The lockmode to be used by the session.
    :param session:        The db session.
    :return:               List of dicts {'scope':, 'name':, 'rse': ..., 'state': ...}
    :raises:               NoResultFound
    """

    locks = []

    query = session.query(models.ReplicaLock).filter_by(rule_id=rule_id)
    if lockmode is not None:
        query = query.with_lockmode(lockmode)
    for row in query:
        locks.append({'scope': row.scope, 'name': row.name, 'rse_id': row.rse_id, 'state': row.state, 'rule_id': row.rule_id})

    return locks


@read_session
def get_files_and_replica_locks_of_dataset(scope, name, lockmode, restrict_rses=None, session=None):
    """
    Get all the files of a dataset and, if existing, all locks of the file.

    :param scope:          Scope of the dataset
    :param name:           Name of the datset
    :param lockmode:       The lockmode to be used by the session.
    :param restrict_rses:  Possible RSE_ids to filter on.
    :param session:        The db session.
    :return:               Dictionary with keys: (scope, name)
                           and as value: {'bytes':, 'locks: [{'rse_id':, 'state':}]}
    :raises:               NoResultFound
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
    if restrict_rses is not None:
        rse_clause = []
        for rse_id in restrict_rses:
            rse_clause.append(models.ReplicaLock.rse_id == rse_id)
        if rse_clause:
            session.query(models.DataIdentifierAssociation.child_scope,
                          models.DataIdentifierAssociation.child_name,
                          models.DataIdentifierAssociation.bytes,
                          models.ReplicaLock.rse_id,
                          models.ReplicaLock.state,
                          models.ReplicaLock.rule_id).outerjoin(models.ReplicaLock, and_(
                              models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                              models.DataIdentifierAssociation.child_name == models.ReplicaLock.name,
                              or_(*rse_clause))).filter(
                                  models.DataIdentifierAssociation.scope == scope,
                                  models.DataIdentifierAssociation.name == name)
    if lockmode is not None:
        query = query.with_lockmode(lockmode)
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

    locks = session.query(models.ReplicaLock).with_lockmode('update_nowait').filter_by(scope=scope, name=name, rse_id=rse_id)
    for lock in locks:
        lock.state = LockState.OK

        # Update the rule counters
        rule = session.query(models.ReplicationRule).with_lockmode('update_nowait').filter_by(id=lock.rule_id).one()
        rule.locks_replicating_cnt -= 1
        rule.locks_ok_cnt += 1

        # Update the rule state
        if (rule.state == RuleState.SUSPENDED):
            continue
        elif (rule.error is not None):
            rule.state = RuleState.STUCK
        elif (rule.locks_stuck_cnt > 0):
            rule.state = RuleState.STUCK
        elif (rule.locks_replicating_cnt == 0):
            rule.state = RuleState.OK


@transactional_session
def failed_transfer(scope, name, rse_id, session=None):
    """
    Update the state of all replica locks because of a failed transfer

    :param scope:    Scope of the did
    :param name:     Name of the did
    :param rse_id:   RSE id
    """

    locks = session.query(models.ReplicaLock).with_lockmode('update_nowait').filter_by(scope=scope, name=name, rse_id=rse_id)
    for lock in locks:
        lock.state = LockState.STUCK

        # Update the rule counters
        rule = session.query(models.ReplicationRule).with_lockmode('update_nowait').filter_by(id=lock.rule_id).one()
        rule.locks_replicating_cnt -= 1
        rule.locks_stuck_cnt += 1

        # Update the rule state
        if (rule.state == RuleState.SUSPENDED):
            continue
        elif (rule.error is not None):
            rule.state = RuleState.STUCK
        elif (rule.locks_stuck_cnt > 0):
            rule.state = RuleState.STUCK
