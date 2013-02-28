# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common.exception import InvalidReplicaLock
from rucio.db import models
from rucio.db.session import read_session, transactional_session


@read_session
def get_replica_locks(scope, name, account=None, session=None):
    """
    Get the active replica locks for a file

    :param scope:    Scope of the did
    :param name:     Name of the did
    :param account:  If specified, only list replica locks of this account
    :return:         List of dicts {'rse': ..., 'state': ...}
    :raises:         NoResultFound
    """

    rses = []
    try:
        if account is not None:
            query = session.query(models.ReplicaLock).filter_by(scope=scope, name=name, account=account)
        else:
            query = session.query(models.ReplicaLock).filter_by(scope=scope, name=name)
            for row in query:
                rses.append({'rse_id': row.rse_id, 'state': row.state})
    except NoResultFound:
        rses = []
    return rses


@transactional_session
def add_replica_lock(rule_id, scope, name, rse_id, account, state='WAITING', session=None):
    """
    Add a replica lock

    :param rule_id:  The rule the lock is associated to
    :param scope:    Scope of the did
    :param name:     Name of the did
    :param rse_id:   RSE id
    :param account:  account owning the lock
    :param state:    State of the replication rule (WAITING/OK)
    :raises:         InvalidReplicaLock
    """

    new_lock = models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=scope, name=name, account=account, state=state)
    try:
        new_lock.save(session=session)
    except IntegrityError, e:
        raise InvalidReplicaLock(e.args[0])
