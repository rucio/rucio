# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from random import choice
from sqlalchemy.exc import IntegrityError

from rucio.common.exception import RucioException
from rucio.common.utils import generate_uuid
from rucio.core import identifier, rse
from rucio.db import models
from rucio.db.session import get_session


session = get_session()


def add_replication_rule(dids, account, copies, rse_expression, parameters):
    """
    Adds a replication rule.
    :param dids:            The data identifier set.
    :param copies:          The number of replicas.
    :param rse_expression:  Boolean expression to give the list of RSEs.
    :param weight:          If the weighting option of the replication rule is used, the choice of RSEs takes their weight into account.
    :param lifetime:        The lifetime of the replication rules.
    :param grouping:        all -  All files will be replicated to the same RSE.
                            dataset - All files in the same dataset will be replicated to the same RSE;
                            none - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
    :param account:         The account.
    """

    # Resolve the rse_expression in a list of RSE
    filters = {}
    for exp in rse_expression.split('and'):
        k, v = exp.split('=')
        filters[k] = v
    rses = rse.list_rses(filters=filters)

    rule_id = generate_uuid()
    for did in dids:
        # Insert the replication rule
        new_rule = models.ReplicationRule(id=rule_id, account=account, name=did['name'], scope=did['scope'], copies=copies, rse_expression=rse_expression)
        try:
            new_rule.save(session=session)
        except IntegrityError, e:
            print e
            session.rollback()
            raise RucioException(e.args[0])

        # Insert the locks
        # Apply the weight ? disk space ? quotas ? grouping (dataset for now) ?
        did_locks = list()
        rses_tmp = list(rses)
        for i in xrange(copies):
            selected_rse = choice(rses_tmp)
            rses_tmp.remove(selected_rse)
            did_lock = {'id': rule_id, 'scope': did['scope'], 'name': did['name'], 'rse': selected_rse, 'account': account}
            did_locks.append(did_lock)
        add_replica_locks(locks=did_locks)

    session.commit()
    return rule_id


def list_replication_rules(filters={}):
    """
    List replication rules.

    :param filters: dictionary of attributes by which the results should be filtered.
    """

    query = session.query(models.ReplicationRule)
    if filters:
        for (k, v) in filters.items():
            query = query.filter(getattr(models.ReplicationRule, k) == v)

    for row in query:
        d = {}
        for column in row.__table__.columns:
            d[column.name] = getattr(row, column.name)
        yield d


def add_replica_locks(locks):
    """
    Add replica locks and replicas.

    :param locks: List of dictionary replica locks.
    """

    for lock in locks:
        rse = session.query(models.RSE).filter_by(rse=lock['rse']).one()
        # add the replica locks for datasets and containers
        new_lock = models.ReplicaLock(rule_id=lock['id'], rse_id=rse.id, scope=lock['scope'], name=lock['name'], account=lock['account'])
        new_lock.save(session=session)

        # Get did content
        files = identifier.list_files(scope=lock['scope'], name=lock['name'])
        # Generate the replica locks for file, and eventually the transfer request
        for file in files:
            new_lock = models.ReplicaLock(rule_id=lock['id'], rse_id=rse.id, scope=file['scope'], name=file['name'], account=lock['account'])
            # If replica doesn't exist, add a replica with the state UNAVAILABLE
            # which will be picked up by the conveyor daemon
            # Optionally extended with a submission to gearman in the future
            new_replica = models.RSEFileAssociation(rse_id=rse.id, scope=file['scope'], name=file['name'])
            new_replica = session.merge(new_replica)
            new_lock.save(session=session)
            new_replica.save(session=session)

        # Update the replication rule status
        del(lock['rse'])
        session.query(models.ReplicationRule).filter_by(**lock).update({'state': 'ready'})
