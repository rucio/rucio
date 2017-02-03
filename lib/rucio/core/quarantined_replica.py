"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2016-2017
"""

import datetime

from sqlalchemy import and_, or_, exists, not_
from sqlalchemy.sql.expression import bindparam, text, select, false

from rucio.common.utils import chunks
from rucio.core.rse import get_rse_id
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session


@transactional_session
def add_quarantined_replicas(rse, replicas, session=None):
    """
    Bulk add quarantined file replicas.

    :param rse:     The rse name.
    :param files:   The list of files.
    :param session: The database session in use.

    :returns: True is successful.
    """
    rse_id = get_rse_id(rse, session=session)

    file_clause = []
    for replica in replicas:
        file_clause.append(and_(models.RSEFileAssociation.scope == replica.get('scope', None),
                                models.RSEFileAssociation.name == replica.get('name', None),
                                models.RSEFileAssociation.rse_id == rse_id))

    if file_clause:
        file_query = session.query(models.RSEFileAssociation.scope,
                                   models.RSEFileAssociation.name,
                                   models.RSEFileAssociation.rse_id).\
            with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').\
            filter(or_(*file_clause))

        existing_replicas = [(scope, name, rseid) for scope, name, rseid in file_query]

        replicas = [replica for replica in replicas if (replica.get('scope', None), replica.get('name', None), rse_id) not in existing_replicas]

        for files in chunks(replicas, 1000):
            session.bulk_insert_mappings(
                models.QuarantinedReplica,
                [{'rse_id': rse_id, 'path': file['path'],
                  'scope': file.get('scope'), 'name': file.get('name'),
                  'bytes': file.get('bytes')} for file in files])


@transactional_session
def delete_quarantined_replicas(rse, replicas, session=None):
    """
    Delete file replicas.

    :param rse: the rse name.
    :param files: the list of files to delete.
    :param ignore_availability: Ignore the RSE blacklisting.
    :param session: The database session in use.
    """
    rse_id = get_rse_id(rse, session=session)

    conditions = []
    for replica in replicas:
        conditions.append(models.QuarantinedReplica.path == replica['path'])

    if conditions:
        session.query(models.QuarantinedReplica).\
            filter(models.QuarantinedReplica.rse_id == rse_id).\
            filter(or_(*conditions)).\
            delete(synchronize_session=False)

    session.\
        bulk_insert_mappings(models.QuarantinedReplica.__history_mapper__.class_,
                             [{'rse_id': rse_id, 'path': replica['path'],
                               'bytes': replica.get('bytes'),
                               'created_at': replica.get('created_at'),
                               'deleted_at': datetime.datetime.utcnow()}
                              for replica in replicas])


@read_session
def list_quarantined_replicas(rse, limit, worker_number=None, total_workers=None, session=None):
    """
    List RSE Quarantined File replicas.

    :param rse: the rse name.
    :param limit: The maximum number of replicas returned.
    :param worker_number:      id of the executing worker.
    :param total_workers:      Number of total workers.
    :param session: The database session in use.

    :returns: a list of dictionary replica.
    """
    rse_id = get_rse_id(rse, session=session)

    query = session.query(models.QuarantinedReplica.path,
                          models.QuarantinedReplica.bytes,
                          models.QuarantinedReplica.scope,
                          models.QuarantinedReplica.name,
                          models.QuarantinedReplica.created_at).\
        filter(models.QuarantinedReplica.rse_id == rse_id)

    # do no delete valid replicas
    stmt = exists(select([1]).prefix_with("/*+ index(REPLICAS REPLICAS_PK) */", dialect='oracle')).\
        where(and_(models.RSEFileAssociation.scope == models.QuarantinedReplica.scope,
                   models.RSEFileAssociation.name == models.QuarantinedReplica.name,
                   models.RSEFileAssociation.rse_id == models.QuarantinedReplica.rse_id))
    query = query.filter(not_(stmt))

    if worker_number and total_workers and total_workers - 1 > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('worker_number', worker_number - 1), bindparam('total_workers', total_workers - 1)]
            query = query.filter(text('ORA_HASH(path, :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(path), %s) = %s' % (total_workers - 1, worker_number - 1))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(path))::bit(32)::int), %s) = %s' % (total_workers - 1, worker_number - 1))

    return [{'path': path,
             'rse': rse,
             'rse_id': rse_id,
             'created_at': created_at,
             'scope': scope,
             'name': name,
             'bytes': bytes}
            for path, bytes, scope, name, created_at in query.limit(limit)]


@read_session
def list_rses(session=None):
    """
    List RSEs in the Quarantined Queues.

    :param session: The database session in use.

    :returns: a list of RSEs.
    """
    query = session.query(models.RSE.rse).distinct(models.RSE.rse).\
        filter(models.QuarantinedReplica.rse_id == models.RSE.id).\
        filter(models.RSE.deleted == false())
    return [rse for (rse,) in query]
