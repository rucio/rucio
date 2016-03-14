"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
"""

import datetime

from sqlalchemy import or_
from sqlalchemy.sql.expression import bindparam, text

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
    for files in chunks(replicas, 1000):
        session.bulk_insert_mappings(
            models.QuarantinedReplica,
            [{'rse_id': rse_id, 'path': file['path'],
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
                          models.QuarantinedReplica.created_at).\
        filter(models.QuarantinedReplica.rse_id == rse_id).\
        limit(limit)

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
             'bytes': bytes}
            for path, bytes, created_at in query]
