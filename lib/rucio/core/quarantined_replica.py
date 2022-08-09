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

import datetime

from sqlalchemy import and_, or_
from sqlalchemy.sql.expression import false

from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.session import read_session, transactional_session
from rucio.common.utils import chunks


@transactional_session
def add_quarantined_replicas(rse_id, replicas, session=None):
    """
    Bulk add quarantined file replicas.

    :param rse_id:      The rse id.
    :param replicas: A list of dicts with the replica information.
    :param session:  The database session in use.
    """

    # Exlude files that have a registered replica.  This is a
    # safeguard against potential issues in the Auditor.
    file_clause = []
    for replica in replicas:
        if "scope" in replica and "name" in replica:
            file_clause.append(and_(models.RSEFileAssociation.scope == replica['scope'],
                                    models.RSEFileAssociation.name == replica['name'],
                                    models.RSEFileAssociation.rse_id == rse_id))
    if file_clause:
        file_query = session.query(models.RSEFileAssociation.scope,
                                   models.RSEFileAssociation.name,
                                   models.RSEFileAssociation.rse_id).\
            with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').\
            filter(or_(*file_clause))
        existing_replicas = [(scope, name, rseid) for scope, name, rseid in file_query]
        replicas = [replica for replica in replicas if (replica.get('scope', None), replica.get('name', None), rse_id) not in existing_replicas]

    # Exclude files that have already been added to the quarantined
    # replica table.
    quarantine_clause = []
    for replica in replicas:
        quarantine_clause.append(and_(models.QuarantinedReplica.path == replica['path'],
                                      models.QuarantinedReplica.rse_id == rse_id))
    quarantine_query = session.query(models.QuarantinedReplica.path,
                                     models.QuarantinedReplica.rse_id).\
        filter(or_(*quarantine_clause))
    quarantine_replicas = [(path, rseid) for path, rseid in quarantine_query]
    replicas = [replica for replica in replicas if (replica['path'], rse_id) not in quarantine_replicas]

    session.bulk_insert_mappings(
        models.QuarantinedReplica,
        [{'rse_id': rse_id,
          'path': file['path'],
          'scope': file.get('scope'),
          'name': file.get('name'),
          'bytes': file.get('bytes')}
         for file in replicas])


@transactional_session
def delete_quarantined_replicas(rse_id, replicas, session=None):
    """
    Delete file replicas.

    :param rse_id: the rse id.
    :param replicas: A list of dicts with the replica information.
    :param session: The database session in use.
    """

    conditions = []
    for replica in replicas:
        conditions.append(models.QuarantinedReplica.path == replica['path'])

    if conditions:
        session.query(models.QuarantinedReplica).\
            filter(models.QuarantinedReplica.rse_id == rse_id).\
            filter(or_(*conditions)).\
            delete(synchronize_session=False)

    session.\
        bulk_insert_mappings(models.QuarantinedReplicaHistory,
                             [{'rse_id': rse_id, 'path': replica['path'],
                               'bytes': replica.get('bytes'),
                               'created_at': replica.get('created_at'),
                               'deleted_at': datetime.datetime.utcnow()}
                              for replica in replicas])


@read_session
def list_quarantined_replicas(rse_id, limit, worker_number=None, total_workers=None, session=None):
    """
    List RSE Quarantined File replicas.

    :param rse_id: the rse id.
    :param limit: The maximum number of replicas returned.
    :param worker_number:      id of the executing worker.
    :param total_workers:      Number of total workers.
    :param session: The database session in use.

    :returns: two lists :
              - The first one contains quarantine replicas actually registered in the replicas tables
              - The second one contains real "dark" files
    """

    replicas_clause = []
    quarantined_replicas = {}
    real_replicas = []
    dark_replicas = []
    query = session.query(models.QuarantinedReplica.path,
                          models.QuarantinedReplica.bytes,
                          models.QuarantinedReplica.scope,
                          models.QuarantinedReplica.name,
                          models.QuarantinedReplica.created_at).\
        filter(models.QuarantinedReplica.rse_id == rse_id)
    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='path')

    for path, bytes_, scope, name, created_at in query.limit(limit):
        if not (scope, name) in quarantined_replicas:
            quarantined_replicas[(scope, name)] = []
            replicas_clause.append(and_(models.RSEFileAssociation.scope == scope,
                                        models.RSEFileAssociation.name == name))
        quarantined_replicas[(scope, name)].append((path, bytes_, created_at))

    for chunk in chunks(replicas_clause, 20):
        query = session.query(models.RSEFileAssociation.scope,
                              models.RSEFileAssociation.name).\
            filter(models.RSEFileAssociation.rse_id == rse_id).\
            filter(or_(*chunk))

        for scope, name in query.all():
            reps = quarantined_replicas.pop((scope, name))
            real_replicas.extend([{'scope': scope,
                                   'name': name,
                                   'rse_id': rse_id,
                                   'path': rep[0],
                                   'bytes': rep[1],
                                   'created_at': rep[2]}
                                  for rep in reps])

    for key, value in quarantined_replicas.items():
        dark_replicas.extend([{'scope': key[0],
                               'name': key[1],
                               'rse_id': rse_id,
                               'path': rep[0],
                               'bytes': rep[1],
                               'created_at': rep[2]}
                              for rep in value])

    return real_replicas, dark_replicas


@read_session
def list_rses_with_quarantined_replicas(filters=None, session=None):
    """
    List RSEs in the Quarantined Queues.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.

    :returns: a list of RSEs.
    """
    query = session.query(models.RSE.id).distinct(models.RSE.id).\
        filter(models.QuarantinedReplica.rse_id == models.RSE.id).\
        filter(models.RSE.deleted == false())

    if filters and filters.get('vo'):
        query = query.filter(getattr(models.RSE, 'vo') == filters.get('vo'))

    return [rse for (rse,) in query]
