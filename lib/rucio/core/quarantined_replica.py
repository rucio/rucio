#!/usr/bin/env python
# Copyright 2016-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2016-2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019-2020
#
# PY3K COMPATIBLE

import datetime

from sqlalchemy import and_, or_, exists, not_
from sqlalchemy.sql.expression import select, false

from rucio.common.utils import chunks
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.session import read_session, transactional_session


@transactional_session
def add_quarantined_replicas(rse_id, replicas, session=None):
    """
    Bulk add quarantined file replicas.

    :param rse_id:      The rse id.
    :param replicas: A list of dicts with the replica information.
    :param session:  The database session in use.
    """

    for chunk in chunks(replicas, 100):
        # Exlude files that have a registered replica.  This is a
        # safeguard against potential issues in the Auditor.
        file_clause = []
        for replica in chunk:
            file_clause.append(and_(models.RSEFileAssociation.scope == replica.get('scope', None),
                                    models.RSEFileAssociation.name == replica.get('name', None),
                                    models.RSEFileAssociation.rse_id == rse_id))
        file_query = session.query(models.RSEFileAssociation.scope,
                                   models.RSEFileAssociation.name,
                                   models.RSEFileAssociation.rse_id).\
            with_hint(models.RSEFileAssociation, "index(REPLICAS REPLICAS_PK)", 'oracle').\
            filter(or_(*file_clause))
        existing_replicas = [(scope, name, rseid) for scope, name, rseid in file_query]
        chunk = [replica for replica in chunk if (replica.get('scope', None), replica.get('name', None), rse_id) not in existing_replicas]

        # Exclude files that have already been added to the quarantined
        # replica table.
        quarantine_clause = []
        for replica in chunk:
            quarantine_clause.append(and_(models.QuarantinedReplica.path == replica['path'],
                                          models.QuarantinedReplica.rse_id == rse_id))
        quarantine_query = session.query(models.QuarantinedReplica.path,
                                         models.QuarantinedReplica.rse_id).\
            filter(or_(*quarantine_clause))
        quarantine_replicas = [(path, rseid) for path, rseid in quarantine_query]
        chunk = [replica for replica in chunk if (replica['path'], rse_id) not in quarantine_replicas]

        session.bulk_insert_mappings(
            models.QuarantinedReplica,
            [{'rse_id': rse_id, 'path': file['path'],
              'scope': file.get('scope'), 'name': file.get('name'),
              'bytes': file.get('bytes')} for file in chunk])


@transactional_session
def delete_quarantined_replicas(rse_id, replicas, session=None):
    """
    Delete file replicas.

    :param rse_id: the rse id.
    :param files: the list of files to delete.
    :param ignore_availability: Ignore the RSE blacklisting.
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
        bulk_insert_mappings(models.QuarantinedReplica.__history_mapper__.class_,
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

    :returns: a list of dictionary replica.
    """

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
    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='path')
    return [{'path': path,
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
    query = session.query(models.RSE.id).distinct(models.RSE.id).\
        filter(models.QuarantinedReplica.rse_id == models.RSE.id).\
        filter(models.RSE.deleted == false())
    return [rse for (rse,) in query]
