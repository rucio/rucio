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
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.sql.expression import false, insert

from rucio.core.common.utils import chunks
from rucio.core.db.sqla import filter_thread_work, models
from rucio.core.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sqlalchemy.orm import Session


@transactional_session
def add_quarantined_replicas(rse_id: str, replicas: list[dict[str, Any]], *, session: "Session") -> None:
    """
    Bulk add quarantined file replicas.

    :param rse_id:      The rse id.
    :param replicas: A list of dicts with the replica information.
    :param session:  The database session in use.
    """

    # Exclude files that have a registered replica.  This is a
    # safeguard against potential issues in the Auditor.
    file_clause = []
    for replica in replicas:
        if "scope" in replica and "name" in replica:
            file_clause.append(and_(models.RSEFileAssociation.scope == replica['scope'],
                                    models.RSEFileAssociation.name == replica['name'],
                                    models.RSEFileAssociation.rse_id == rse_id))
    if file_clause:
        stmt = select(
            models.RSEFileAssociation.scope,
            models.RSEFileAssociation.name,
            models.RSEFileAssociation.rse_id
        ).with_hint(
            models.RSEFileAssociation,
            'INDEX(REPLICAS REPLICAS_PK)',
            'oracle'
        ).where(
            or_(*file_clause)
        )
        existing_replicas = [(scope, name, rseid) for scope, name, rseid in session.execute(stmt).all()]
        replicas = [replica for replica in replicas if (replica.get('scope', None), replica.get('name', None), rse_id) not in existing_replicas]

    # Exclude files that have already been added to the quarantined
    # replica table.
    quarantine_clause = []
    for replica in replicas:
        quarantine_clause.append(and_(models.QuarantinedReplica.path == replica['path'],
                                      models.QuarantinedReplica.rse_id == rse_id))
    stmt = select(
        models.QuarantinedReplica.path,
        models.QuarantinedReplica.rse_id
    ).where(
        or_(*quarantine_clause)
    )
    quarantine_replicas = [(path, rseid) for path, rseid in session.execute(stmt).all()]
    replicas = [replica for replica in replicas if (replica['path'], rse_id) not in quarantine_replicas]

    values = [{'rse_id': rse_id,
               'path': replica['path'],
               'scope': replica.get('scope'),
               'name': replica.get('name'),
               'bytes': replica.get('bytes')}
              for replica in replicas]
    stmt = insert(
        models.QuarantinedReplica
    )
    session.execute(stmt, values)


@transactional_session
def delete_quarantined_replicas(rse_id: str, replicas: "Iterable[dict[str, Any]]", *, session: "Session") -> None:
    """
    Delete file replicas.

    :param rse_id: the rse id.
    :param replicas: An iterable of dicts with the replica information.
    :param session: The database session in use.
    """

    conditions = []
    for replica in replicas:
        conditions.append(models.QuarantinedReplica.path == replica['path'])

    if conditions:
        stmt = delete(
            models.QuarantinedReplica
        ).where(
            and_(models.QuarantinedReplica.rse_id == rse_id,
                 or_(*conditions))
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

    if replicas:
        values = [{'rse_id': rse_id, 'path': replica['path'],
                   'bytes': replica.get('bytes'),
                   'created_at': replica.get('created_at'),
                   'deleted_at': datetime.datetime.utcnow()}
                  for replica in replicas]
        stmt = insert(
            models.QuarantinedReplicaHistory
        )
        session.execute(stmt, values)


@read_session
def list_quarantined_replicas(rse_id: str, limit: int, worker_number: Optional[int] = None, total_workers: Optional[int] = None, *, session: "Session") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
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
    stmt = select(
        models.QuarantinedReplica.path,
        models.QuarantinedReplica.bytes,
        models.QuarantinedReplica.scope,
        models.QuarantinedReplica.name,
        models.QuarantinedReplica.created_at
    ).where(
        models.QuarantinedReplica.rse_id == rse_id
    )
    stmt = filter_thread_work(session=session, query=stmt, total_threads=total_workers, thread_id=worker_number, hash_variable='path')
    stmt = stmt.limit(
        limit
    )
    for path, bytes_, scope, name, created_at in session.execute(stmt).all():
        if not (scope, name) in quarantined_replicas:
            quarantined_replicas[(scope, name)] = []
            replicas_clause.append(and_(models.RSEFileAssociation.scope == scope,
                                        models.RSEFileAssociation.name == name))
        quarantined_replicas[(scope, name)].append((path, bytes_, created_at))

    stmt = select(
        models.RSEFileAssociation.scope,
        models.RSEFileAssociation.name
    ).where(
        models.RSEFileAssociation.rse_id == rse_id
    )
    for chunk in chunks(replicas_clause, 20):
        curr_stmt = stmt.where(
            or_(*chunk)
        )

        for scope, name in session.execute(curr_stmt).all():
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
def list_rses_with_quarantined_replicas(filters: Optional[dict[str, Any]] = None, *, session: "Session") -> list[str]:
    """
    List RSEs in the Quarantined Queues.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.

    :returns: a list of RSEs.
    """
    stmt = select(
        models.RSE.id
    ).distinct(
    ).where(
        and_(models.QuarantinedReplica.rse_id == models.RSE.id,
             models.RSE.deleted == false())
    )

    if filters and filters.get('vo'):
        stmt = stmt.where(
            models.RSE.vo == filters.get('vo')
        )

    return [str(rseid) for rseid in session.execute(stmt).scalars().all()]
