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

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, delete, exists, insert, or_, select, true, update
from sqlalchemy.exc import NoResultFound

from rucio.common import exception
from rucio.core.rse import get_rse_name
from rucio.db.sqla import models
from rucio.db.sqla.constants import ReplicaState
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sqlalchemy.orm import Session


@transactional_session
def add_volatile_replicas(rse_id: str, replicas: "Iterable[dict[str, Any]]", *, session: "Session") -> None:
    """
    Bulk add volatile replicas.

    :param rse_id: the rse id.
    :param replicas: the iterable of volatile replicas.
    :param session: The database session in use.
    """
    # first check that the rse is a volatile one
    try:
        stmt = select(
            models.RSE
        ).where(
            and_(models.RSE.id == rse_id,
                 models.RSE.volatile == true())
        )
        session.execute(stmt).one()
    except NoResultFound:
        raise exception.UnsupportedOperation('No volatile rse found for %s !'
                                             % get_rse_name(rse_id=rse_id, session=session))

    file_clause, replica_clause = [], []
    for replica in replicas:
        file_clause.append(and_(models.DataIdentifier.scope == replica['scope'],
                                models.DataIdentifier.name == replica['name'],
                                ~exists(select(1).prefix_with('/*+ INDEX(REPLICAS REPLICAS_PK) */', dialect='oracle'))
                                .where(and_(models.RSEFileAssociation.scope == replica['scope'],
                                            models.RSEFileAssociation.name == replica['name'],
                                            models.RSEFileAssociation.rse_id == rse_id))))
        replica_clause.append(and_(models.RSEFileAssociation.scope == replica['scope'],
                                   models.RSEFileAssociation.name == replica['name'],
                                   models.RSEFileAssociation.rse_id == rse_id))
    if replica_clause:
        now = datetime.utcnow()
        stmt = update(
            models.RSEFileAssociation
        ).prefix_with(
            '/*+ INDEX(REPLICAS REPLICAS_PK) */',
            dialect='oracle'
        ).where(
            or_(*replica_clause)
        ).execution_options(
            synchronize_session=False
        ).values({
            models.RSEFileAssociation.updated_at: now,
            models.RSEFileAssociation.tombstone: now
        })
        session.execute(stmt)

    if file_clause:
        stmt = select(
            models.DataIdentifier.scope,
            models.DataIdentifier.name,
            models.DataIdentifier.bytes,
            models.DataIdentifier.md5,
            models.DataIdentifier.adler32
        ).filter(
            or_(*file_clause)
        )

        new_replicas = [
            {
                'rse_id': rse_id,
                'adler32': adler32,
                'state': ReplicaState.AVAILABLE,
                'scope': scope,
                'name': name,
                'lock_cnt': 0,
                'tombstone': datetime.utcnow(),
                'bytes': bytes_,
                'md5': md5
            }
            for scope, name, bytes_, md5, adler32 in session.execute(stmt).all()
        ]
        if new_replicas:
            stmt = insert(
                models.RSEFileAssociation
            )
            session.execute(stmt, new_replicas)


@transactional_session
def delete_volatile_replicas(rse_id: str, replicas: "Iterable[dict[str, Any]]", *, session: "Session") -> None:
    """
    Bulk delete volatile replicas.

    :param rse_id: the rse id.
    :param replicas: the iterable of volatile replicas.
    :param session: The database session in use.
    """
    # first check that the rse is a volatile one
    try:
        stmt = select(
            models.RSE
        ).where(
            and_(models.RSE.id == rse_id,
                 models.RSE.volatile == true())
        )
        session.execute(stmt).one()
    except NoResultFound:
        raise exception.UnsupportedOperation('No volatile rse found for %s !'
                                             % get_rse_name(rse_id=rse_id, session=session))

    conditions = []
    for replica in replicas:
        conditions.append(and_(models.RSEFileAssociation.scope == replica['scope'],
                               models.RSEFileAssociation.name == replica['name']))

    if conditions:
        stmt = delete(
            models.RSEFileAssociation
        ).where(
            and_(models.RSEFileAssociation.rse_id == rse_id,
                 or_(*conditions))
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)
