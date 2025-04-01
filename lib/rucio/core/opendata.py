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

from typing import TYPE_CHECKING, Any, Literal, Optional, Union

from sqlalchemy import and_, delete, exists, insert, or_, update
from sqlalchemy.exc import DatabaseError, IntegrityError, NoResultFound
from sqlalchemy.sql.expression import bindparam, case, false, null, select, true

from rucio.common import exception
from rucio.core.monitor import MetricManager
from rucio.db.sqla import filter_thread_work, models
from rucio.db.sqla.session import read_session, stream_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount, InternalScope, LoggerFunction

METRICS = MetricManager(module=__name__)


@read_session
def list_opendata_dids(
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        *,
        session: "Session"
) -> list[dict[str, Any]]:
    list_stmt = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
        models.OpenDataDid.created_at,
        models.OpenDataDid.updated_at,
    ).order_by(
        models.DataIdentifier.updated_at
    )

    if limit:
        list_stmt = list_stmt.limit(limit)

    if offset:
        list_stmt = list_stmt.offset(offset)

    return [{'scope': scope, 'name': name, 'state': state, 'created_at': created_at, 'updated_at': updated_at} for
            scope, name, state, created_at, updated_at in session.execute(list_stmt)]


@read_session
def get_opendata_did(
        scope: "InternalScope",
        name: str,
        *,
        session: "Session"
) -> Optional[dict[str, Any]]:
    get_stmt = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
        models.OpenDataDid.metadata_json,
        models.OpenDataDid.created_at,
        models.OpenDataDid.updated_at,
    ).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name,
        )
    )

    try:
        return dict(session.execute(get_stmt).fetchone())
    except NoResultFound:
        return None

@transactional_session
def add_opendata_did(
        scope: "InternalScope",
        name: str,
        *,
        session: "Session",
) -> None:
    return add_opendata_dids([{'scope': scope, 'name': name}], session=session)


@transactional_session
def add_opendata_dids(
        dids: "Sequence[dict[str, str]]",
        *,
        session: "Session",
) -> None:
    for did in dids:
        if 'scope' not in did or 'name' not in did:
            raise exception.InputValidationError("DID must have 'scope' and 'name' keys.")

    # Build query to insert into opendata table
    insert_stmt = insert(models.OpenDataDid).values(dids)

    # Execute query
    session.execute(insert_stmt)

@transactional_session
def delete_opendata_did(
        scope: "InternalScope",
        name: str,
        *,
        session: "Session",
) -> None:
    return delete_opendata_dids([{'scope': scope, 'name': name}], session=session)


@transactional_session
def delete_opendata_dids(
        dids: "Sequence[dict[str, str]]",
        *,
        session: "Session",
) -> None:
    for did in dids:
        if 'scope' not in did or 'name' not in did:
            raise exception.InputValidationError("DID must have 'scope' and 'name' keys.")

    delete_stmt = delete(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == bindparam('scope'),
            models.OpenDataDid.name == bindparam('name')
        )
    )

    # Execute query
    session.execute(delete_stmt, dids)
