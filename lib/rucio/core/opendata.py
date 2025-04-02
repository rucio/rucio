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

import json
from re import match
from typing import TYPE_CHECKING, Any, Literal, Optional, Union

from sqlalchemy import and_, delete, exists, insert, or_, update
from sqlalchemy.exc import DatabaseError, IntegrityError, NoResultFound, DataError
from sqlalchemy.sql.expression import bindparam, case, false, null, select, true

from rucio.common import exception
from rucio.core.monitor import MetricManager
from rucio.db.sqla import filter_thread_work, models
from rucio.db.sqla.constants import OpenDataDIDState
from rucio.db.sqla.session import read_session, stream_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount, InternalScope, LoggerFunction

METRICS = MetricManager(module=__name__)


@read_session
def list_opendata_dids(
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        state: Optional[str] = None,  # TODO: typing only valid states
        session: "Session"
) -> list[dict[str, Any]]:
    list_stmt = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
        models.OpenDataDid.created_at,
        models.OpenDataDid.updated_at,
    ).order_by(
        models.OpenDataDid.updated_at
    )

    print(f"Called list_opendata_dids with limit={limit}, offset={offset}, state={state}")

    if limit:
        list_stmt = list_stmt.limit(limit)

    if offset:
        list_stmt = list_stmt.offset(offset)

    if state:
        list_stmt = list_stmt.where(models.OpenDataDid.state == state)

    print(f"Query: {list_stmt}")

    return [{"scope": scope, "name": name, "state": state, "created_at": created_at, "updated_at": updated_at} for
            scope, name, state, created_at, updated_at in session.execute(list_stmt)]


@read_session
def get_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[str] = None,  # TODO: typing only valid states
        session: "Session"
) -> Optional[dict[str, Any]]:
    print(f"Called GATEWAY get_opendata_did with scope={scope}, name={name}, state={state}")

    get_stmt = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
        models.OpenDataDid.opendata_json,
        models.OpenDataDid.created_at,
        models.OpenDataDid.updated_at,
    ).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name,
        )
    )

    if state:
        get_stmt = get_stmt.where(models.OpenDataDid.state == state)

    print(f"Query: {get_stmt}")

    result = session.execute(get_stmt).mappings().fetchone()
    if not result:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")

    return dict(result)


@transactional_session
def add_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> None:
    try:
        return add_opendata_dids([{"scope": scope, "name": name}], session=session)
    except exception.OpenDataDataIdentifierNotFound:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")
    except exception.OpenDataDataIdentifierAlreadyExists:
        raise exception.OpenDataDataIdentifierAlreadyExists(f"OpenData DID {scope}:{name} already exists.")


@transactional_session
def add_opendata_dids(
        dids: "Sequence[dict[str, str]]",
        *,
        session: "Session",
) -> None:
    for did in dids:
        if "scope" not in did or "name" not in did:
            raise exception.InputValidationError("DID must have 'scope' and 'name' keys.")

    insert_stmt = insert(models.OpenDataDid).values(dids)

    try:
        session.execute(insert_stmt)
    except IntegrityError as error:
        # Is there an easier way to switch on the specific IntegrityError?
        if match('.*IntegrityError.*ORA-00001: unique constraint.*DIDS_PK.*violated.*', error.args[0]) \
                or match('.*IntegrityError.*UNIQUE constraint failed: dids.scope, dids.name.*', error.args[0]) \
                or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', error.args[0]) \
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
                or match('.*IntegrityError.*columns? .*not unique.*', error.args[0]):
            raise exception.OpenDataDataIdentifierAlreadyExists()

        raise exception.OpenDataDataIdentifierNotFound()


@transactional_session
def delete_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> None:
    select_stmt = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
    ).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )

    result = session.execute(select_stmt).mappings().fetchone()
    if not result:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    # state needs to be draft to be deleted
    if result["state"] != OpenDataDIDState.DRAFT:
        raise exception.OpenDataInvalidState(
            f"OpenData entry '{scope}:{name}' not in a valid state for deletion. State: {result['state']}, expected: {OpenDataDIDState.DRAFT}")

    delete_stmt = delete(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == bindparam("scope"),
            models.OpenDataDid.name == bindparam("name")
        )
    )

    result = session.execute(delete_stmt, {"scope": scope, "name": name})

    if result.rowcount == 0:
        raise ValueError(f"Error deleting OpenData entry '{scope}:{name}'.")


@transactional_session
def update_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[str] = None,  # TODO: typing only valid states
        opendata_json: Optional[dict] = None,
        session: "Session",
) -> None:
    print(
        f"Called CORE update_opendata_did with scope={scope}, name={name}, state={state}, opendata_json={opendata_json}")
    if not state and not opendata_json:
        raise exception.InputValidationError("Either 'state' or 'opendata_json' must be provided.")

    # print type of json
    if opendata_json is not None and not isinstance(opendata_json, dict):
        raise exception.InputValidationError("opendata_json must be a dictionary.")

    exists_stmt = select(
        exists().where(
            and_(
                models.OpenDataDid.scope == scope,
                models.OpenDataDid.name == name
            )
        )
    )

    if not session.execute(exists_stmt).scalar():
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    update_stmt = update(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )
    if state:
        update_stmt = update_stmt.values(state=state)
    if opendata_json:
        try:
            json.dumps(opendata_json)
        except (TypeError, ValueError) as e:
            raise exception.InputValidationError(f"Invalid JSON data: {e}")
        update_stmt = update_stmt.values(opendata_json=opendata_json)

    # TODO: Add some logic to handle how state is updated e.g. can go from DRAFT to PUBLIC but not the other way around

    # print query
    print(f"Update statement: {update_stmt}")

    try:
        result = session.execute(update_stmt)

        if result.rowcount == 0:
            raise ValueError(f"Error updating OpenData entry '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")
