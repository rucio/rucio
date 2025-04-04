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
from typing import TYPE_CHECKING, Any, Optional, Union

from sqlalchemy import and_, delete, exists, insert, update
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.sql.expression import bindparam, select

from rucio.common import exception
from rucio.common.exception import OpenDataError
from rucio.core.monitor import MetricManager
from rucio.db.sqla import models
from rucio.db.sqla.constants import OpenDataDIDState
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalScope

METRICS = MetricManager(module=__name__)


def is_valid_opendata_did_state(state: str) -> bool:
    try:
        _ = OpenDataDIDState[state]
        return True
    except KeyError:
        return False


def check_valid_opendata_did_state(state: str) -> None:
    if not is_valid_opendata_did_state(state):
        raise OpenDataError(
            f"Invalid state '{state}'. Valid opendata states are: {', '.join([s.name for s in OpenDataDIDState])}")


# Don't know how to annotate this :(
def opendata_state_str_to_enum(state: str) -> Any:
    try:
        return OpenDataDIDState[state]
    except KeyError:
        raise exception.InputValidationError(
            f"Invalid state '{state}'. Valid opendata states are: {', '.join([s.name for s in OpenDataDIDState])}")


@read_session
def list_opendata_dids(
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        state: Optional[OpenDataDIDState] = None,
        session: "Session"
) -> list[dict[str, Any]]:
    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
        models.OpenDataDid.created_at,
        models.OpenDataDid.updated_at,
    ).order_by(
        models.OpenDataDid.updated_at
    )

    print(f"Called list_opendata_dids with limit={limit}, offset={offset}, state={state}")

    if limit is not None:
        query = query.limit(limit)

    if offset is not None:
        query = query.offset(offset)

    if state is not None:
        query = query.where(models.OpenDataDid.state == state)

    print(f"Query: {query}")

    return [{"scope": scope, "name": name, "state": state, "created_at": created_at, "updated_at": updated_at} for
            scope, name, state, created_at, updated_at in session.execute(query)]


@read_session
def get_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[OpenDataDIDState] = None,
        session: "Session"
) -> Optional[dict[str, Any]]:
    print(f"Called GATEWAY get_opendata_did with scope={scope}, name={name}, state={state}")

    query = select(
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
        query = query.where(models.OpenDataDid.state == state)

    print(f"Query: {query}")

    result = session.execute(query).mappings().fetchone()
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

    query = insert(models.OpenDataDid).values(dids)

    try:
        session.execute(query)
    except IntegrityError as error:
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
    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
    ).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )

    result = session.execute(query).mappings().fetchone()
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
        state: Optional[OpenDataDIDState] = None,
        opendata_json: Optional[Union[dict, str]] = None,
        session: "Session",
) -> None:
    if state is None and opendata_json is None:
        raise exception.InputValidationError("Either 'state' or 'opendata_json' must be provided.")

    if opendata_json is not None:
        if isinstance(opendata_json, str):
            try:
                opendata_json = json.loads(opendata_json)
            except ValueError as error:
                raise exception.InputValidationError(f"Invalid JSON data: {error}")

        if not isinstance(opendata_json, dict):
            raise exception.InputValidationError("opendata_json must be a dictionary.")

    exists_query = select(models.OpenDataDid.state).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )

    state_before = session.execute(exists_query).scalar()
    if state_before is None:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    update_query = update(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )
    if state is not None:
        update_query = update_query.values(state=state)

        if state == OpenDataDIDState.DRAFT:
            if state_before != OpenDataDIDState.DRAFT:
                raise OpenDataError("Cannot set state to DRAFT. Once a DID is made public, it cannot be reverted to DRAFT.")
        elif state == OpenDataDIDState.PUBLIC:
            # All states can be set to PUBLIC
            ...
        elif state == OpenDataDIDState.SUSPENDED:
            if state_before == OpenDataDIDState.DRAFT:
                raise OpenDataError("Cannot set state to SUSPENDED from DRAFT. First set it to PUBLIC.")

    if opendata_json is not None:
        update_query = update_query.values(opendata_json=opendata_json)

    try:
        result = session.execute(update_query)

        if result.rowcount == 0:
            raise ValueError(f"Error updating OpenData entry '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")
