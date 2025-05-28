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

from sqlalchemy import and_, delete, insert, update
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.sql.expression import bindparam, select

from rucio.common import exception
from rucio.common.exception import OpenDataError, OpenDataInvalidStateUpdate
from rucio.core.did import list_files
from rucio.core.monitor import MetricManager
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, OpenDataDIDState
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
def opendata_state_str_to_enum(state: str) -> OpenDataDIDState:
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
def get_opendata_doi(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session"
) -> Optional[dict[str, Any]]:
    query = select(
        models.OpenDataDOI.doi,
    ).where(
        and_(
            models.OpenDataDOI.name == name,
            models.OpenDataDOI.scope == scope,
        )
    )

    result = session.execute(query).mappings().fetchone()
    if not result:
        return None
    else:
        return result["doi"]


@read_session
def get_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[OpenDataDIDState] = None,
        session: "Session"
) -> Optional[dict[str, Any]]:
    print(f"Called CORE get_opendata_did with scope={scope}, name={name}, state={state}")

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

    if state is not None:
        query = query.where(models.OpenDataDid.state == state)

    print(f"Query: {query}")

    result = session.execute(query).mappings().fetchone()
    if not result:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")

    print(f"Query result: {result}")

    doi = get_opendata_doi(scope=scope, name=name, session=session)

    return dict(result) | {"doi": doi} if doi else dict(result, doi=None)


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
        dids: "Sequence[dict[str, Any]]",
        *,
        session: "Session",
) -> None:
    for did in dids:
        if "scope" not in did or "name" not in did:
            raise exception.InputValidationError("DID must have 'scope' and 'name' keys.")

    # query = insert(models.OpenDataDid).values(dids)

    try:
        # Default state is DRAFT, set in the model
        session.execute(
            insert(models.OpenDataDid),
            [{"scope": did["scope"], "name": did["name"]} for did in dids]
        )
        # session.execute(query)
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


@read_session
def _check_opendata_did_exists(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> bool:
    query = select(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )
    result = session.execute(query).scalar()
    return result is not None


@transactional_session
def update_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[OpenDataDIDState] = None,
        opendata_json: Optional[Union[dict, str]] = None,
        doi: Optional[str] = None,
        session: "Session",
) -> None:
    if state is None and opendata_json is None and doi is None:
        raise exception.InputValidationError(
            "Either 'state', 'opendata_json', or 'doi' must be provided to update the OpenData DID.")
    if not _check_opendata_did_exists(scope=scope, name=name, session=session):
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    if state is not None:
        update_opendata_state(scope=scope, name=name, state=state, session=session)

    if opendata_json is not None:
        update_opendata_json(scope=scope, name=name, opendata_json=opendata_json, session=session)

    if doi is not None:
        update_opendata_doi(scope=scope, name=name, doi=doi, session=session)


@transactional_session
def update_opendata_json(
        *,
        scope: "InternalScope",
        name: str,
        opendata_json: Union[dict, str],
        session: "Session",
) -> None:
    if isinstance(opendata_json, str):
        try:
            opendata_json = json.loads(opendata_json)
        except ValueError as error:
            raise exception.InputValidationError(f"Invalid JSON data: {error}")

    if not isinstance(opendata_json, dict):
        raise exception.InputValidationError("opendata_json must be a dictionary.")

    update_query = update(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    ).values({"opendata_json": opendata_json})

    try:
        result = session.execute(update_query)

        if result.rowcount == 0:
            raise ValueError(f"Error updating OpenData json for DID '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")


@transactional_session
def update_opendata_state(
        *,
        scope: "InternalScope",
        name: str,
        state: OpenDataDIDState,
        session: "Session",
) -> None:
    check_valid_opendata_did_state(state.name)

    state_before = session.execute(
        select(models.OpenDataDid.state).where(
            and_(
                models.OpenDataDid.scope == scope,
                models.OpenDataDid.name == name
            )
        )
    ).scalar()

    update_query = update(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    ).values({"state": state})

    if state == OpenDataDIDState.DRAFT:
        if state_before != OpenDataDIDState.DRAFT:
            raise OpenDataInvalidStateUpdate(
                "Cannot set state to DRAFT. Once a DID is made public, it cannot be reverted to DRAFT.")
    elif state == OpenDataDIDState.PUBLIC:
        # All states can be set to PUBLIC
        # DID needs to be closed before going public

        did_is_file = session.execute(
            select(models.DataIdentifier.did_type).where(
                and_(
                    models.DataIdentifier.scope == scope,
                    models.DataIdentifier.name == name
                )
            )
        ).scalar() == DIDType.FILE

        if not did_is_file:
            did_is_open = session.execute(
                select(models.DataIdentifier.is_open).where(
                    and_(
                        models.DataIdentifier.scope == scope,
                        models.DataIdentifier.name == name
                    )
                )
            ).scalar()

            if did_is_open:
                raise OpenDataInvalidStateUpdate(
                    "Cannot set state to PUBLIC. The DID must be closed first.")

    elif state == OpenDataDIDState.SUSPENDED:
        if state_before == OpenDataDIDState.DRAFT:
            raise OpenDataInvalidStateUpdate("Cannot set state to SUSPENDED from DRAFT. First set it to PUBLIC.")

    try:
        result = session.execute(update_query)

        if result.rowcount == 0:
            raise ValueError(f"Error updating OpenData state for DID '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")


@transactional_session
def update_opendata_doi(
        *,
        scope: "InternalScope",
        name: str,
        doi: str,
        session: "Session",
) -> None:
    if not _check_opendata_did_exists(scope=scope, name=name, doi=doi):
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    if not isinstance(doi, str):
        raise exception.InputValidationError("DOI must be a string.")
    if not match(r'^10\.\d{4,9}/[-._;()/:A-Za-z0-9]+$', doi):
        raise exception.InputValidationError("Invalid DOI format.")

    # insert on the DOI table if it does not exist, otherwise update it
    doi_before = session.execute(select(models.OpenDataDOI.doi).where(
        and_(
            models.OpenDataDOI.scope == scope,
            models.OpenDataDOI.name == name
        )
    )).scalar()
    if doi_before is None:
        update_query = insert(models.OpenDataDOI).values(scope=scope, name=name, doi=doi)
    else:
        # TODO: do not freely prevent DOI updates? To be discussed
        update_query = update(models.OpenDataDOI).where(
            and_(
                models.OpenDataDOI.scope == scope,
                models.OpenDataDOI.name == name
            )
        ).values(doi=doi)

    try:
        result = session.execute(update_query)

        if result.rowcount == 0:
            raise ValueError(f"Error updating OpenData DOI for DID '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")


@read_session
def get_opendata_did_files(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session"
) -> list[dict[str, Any]]:
    print(f"Called CORE get_opendata_did_files with scope={scope}, name={name}")

    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
    ).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name,
        )
    )

    result = session.execute(query).mappings().fetchone()
    if not result:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")

    files = list_files(scope=scope, name=name)
    result = [
        {
            "scope": file["scope"],
            "name": file["name"],
            "bytes": file["bytes"],
            "adler32": file["adler32"],
            "uri": "TODO",
        }
        for file in files
    ]

    return result
