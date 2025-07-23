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
from re import match, search
from typing import TYPE_CHECKING, Any, Optional, Union, cast

from sqlalchemy import and_, delete, insert, update
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.sql.expression import bindparam, select

from rucio.common import exception
from rucio.common.exception import OpenDataError, OpenDataInvalidStateUpdate
from rucio.core.did import list_files
from rucio.core.monitor import MetricManager
from rucio.core.replica import list_replicas
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, OpenDataDIDState

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.orm import Session

    from rucio.common.constants import OPENDATA_DID_STATE_LITERAL
    from rucio.common.types import InternalScope

METRICS = MetricManager(module=__name__)


def is_valid_opendata_did_state(state: str) -> bool:
    """
    Checks if the provided state string corresponds to a valid Opendata DID state.

    Parameters:
        state: The state string to validate (e.g., 'draft', 'public', 'suspended').

    Returns:
        True if the state is valid, False otherwise.
    """

    try:
        _ = OpenDataDIDState[state.upper()]
        return True
    except KeyError:
        return False


def validate_opendata_did_state(state: str) -> "OPENDATA_DID_STATE_LITERAL":
    """
    Validate the provided Opendata DID state string and return it in a consistent format.
    If the state is invalid, raise an OpenDataError with a message listing valid states.

    Parameters:
        state: The state string to validate (e.g., 'draft', 'public', 'suspended').

    Returns:
        The validated state string in lowercase.
    """

    state = state.lower()
    if not is_valid_opendata_did_state(state):
        raise OpenDataError(
            f"Invalid state '{state}'. Valid opendata states are: {', '.join([s.name.lower() for s in OpenDataDIDState])}")

    return cast("OPENDATA_DID_STATE_LITERAL", state)


def opendata_state_str_to_enum(state: "OPENDATA_DID_STATE_LITERAL") -> OpenDataDIDState:
    """
    Convert a string representation of an Opendata DID state to the corresponding OpenDataDIDState enum.
    If the state is invalid, raise an OpenDataError with a message listing valid states.

    Parameters:
        state: The state string to convert (e.g., 'draft', 'public', 'suspended').

    Returns:
        The corresponding OpenDataDIDState enum value.
    """

    return OpenDataDIDState[validate_opendata_did_state(state).upper()]


def _check_opendata_did_exists(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> bool:
    """
    Check if an Opendata DID does exist in the database.
    """

    query = select(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )
    result = session.execute(query).scalar()
    return result is not None


def list_opendata_dids(
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        state: Optional[OpenDataDIDState] = None,
        session: "Session",
) -> dict[str, list[dict[str, Any]]]:
    """
    List Opendata DIDs with optional filtering by state, limit, and offset.

    Parameters:
        limit: Maximum number of DIDs to return.
        offset: Offset for pagination.
        state: Filter by Opendata DID state.
        session: SQLAlchemy session to use for the query.

    Returns:
        A dictionary containing the total count, offset, and a list of DIDs.
    """

    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
        models.OpenDataDid.created_at,
        models.OpenDataDid.updated_at,
    ).order_by(
        models.OpenDataDid.updated_at
    )

    if limit is not None:
        query = query.limit(limit)

    if offset is not None:
        query = query.offset(offset)

    if state is not None:
        query = query.where(models.OpenDataDid.state == state)

    dids = [{"scope": scope, "name": name, "state": state, "created_at": created_at, "updated_at": updated_at} for
            scope, name, state, created_at, updated_at in session.execute(query)]

    response = {
        "total": len(dids),
        "offset": offset if offset is not None else 0,
        "dids": dids,
    }

    return response


def get_opendata_meta(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> dict:
    """
    Retrieve the metadata associated with an Opendata DID.

    Parameters:
        scope: The scope of the Opendata DID.
        name: The name of the Opendata DID.
        session: SQLAlchemy session to use for the query.

    Returns:
        A dictionary containing the metadata for the specified Opendata DID.
    """

    query = select(
        models.OpenDataMeta.meta,
    ).where(
        and_(
            models.OpenDataMeta.name == name,
            models.OpenDataMeta.scope == scope,
        )
    )

    result = session.execute(query).mappings().fetchone()

    if not result:
        return {}
    else:
        return result["meta"]


def get_opendata_doi(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> Optional[str]:
    """
    Retrieve the DOI (Digital Object Identifier) associated with an Opendata DID.

    Parameters:
        scope: The scope of the Opendata DID.
        name: The name of the Opendata DID.
        session: SQLAlchemy session to use for the query.

    Returns:
        The DOI associated with the Opendata DID, or None if not found.
    """

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


def get_opendata_did_files(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> list[dict[str, Any]]:
    """
    Retrieve the files associated with an Opendata DID.

    Parameters:
        scope: The scope of the Opendata DID.
        name: The name of the Opendata DID.
        session: SQLAlchemy session to use for the query.

    Returns:
        A list of dictionaries containing file information associated with the Opendata DID.
    """

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
        }
        for file in files
    ]

    for i, file in enumerate(result):
        replicas = list_replicas(dids=[{"scope": file["scope"], "name": file["name"]}], session=session)
        uris = []
        for replica in replicas:
            pfns = replica["pfns"]
            for uri, data in pfns.items():
                if data["type"] != "DISK":
                    continue
                uris.append(uri)

        result[i]["uris"] = uris

    return result


def get_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[OpenDataDIDState] = None,
        include_files: bool = True,
        include_metadata: bool = False,
        include_doi: bool = True,
        session: "Session",
) -> dict[str, Any]:
    """
    Retrieve information about an Opendata DID (Data Identifier).

    Parameters:
        scope: The scope under which the DID is registered.
        name: The name of the DID.
        state: Filter by Opendata DID state.
        include_files: If True, include a list of associated files. Defaults to True.
        include_metadata: If True, include extended metadata. Defaults to False.
        include_doi: If True, include DOI (Digital Object Identifier) information. Defaults to True.
        session: SQLAlchemy session to use for the query.

    Returns:
        A dictionary containing metadata about the specified DID.
    """

    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
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

    result = session.execute(query).mappings().fetchone()

    if not result:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")

    result = dict(result)

    if include_doi:
        result["doi"] = get_opendata_doi(scope=scope, name=name, session=session)
    if include_metadata:
        result["meta"] = get_opendata_meta(scope=scope, name=name, session=session)
    if include_files:
        opendata_files = get_opendata_did_files(scope=scope, name=name, session=session)
        result["files"] = opendata_files

        bytes_sum = sum(file["bytes"] for file in opendata_files)
        extensions = set()
        replicas_missing = 0
        for file in opendata_files:
            if "uris" not in file or not file["uris"]:
                replicas_missing += 1
                continue
            for replica in file["uris"]:
                filename = replica.split("/")[-1]
                if "." in filename:
                    extensions.add(filename.split(".")[-1])

        result["files_summary"] = {
            "count": len(opendata_files),
            "bytes": bytes_sum,
            "extensions": list(extensions),
            "replicas_missing": replicas_missing,
        }

    return result


def add_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> None:
    """
    Add an existing DID to the Opendata catalog.

    Parameters:
        scope: The scope under which the DID is registered.
        name: The name of the DID.
        session: SQLAlchemy session to use for the operation.

    Raises:
        DataIdentifierNotFound: If the DID does not exist.
        OpenDataDataIdentifierAlreadyExists: If the Opendata DID already exists in the catalog.
    """

    try:
        return add_opendata_dids([{"scope": scope, "name": name}], session=session)
    except exception.DataIdentifierNotFound:
        raise exception.DataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")
    except exception.OpenDataDataIdentifierAlreadyExists:
        raise exception.OpenDataDataIdentifierAlreadyExists(f"OpenData DID {scope}:{name} already exists.")


def add_opendata_dids(
        dids: "Sequence[dict[str, Any]]",
        *,
        session: "Session",
) -> None:
    """
    Add multiple Opendata DIDs to the catalog.

    Parameters:
        dids: A sequence of dictionaries, each containing 'scope' and 'name' keys for the DIDs to be added.
        session: SQLAlchemy session to use for the operation.

    Raises:
        InputValidationError: If any DID does not have 'scope' or 'name' keys.
        OpenDataDataIdentifierAlreadyExists: If any of the DIDs already exist in the catalog.
        DataIdentifierNotFound: If any of the DIDs do not exist in the database.
    """

    for did in dids:
        if "scope" not in did or "name" not in did:
            raise exception.InputValidationError("DID must have 'scope' and 'name' keys.")

    try:
        # The default state is DRAFT, set in the model
        session.execute(
            insert(models.OpenDataDid),
            [
                {
                    "scope": did["scope"],
                    "name": did["name"],
                }
                for did in dids]
        )
    except IntegrityError as error:
        msg = str(error)

        if (
                search(r'ORA-00001: unique constraint \([^)]+DIDS_OPENDATA_PK\) violated', msg)
                or search(r'UNIQUE constraint failed: dids_opendata\.scope, dids_opendata\.name', msg)
                or search(r'1062.*Duplicate entry.*for key', msg)
                or search(r'duplicate key value violates unique constraint', msg)
                or search(r'UniqueViolation.*duplicate key value violates unique constraint', msg)
                or search(r'columns?.*not unique', msg)
        ):
            raise exception.OpenDataDataIdentifierAlreadyExists()

        raise exception.DataIdentifierNotFound()


def delete_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> None:
    """
    Delete an Opendata DID from the catalog.

    Parameters:
        scope: The scope under which the DID is registered.
        name: The name of the DID to be deleted.
        session: SQLAlchemy session to use for the operation.

    Raises:
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        OpenDataInvalidState: If the Opendata DID is not in a valid state for deletion (must be DRAFT).
        ValueError: If there is an error during the deletion process.
    """

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
        raise ValueError(f"Error deleting Opendata entry '{scope}:{name}'.")


def update_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[OpenDataDIDState] = None,
        meta: Optional[Union[dict, str]] = None,
        doi: Optional[str] = None,
        session: "Session",
) -> None:
    """
    Update an existing Opendata DID in the catalog.

    Parameters:
        scope: The scope under which the DID is registered.
        name: The name of the DID to be updated.
        state: The new state to set for the DID.
        meta: Metadata to update for the DID. Must be a valid JSON object or string.
        doi: DOI to associate with the DID. Must be a valid DOI string (e.g., "10.1234/foo.bar").
        session: SQLAlchemy session to use for the operation.

    Raises:
        InputValidationError: If none of 'state', 'meta', or 'doi' are provided, or if the provided data is invalid.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        OpenDataInvalidStateUpdate: If the state update is not valid (e.g., trying to set DRAFT after PUBLIC).
        ValueError: If there is an error during the update process.
    """

    if state is None and meta is None and doi is None:
        raise exception.InputValidationError(
            "Either 'state', 'meta', or 'doi' must be provided to update the Opendata DID.")
    if not _check_opendata_did_exists(scope=scope, name=name, session=session):
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    if state is not None:
        update_opendata_state(scope=scope, name=name, state=state, session=session)

    if meta is not None:
        update_opendata_meta(scope=scope, name=name, meta=meta, session=session)

    if doi is not None:
        update_opendata_doi(scope=scope, name=name, doi=doi, session=session)


def update_opendata_meta(
        *,
        scope: "InternalScope",
        name: str,
        meta: Union[dict, str],
        session: "Session",
) -> None:
    """
    Update the metadata associated with an Opendata DID.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        meta: Metadata to update for the DID. Must be a valid JSON object or string.
        session: SQLAlchemy session to use for the operation.

    Raises:
        InputValidationError: If 'meta' is not a dictionary or a valid JSON string.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        ValueError: If there is an error during the update or insert process.
    """

    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except ValueError as error:
            raise exception.InputValidationError(f"Invalid JSON data: {error}")

    if not isinstance(meta, dict):
        raise exception.InputValidationError("'meta' must be a dictionary.")

    try:
        stmt = update(models.OpenDataMeta).where(
            and_(
                models.OpenDataMeta.scope == scope,
                models.OpenDataMeta.name == name
            )
        ).values(meta=meta).execution_options(synchronize_session="fetch")
        result = session.execute(stmt)

        if result.rowcount == 0:
            # If no rows were updated, insert a new row
            insert_stmt = insert(models.OpenDataMeta).values(
                scope=scope,
                name=name,
                meta=meta
            )
            result = session.execute(insert_stmt)

        if result.rowcount == 0:
            raise ValueError(f"Error inserting Opendata meta for DID '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")


def update_opendata_state(
        *,
        scope: "InternalScope",
        name: str,
        state: OpenDataDIDState,
        session: "Session",
) -> None:
    """
    Update the state of an Opendata DID.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        state: The new state to set for the Opendata DID.
        session: SQLAlchemy session to use for the operation.

    Raises:
        InputValidationError: If the provided state is not a valid OpenDataDIDState.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        OpenDataInvalidStateUpdate: If the state update is not valid (e.g., trying to set DRAFT after PUBLIC).
        ValueError: If there is an error during the update process.
    """

    if not isinstance(state, OpenDataDIDState):
        raise exception.InputValidationError(
            f"Invalid state '{state}'. Valid opendata states are: {', '.join([s.name for s in OpenDataDIDState])}")

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
            raise ValueError(f"Error updating Opendata state for DID '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")


def update_opendata_doi(
        *,
        scope: "InternalScope",
        name: str,
        doi: str,
        session: "Session",
) -> None:
    """
    Update the DOI (Digital Object Identifier) associated with an Opendata DID.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        doi: The new DOI to associate with the Opendata DID. Must be a valid DOI string.
        session: SQLAlchemy session to use for the operation.

    Raises:
        InputValidationError: If the provided DOI is not a valid string or does not match the expected format.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        ValueError: If there is an error during the update process.
    """

    if not _check_opendata_did_exists(scope=scope, name=name, session=session):
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
            raise ValueError(f"Error updating Opendata DOI for DID '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")
