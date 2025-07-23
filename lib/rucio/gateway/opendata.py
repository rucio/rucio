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
from typing import TYPE_CHECKING, Any, Optional

from rucio.common.constants import DEFAULT_VO
from rucio.common.types import InternalScope
from rucio.common.utils import gateway_update_return_dict
from rucio.core import opendata
from rucio.core.opendata import opendata_state_str_to_enum, validate_opendata_did_state
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session

if TYPE_CHECKING:
    from rucio.common.constants import OPENDATA_DID_STATE_LITERAL


def list_opendata_dids(
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        state: Optional["OPENDATA_DID_STATE_LITERAL"] = None,
) -> dict[str, list[dict[str, Any]]]:
    """
    List Opendata DIDs from the Opendata catalog.

    Parameters:
        limit: Maximum number of DIDs to return.
        offset: Number of DIDs to skip before starting to collect the result set.
        state: Filter DIDs by their state.

    Returns:
        A dictionary with a list of DIDs matching the criteria.
    """

    state_enum = None
    if state is not None:
        state = validate_opendata_did_state(state)
        state_enum = opendata_state_str_to_enum(state)
    with db_session(DatabaseOperationType.READ) as session:
        result = opendata.list_opendata_dids(limit=limit, offset=offset, state=state_enum, session=session)
    return result


def get_opendata_did(
        *,
        scope: str,
        name: str,
        state: Optional["OPENDATA_DID_STATE_LITERAL"] = None,
        include_files: bool = True,
        include_metadata: bool = False,
        include_doi: bool = True,
        vo: str = DEFAULT_VO,
) -> dict[str, Any]:
    """
    Retrieve a specific Opendata DID from the Opendata catalog.

    Parameters:
        scope: The scope of the DID.
        name: The name of the DID.
        state: Optional state to filter the DID.
        include_files: Whether to include files in the result.
        include_metadata: Whether to include metadata in the result.
        include_doi: Whether to include DOI information in the result.
        vo: The virtual organization.

    Returns:
        A dictionary containing the details of the requested DID.
    """

    internal_scope = InternalScope(scope, vo=vo)
    state_enum = None
    if state is not None:
        state = validate_opendata_did_state(state)
        state_enum = opendata_state_str_to_enum(state)

    with db_session(DatabaseOperationType.READ) as session:
        result = opendata.get_opendata_did(scope=internal_scope,
                                           name=name,
                                           state=state_enum,
                                           include_files=include_files,
                                           include_metadata=include_metadata,
                                           include_doi=include_doi,
                                           session=session)
        return gateway_update_return_dict(result, session=session)


def add_opendata_did(
        *,
        scope: str,
        name: str,
        vo: str = DEFAULT_VO,
) -> None:
    """
    Add a new Opendata DID to the Opendata catalog.

    Parameters:
        scope: The scope of the DID.
        name: The name of the DID.
        vo: The virtual organization.

    Returns:
        None
    """

    internal_scope = InternalScope(scope, vo=vo)
    with db_session(DatabaseOperationType.WRITE) as session:
        return opendata.add_opendata_did(scope=internal_scope, name=name, session=session)


def delete_opendata_did(
        *,
        scope: str,
        name: str,
        vo: str = DEFAULT_VO,
) -> None:
    """
    Delete an Opendata DID from the Opendata catalog.

    Parameters:
        scope: The scope of the DID.
        name: The name of the DID.
        vo: The virtual organization.

    Returns:
        None
    """

    internal_scope = InternalScope(scope, vo=vo)
    with db_session(DatabaseOperationType.WRITE) as session:
        return opendata.delete_opendata_did(scope=internal_scope, name=name, session=session)


def update_opendata_did(
        *,
        scope: str,
        name: str,
        state: Optional["OPENDATA_DID_STATE_LITERAL"] = None,
        meta: Optional[dict] = None,
        doi: Optional[str] = None,
        vo: str = DEFAULT_VO,
) -> None:
    """
    Update an existing Opendata DID in the Opendata catalog.

    Parameters:
        scope: The scope of the DID.
        name: The name of the DID.
        state: Optional new state for the DID.
        meta: Optional metadata dictionary or JSON string.
        doi: Optional DOI string.
        vo: The virtual organization.

    Returns:
        None

    Raises:
        ValueError: If meta is a string and cannot be parsed as valid JSON.
    """

    internal_scope = InternalScope(scope, vo=vo)
    state_enum = None
    if state is not None:
        state = validate_opendata_did_state(state)
        state_enum = opendata_state_str_to_enum(state)
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except ValueError as error:
            raise ValueError(f"Invalid JSON: {error}")

    with db_session(DatabaseOperationType.WRITE) as session:
        return opendata.update_opendata_did(scope=internal_scope,
                                            name=name,
                                            state=state_enum,
                                            meta=meta,
                                            doi=doi,
                                            session=session)
