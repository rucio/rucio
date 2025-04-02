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

from typing import TYPE_CHECKING, Any, Optional

from rucio.common.types import InternalScope
from rucio.common.utils import gateway_update_return_dict
from rucio.core import opendata
from rucio.db.sqla.session import read_session, stream_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.orm import Session


@stream_session
def list_opendata_dids(
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        state: Optional[str] = None,  # TODO: type only valid states
        session: "Session"
) -> "Iterator[dict[str, Any]]":
    result = opendata.list_opendata_dids(limit=limit, offset=offset, state=state, session=session)

    yield from (gateway_update_return_dict(d, session=session) for d in result)


@read_session
def get_opendata_did(
        *,
        scope: str,
        name: str,
        state: Optional[str] = None,  # TODO: type only valid states
        vo: str = "def",
        session: "Session"
) -> dict[str, Any]:
    internal_scope = InternalScope(scope, vo=vo)
    return gateway_update_return_dict(
        opendata.get_opendata_did(scope=internal_scope, name=name, state=state, session=session),
        session=session)


@transactional_session
def add_opendata_did(
        *,
        scope: str,
        name: str,
        vo: str = "def",
        session: "Session"
) -> None:
    internal_scope = InternalScope(scope, vo=vo)
    return opendata.add_opendata_did(scope=internal_scope, name=name, session=session)


@transactional_session
def delete_opendata_did(
        *,
        scope: str,
        name: str,
        vo: str = "def",
        session: "Session"
) -> None:
    internal_scope = InternalScope(scope, vo=vo)
    return opendata.delete_opendata_did(scope=internal_scope, name=name, session=session)
