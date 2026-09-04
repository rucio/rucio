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

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from rucio.common.types import InternalAccount


@enum.unique
class StorageTokenOperation(str, enum.Enum):
    FTS_AUTH = 'fts_auth'
    TPC_SOURCE = 'tpc_source'
    TPC_DESTINATION = 'tpc_destination'
    TPC_STAGE = 'tpc_stage'
    TPC_POLL = 'tpc_poll'
    CENTRAL_DELETE = 'central_delete'
    CLIENT_DELETE = 'client_delete'
    CLIENT_DOWNLOAD = 'client_download'
    CLIENT_UPLOAD = 'client_upload'


@dataclass
class StorageTokenContext:
    operation: StorageTokenOperation
    rse_id: Optional[str] = None
    did: Optional[tuple[str, str]] = None
    account: Optional['InternalAccount'] = None
    extras: dict[str, Any] = field(default_factory=dict)
    vo: Optional[str] = None
