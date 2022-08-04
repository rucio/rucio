# -*- coding: utf-8 -*-
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

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from typing_extensions import TypedDict, NotRequired
from ..literals.replica import ReplicaStateLongLiteral, ReplicaStateShortLiteral


class ReplicaRSENameDict(TypedDict):
    rse: str
    scope: str
    name: str


class ReplicaRSEIdDict(TypedDict):
    rse_id: str
    scope: str
    name: str


ReplicaRSEDict = Union[ReplicaRSENameDict, ReplicaRSEIdDict]


class QuarantineReplicaDict(TypedDict):
    scope: NotRequired[str]
    name: NotRequired[str]
    path: str


class ReplicaPFNDict(TypedDict):
    rse: str
    rse_id: str
    type: str
    domain: str
    priority: int
    volatile: bool
    client_extract: bool


class ReplicaDict(TypedDict):
    scope: str
    name: str
    bytes: int
    md5: str
    adler32: str
    rses: Dict[str, List[str]]
    pfns: Dict[str, Dict[str, ReplicaPFNDict]]
    states: Dict[str, str]


class SuspiciousReplicaDict(TypedDict):
    scope: str
    name: str
    rse: str
    rse_id: str
    cnt: int
    created_at: datetime


class AddReplicaDict(TypedDict):
    scope: str
    name: str
    bytes: int
    pfn: NotRequired[str]
    state: NotRequired[str]
    path: NotRequired[str]
    md5: NotRequired[str]
    adler32: NotRequired[str]
    lock_cnt: NotRequired[str]
    tombstone: NotRequired[str]
    meta: NotRequired[Dict[str, Any]]


class UpdateReplicaStateDict(TypedDict):
    scope: str
    name: str
    state: ReplicaStateShortLiteral


class DatasetReplicaDict(TypedDict):
    scope: str
    name: str
    rse: str
    rse_id: str
    bytes: int
    length: int
    available_bytes: int
    available_length: int
    state: ReplicaStateLongLiteral
    created_at: datetime
    updated_at: datetime
    accessed_at: Optional[datetime]
