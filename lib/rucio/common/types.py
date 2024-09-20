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

import sys
from collections.abc import Callable
from os import PathLike

if sys.version_info < (3, 11):  # pragma: no cover
    from typing_extensions import TYPE_CHECKING, Any, Literal, NotRequired, Optional, TypedDict, Union  # noqa: UP035
    PathTypeAlias = Union[PathLike, str]
else:
    from typing import TYPE_CHECKING, Any, Literal, NotRequired, Optional, TypedDict, Union
    PathTypeAlias = PathLike


if TYPE_CHECKING:
    from datetime import datetime

    from rucio.common.constants import SUPPORTED_PROTOCOLS_LITERAL
    from rucio.db.sqla.constants import AccountType, IdentityType, ReplicaState, RequestState, RequestType, RSEType


class InternalType:
    '''
    Base for Internal representations of string types
    '''
    def __init__(self, value: Optional[str], vo: str = 'def', fromExternal: bool = True):
        if value is None:
            self.external = None
            self.internal = None
            self.vo = vo
        elif fromExternal:
            self.external = value
            self.vo = vo
            self.internal = _RepresentationCalculator.calc_internal(self.external, self.vo)
        else:
            self.internal = value
            vo, external = _RepresentationCalculator.calc_external(self.internal)
            self.external = external
            self.vo = vo

    def __repr__(self):
        return self.internal

    def __str__(self):
        return self.external

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.internal == other.internal
        return NotImplemented

    def __ne__(self, other):
        val = self == other
        if val is NotImplemented:
            return NotImplemented
        return not val

    def __le__(self, other):
        val = self.external <= other.external
        if val is NotImplemented:
            return NotImplemented
        return val

    def __lt__(self, other):
        val = self.external < other.external
        if val is NotImplemented:
            return NotImplemented
        return val

    def __hash__(self):
        return hash(self.internal)


class _RepresentationCalculator:
    @staticmethod
    def calc_external(internal: str) -> tuple[str, str]:
        """
        Calculate external representation from internal representation

        :param internal: internal representation

        :returns: tuple of VO and external representation
        """
        split = internal.split('@', 1)
        if len(split) == 1:  # if cannot convert, vo is '' and this is single vo
            vo = 'def'
            external = split[0]
        else:
            vo = split[1]
            external = split[0]
        return vo, external

    @staticmethod
    def calc_internal(external: str, vo: str) -> str:
        """
        Calculate internal representation from external representation and VO

        :param external: external representation
        :param vo: VO name

        :returns: internal representation
        """
        if vo == 'def':
            return external
        internal = '{}@{}'.format(external, vo)
        return internal


class InternalAccount(InternalType):
    '''
    Internal representation of an account
    '''
    def __init__(self, account: Optional[str], vo: str = 'def', fromExternal: bool = True):
        super(InternalAccount, self).__init__(value=account, vo=vo, fromExternal=fromExternal)


class InternalScope(InternalType):
    '''
    Internal representation of a scope
    '''
    def __init__(self, scope: Optional[str], vo: str = 'def', fromExternal: bool = True):
        super(InternalScope, self).__init__(value=scope, vo=vo, fromExternal=fromExternal)


LoggerFunction = Callable[..., Any]


class RSEDomainLANDict(TypedDict):
    read: Optional[int]
    write: Optional[int]
    delete: Optional[int]


class RSEDomainWANDict(TypedDict):
    read: Optional[int]
    write: Optional[int]
    delete: Optional[int]
    third_party_copy_read: Optional[int]
    third_party_copy_write: Optional[int]


class RSEDomainsDict(TypedDict):
    lan: RSEDomainLANDict
    wan: RSEDomainWANDict


class RSEProtocolDict(TypedDict):
    auth_token: Optional[str]  # FIXME: typing.NotRequired
    hostname: str
    scheme: str
    port: int
    prefix: str
    impl: str
    domains: RSEDomainsDict
    extended_attributes: Optional[Union[str, dict[str, Any]]]


class RSESettingsDict(TypedDict):
    availability_delete: bool
    availability_read: bool
    availability_write: bool
    credentials: Optional[dict[str, Any]]
    lfn2pfn_algorithm: str
    qos_class: Optional[str]
    staging_area: bool
    rse_type: str
    sign_url: Optional[str]
    read_protocol: int
    write_protocol: int
    delete_protocol: int
    third_party_copy_read_protocol: int
    third_party_copy_write_protocol: int
    id: str
    rse: str
    volatile: bool
    verify_checksum: bool
    deterministic: bool
    domain: list[str]
    protocols: list[RSEProtocolDict]


class RSEAccountCounterDict(TypedDict):
    account: InternalAccount
    rse_id: str


class RSEAccountUsageDict(TypedDict):
    rse_id: str
    rse: str
    account: InternalAccount
    used_files: int
    used_bytes: int
    quota_bytes: int


class RSEGlobalAccountUsageDict(TypedDict):
    rse_expression: str
    bytes: int
    files: int
    bytes_limit: int
    bytes_remaining: int


class RSELocalAccountUsageDict(TypedDict):
    rse_id: str
    rse: str
    bytes: int
    files: int
    bytes_limit: int
    bytes_remaining: int


class RSEResolvedGlobalAccountLimitDict(TypedDict):
    resolved_rses: str
    resolved_rse_ids: list[str]
    limit: float


class RuleDict(TypedDict):
    account: InternalAccount
    copies: int
    rse_expression: str
    grouping: Literal['ALL', 'DATASET', 'NONE']
    weight: Optional[str]
    lifetime: Optional[int]
    locked: bool
    subscription_id: Optional[str]
    source_replica_expression: Optional[str]
    activity: str
    notify: Optional[Literal['Y', 'N', 'C', 'P']]
    purge_replicas: bool


class ReplicaDict(TypedDict):
    scope: InternalScope
    name: str
    path: Optional[str]
    state: "ReplicaState"
    bytes: int
    md5: Optional[str]
    adler32: Optional[str]
    rse_id: str
    rse_name: str
    rse_type: "RSEType"
    volatile: bool


class DIDDict(TypedDict):
    name: str
    scope: InternalScope


class DIDStringDict(TypedDict):
    name: str
    scope: str


class DatasetDict(DIDStringDict):
    rse: str


class AttachDict(DatasetDict):
    did: DIDStringDict


class HopDict(TypedDict):
    source_rse_id: str
    source_scheme: "SUPPORTED_PROTOCOLS_LITERAL"
    source_scheme_priority: int
    dest_rse_id: str
    dest_scheme: "SUPPORTED_PROTOCOLS_LITERAL"
    dest_scheme_priority: int


class TokenDict(TypedDict):
    token: str
    expires_at: 'datetime'


class TokenValidationDict(TypedDict):
    account: Optional[InternalAccount]
    identity: Optional[str]
    lifetime: 'datetime'
    audience: Optional[str]
    authz_scope: Optional[str]


class IPDict(TypedDict):
    ip: Optional[str]
    fqdn: Optional[str]
    site: Optional[str]


class IPWithLocationDict(TypedDict):
    ip: str
    fqdn: str
    site: str
    latitude: Optional[float]
    longitude: Optional[float]


class AccountDict(TypedDict):
    account: InternalAccount
    type: "AccountType"
    email: str


class AccountAttributesDict(TypedDict):
    key: str
    value: Union[bool, str]


class IdentityDict(TypedDict):
    type: "IdentityType"
    identity: str
    email: str


class UsageDict(TypedDict):
    bytes: int
    files: int
    updated_at: Optional['datetime']


class AccountUsageModelDict(TypedDict):
    account: InternalAccount
    rse_id: str
    files: int
    bytes: int


class TraceBaseDict(TypedDict):
    hostname: str
    account: str
    eventType: str
    eventVersion: str
    vo: Optional[str]
    uuid: NotRequired[str]
    scope: NotRequired[str]
    datasetScope: NotRequired[str]
    dataset: NotRequired[str]
    remoteSite: NotRequired[str]
    filesize: NotRequired[int]
    stateReason: NotRequired[str]
    protocol: NotRequired[str]
    clientState: NotRequired[str]
    transferStart: NotRequired[float]
    transferEnd: NotRequired[float]


class TraceDict(TraceBaseDict):
    uuid: str
    scope: str
    datasetScope: str
    dataset: str
    remoteSite: str
    filesize: int
    stateReason: str
    protocol: str
    clientState: str
    transferStart: float
    transferEnd: float


class TraceSchemaDict(TypedDict):
    eventType: str


class FileToUploadDict(TypedDict):
    path: PathTypeAlias
    rse: str
    did_scope: str
    did_name: str
    dataset_scope: NotRequired[str]
    dataset_name: NotRequired[str]
    dataset_meta: NotRequired[str]
    impl: NotRequired[str]
    force_scheme: NotRequired[str]
    pfn: NotRequired[str]
    no_register: NotRequired[bool]
    register_after_upload: NotRequired[bool]
    lifetime: NotRequired[int]
    transfer_timeout: NotRequired[int]
    guid: NotRequired[str]
    recursive: NotRequired[bool]


class FileToUploadWithCollectedInfoDict(FileToUploadDict):
    basename: str
    adler32: str
    md5: str
    meta: dict[str, str]
    state: str
    dataset_did_str: NotRequired[str]
    dirname: str
    upload_result: dict
    bytes: int
    basename: str


class FileToUploadWithCollectedAndDatasetInfoDict(FileToUploadWithCollectedInfoDict):
    dataset_scope: str
    dataset_name: str


class RequestGatewayDict(TypedDict):
    """
    Request dict expected as input to gateway
    """
    scope: str
    name: str
    account: Optional[str]
    dest_rse_id: str
    request_type: "RequestType"
    attributes: "RequestAttributesDict"


class RequestDict(TypedDict):
    """
    Requested dict used in core
    """
    id: str
    request_id: str
    scope: InternalScope
    name: str
    source_rse_id: str
    dest_rse_id: str
    dest_url: str
    state: "RequestState"
    account: NotRequired[InternalAccount]
    rule_id: str
    adler32: str
    bytes: int
    err_msg: str
    sources: list[dict[str, Any]]
    request_type: "RequestType"
    retry_count: Optional[int]
    previous_attempt_id: str
    external_host: str
    external_id: str
    transfertool: str
    attributes: "RequestAttributesDict"


class RequestAttributesDict(TypedDict):
    activity: str
    bytes: int
    md5: str
    adler32: str
    is_intermediate_hop: bool


class FilterDict(TypedDict):
    rule_id: str
    request_id: str
    older_than: 'datetime'
    activities: Union[list[str], str]
