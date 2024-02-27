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

from typing import Any, Callable, Literal, Optional, TypedDict, Union


class InternalType(object):
    '''
    Base for Internal representations of string types
    '''
    def __init__(self, value, vo='def', fromExternal=True):
        if value is None:
            self.external = None
            self.internal = None
            self.vo = vo
        elif not isinstance(value, str):
            raise TypeError('Expected value to be string type, got %s' % type(value))
        elif fromExternal:
            self.external = value
            self.vo = vo
            self.internal = self._calc_internal()
        else:
            self.internal = value
            vo, external = self._calc_external()
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

    def _calc_external(self):
        ''' Utility to convert between internal and external representations'''
        split = self.internal.split('@', 1)
        if len(split) == 1:  # if cannot convert, vo is '' and this is single vo
            vo = 'def'
            external = split[0]
        else:
            vo = split[1]
            external = split[0]
        return vo, external

    def _calc_internal(self):
        ''' Utility to convert between internal and external representations'''
        if self.vo == 'def':
            return self.external
        internal = '{}@{}'.format(self.external, self.vo)
        return internal


class InternalAccount(InternalType):
    '''
    Internal representation of an account
    '''
    def __init__(self, account, vo='def', fromExternal=True):
        super(InternalAccount, self).__init__(value=account, vo=vo, fromExternal=fromExternal)


class InternalScope(InternalType):
    '''
    Internal representation of a scope
    '''
    def __init__(self, scope, vo='def', fromExternal=True):
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


class RuleDict(TypedDict):
    account: InternalAccount
    copies: int
    rse_expression: str
    grouping: Literal['ALL', 'DATASET', 'NONE']
    weight: str
    lifetime: int
    locked: bool
    subscription_id: str
    source_replica_expression: Optional[str]
    activity: str
    notify: Optional[Literal['Y', 'N', 'C']]
    purge_replicas: bool
