# Copyright 2012-2019 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from six import string_types


class InternalType(object):
    '''
    Base for Internal representations of string types
    '''
    def __init__(self, value, fromExternal=True):
        if value is None:
            self.external = None
            self.internal = None
        elif not isinstance(value, string_types):
            raise TypeError('Expected string type, got %s' % type(value))
        elif fromExternal:
            self.external = value
            self.internal = self._calc_internal()
        else:
            self.internal = value
            external = self._calc_external()
            self.external = external

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
        return not val

    def __lt__(self, other):
        val = self.external < other.external
        if val is NotImplemented:
            return NotImplemented
        return not val

    def __hash__(self):
        return hash(self.internal)

    def _calc_external(self):
        ''' Utility to convert between internal and external representations'''
        return self.internal

    def _calc_internal(self):
        ''' Utility to convert between internal and external representations'''
        return self.external


class InternalAccount(InternalType):
    '''
    Internal representation of an account
    '''
    def __init__(self, value, fromExternal=True):
        super(InternalAccount, self).__init__(value=value, fromExternal=fromExternal)


class InternalScope(InternalType):
    '''
    Internal representation of a scope
    '''
    def __init__(self, value, fromExternal=True):
        super(InternalScope, self).__init__(value=value, fromExternal=fromExternal)
