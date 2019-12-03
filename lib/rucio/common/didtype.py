# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Tobias Wegner <twegner@cern.ch>, 2019
#
# PY3K COMPATIBLE

"""
DID type to represent a did and to simplify operations on it
"""

from six import string_types

from rucio.common.exception import DIDTypeError


class DIDType(object):

    """
    Class used to store a DID
    Given an object did of type DIDType
    scope is stored in did.scope
    name is stored in did.name
    """

    SCOPE_SEPARATOR = ':'
    IMPLICIT_SCOPE_SEPARATOR = '.'
    IMPLICIT_SCOPE_TO_LEN = {'user': 2, 'group': 2}
    __slots__ = ['scope', 'name']

    def __init__(self, *args, **kwargs):
        """
        Constructs the DIDType object. Possible parameter combinations are:
            DIDType()
            DIDType('scope:name.did.str')
            DIDType('user.implicit.scope.in.name')
            DIDType('custom.scope', 'custom.name')
            DIDType(['list.scope', 'list.name'])
            DIDType(('tuple.scope', 'tuple.name'))
            DIDType({'scope': 'dict.scope', 'name': 'dict.name'})
            DIDType(scope='kw.scope')
            DIDType(name='kw.name')
            DIDType(name='user.kw.implicit.scope')
            DIDType(scope='kw.scope', name='kw.name')
            DIDType(did={'scope': 'kw.did.scope', 'name': 'kw.did.name'})
            DIDType(did=['kw.list.scope', 'kw.list.name'])
            DIDType(did=('kw.tuple.scope', 'kw.tuple.name'))
            DIDType('arg.scope', name='kwarg.name')
            DIDType('arg.name', scope='kwarg.scope')
        """
        self.scope = self.name = ''

        num_args = len(args)
        num_kwargs = len(kwargs)
        if (num_args + num_kwargs) > 2:
            raise DIDTypeError('Constructor takes at most 2 arguments. Given number: {}'.format(num_args + num_kwargs))

        did = ''
        if num_args == 1:
            did = args[0]

            if num_kwargs == 1:
                if not isinstance(did, string_types):
                    raise DIDTypeError('First argument of constructor is expected to be string type'
                                       'when keyword argument is given. Given type: {}'.format(type(did)))

                k, v = next(iter(kwargs.items()))
                if k == 'scope':
                    did = (v, did)
                elif k == 'name':
                    did = (did, v)
                else:
                    raise DIDTypeError('Constructor got unexpected keyword argument: {}'.format(k))
        elif num_args == 0:
            did = kwargs.get('did', kwargs)
        else:
            did = args

        if isinstance(did, dict):
            self.scope = did.get('scope', '')
            self.name = did.get('name', '')
            if not self.has_scope():
                self.update_implicit_scope()
        elif isinstance(did, tuple) or isinstance(did, list):
            if len(did) != 2:
                raise DIDTypeError('Construction from tuple or list requires exactly 2 elements')
            self.scope = did[0]
            self.name = did[1]
        elif isinstance(did, string_types):
            did_parts = did.split(DIDType.SCOPE_SEPARATOR, 1)
            if len(did_parts) == 1:
                self.name = did
                self.update_implicit_scope()
                if not self.has_scope():
                    raise DIDTypeError('Object construction from non-splitable string is ambigious')
            else:
                self.scope = did_parts[0]
                self.name = did_parts[1]
        elif isinstance(did, DIDType):
            self.scope = did.scope
            self.name = did.name
        else:
            raise DIDTypeError('Cannot build object from: {}'.format(type(did)))

        if self.name.endswith('/'):
            self.name = self.name[:-1]

        if not self.is_valid_format():
            raise DIDTypeError('Object has invalid format after construction: {}'.format(str(self)))

    def update_implicit_scope(self):
        """
        This method sets the scope  if it is implicitly given in self.name
        """
        did_parts = self.name.split(DIDType.IMPLICIT_SCOPE_SEPARATOR)
        num_scope_parts = DIDType.IMPLICIT_SCOPE_TO_LEN.get(did_parts[0], 0)
        if num_scope_parts > 0:
            self.scope = '.'.join(did_parts[0:num_scope_parts])

    def is_valid_format(self):
        """
        Method to check if the stored DID has a valid format
        :return: bool
        """
        if self.scope.count(DIDType.SCOPE_SEPARATOR) or self.name.count(DIDType.SCOPE_SEPARATOR):
            return False
        return True

    def has_scope(self):
        """
        Method to check if the scope part was set
        :return: bool
        """
        return len(self.scope) > 0

    def has_name(self):
        """
        Method to check if the name part was set
        :return: bool
        """
        return len(self.name) > 0

    def __str__(self):
        """
        Creates the string representation of self
        :return: string
        """
        if self.has_scope() and self.has_name():
            return '{}{}{}'.format(self.scope, DIDType.SCOPE_SEPARATOR, self.name)
        elif self.has_scope():
            return self.scope
        return self.name

    def __eq__(self, other):
        """
        Equality comparison with another object
        :return: bool
        """
        if isinstance(other, string_types):
            return str(self) == other
        elif not isinstance(other, DIDType):
            try:
                other = DIDType(other)
            except DIDTypeError:
                return False

        return self.scope == other.scope and self.name == other.name

    def __ne__(self, other):
        """
        Inequality comparison with another object
        :return: bool
        """
        return not self.__eq__(other)

    def __hash__(self):
        """
        Uses the string representation of self to create a hash
        :return: int
        """
        return hash(str(self))
