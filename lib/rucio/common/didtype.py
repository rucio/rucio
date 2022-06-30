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

"""
DID type to represent a did and to simplify operations on it
"""

from rucio.common.exception import DIDError


class DID(object):

    """
    Class used to store a DID
    Given an object did of type DID
    scope is stored in did.scope
    name is stored in did.name
    """

    SCOPE_SEPARATOR = ':'
    IMPLICIT_SCOPE_SEPARATOR = '.'
    IMPLICIT_SCOPE_TO_LEN = {'user': 2, 'group': 2}
    __slots__ = ['scope', 'name']

    def __init__(self, *args, **kwargs):
        """
        Constructs the DID object. Possible parameter combinations are:
            DID()
            DID('scope:name.did.str')
            DID('user.implicit.scope.in.name')
            DID('custom.scope', 'custom.name')
            DID(['list.scope', 'list.name'])
            DID(('tuple.scope', 'tuple.name'))
            DID({'scope': 'dict.scope', 'name': 'dict.name'})
            DID(scope='kw.scope')
            DID(name='kw.name')
            DID(name='user.kw.implicit.scope')
            DID(scope='kw.scope', name='kw.name')
            DID(did={'scope': 'kw.did.scope', 'name': 'kw.did.name'})
            DID(did=['kw.list.scope', 'kw.list.name'])
            DID(did=('kw.tuple.scope', 'kw.tuple.name'))
            DID('arg.scope', name='kwarg.name')
            DID('arg.name', scope='kwarg.scope')
        """
        self.scope = self.name = ''

        num_args = len(args)
        num_kwargs = len(kwargs)
        if (num_args + num_kwargs) > 2:
            raise DIDError('Constructor takes at most 2 arguments. Given number: {}'.format(num_args + num_kwargs))

        did = ''
        if num_args == 1:
            did = args[0]

            if num_kwargs == 1:
                if not isinstance(did, str):
                    raise DIDError('First argument of constructor is expected to be string type'
                                   'when keyword argument is given. Given type: {}'.format(type(did)))

                k, v = next(iter(kwargs.items()))
                if k == 'scope':
                    did = (v, did)
                elif k == 'name':
                    did = (did, v)
                else:
                    raise DIDError('Constructor got unexpected keyword argument: {}'.format(k))
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
                raise DIDError('Construction from tuple or list requires exactly 2 elements')
            self.scope = did[0]
            self.name = did[1]
        elif isinstance(did, str):
            did_parts = did.split(DID.SCOPE_SEPARATOR, 1)
            if len(did_parts) == 1:
                self.name = did
                self.update_implicit_scope()
                if not self.has_scope():
                    raise DIDError('Object construction from non-splitable string is ambigious')
            else:
                self.scope = did_parts[0]
                self.name = did_parts[1]
        elif isinstance(did, DID):
            self.scope = did.scope
            self.name = did.name
        else:
            raise DIDError('Cannot build object from: {}'.format(type(did)))

        if self.name.endswith('/'):
            self.name = self.name[:-1]

        if not self.is_valid_format():
            raise DIDError('Object has invalid format after construction: {}'.format(str(self)))

    def update_implicit_scope(self):
        """
        This method sets the scope  if it is implicitly given in self.name
        """
        did_parts = self.name.split(DID.IMPLICIT_SCOPE_SEPARATOR)
        num_scope_parts = DID.IMPLICIT_SCOPE_TO_LEN.get(did_parts[0], 0)
        if num_scope_parts > 0:
            self.scope = '.'.join(did_parts[0:num_scope_parts])

    def is_valid_format(self):
        """
        Method to check if the stored DID has a valid format
        :return: bool
        """
        if self.scope.count(DID.SCOPE_SEPARATOR) or self.name.count(DID.SCOPE_SEPARATOR):
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
            return '{}{}{}'.format(self.scope, DID.SCOPE_SEPARATOR, self.name)
        elif self.has_scope():
            return self.scope
        return self.name

    def __eq__(self, other):
        """
        Equality comparison with another object
        :return: bool
        """
        if isinstance(other, str):
            return str(self) == other
        elif not isinstance(other, DID):
            try:
                other = DID(other)
            except DIDError:
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
