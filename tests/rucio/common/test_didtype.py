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

import pytest

from rucio.common.didtype import DID
from rucio.common.exception import DIDError


class TestDIDType:
    @pytest.mark.parametrize(
        'input_did,expected_scope,expected_name',
        [
            (DID(), '', ''),
            (DID('test.scope:test.name'), 'test.scope', 'test.name'),
            (DID('user.implicit.scope.in.name'), 'user.implicit', 'user.implicit.scope.in.name'),
            (DID('test.scope', 'test.name'), 'test.scope', 'test.name'),
            (DID(['test.scope', 'test.name']), 'test.scope', 'test.name'),
            (DID(('test.scope', 'test.name')), 'test.scope', 'test.name'),
            (DID({'scope': 'test.scope', 'name': 'test.name'}), 'test.scope', 'test.name'),
            (DID(scope='test.scope', name='test.name'), 'test.scope', 'test.name'),
            (DID(scope='test.scope'), 'test.scope', ''),
            (DID(name='test.name'), '', 'test.name'),
            (DID(name='user.kw.implicit.scope'), 'user.kw', 'user.kw.implicit.scope'),
            (DID(did=['test.scope', 'test.name']), 'test.scope', 'test.name'),
            (DID(did=('test.scope', 'test.name')), 'test.scope', 'test.name'),
            (DID(did={'scope': 'test.scope', 'name': 'test.name'}), 'test.scope', 'test.name'),
            (DID('test.scope', name='test.name'), 'test.scope', 'test.name'),
            (DID('test.name', scope='test.scope'), 'test.scope', 'test.name'),
        ],
        ids=[
            'empty_did',
            'string',
            'string_implicit_scope_in_name',
            'args',
            'list',
            'tuple',
            'dict',
            'kwarg_scope_name',
            'single_kwarg_scope',
            'single_kwarg_name',
            'kwarg_implicit_scope_in_name',
            'kwarg_list',
            'kwarg_tuple',
            'kwarg_dict',
            'arg_scope_kwarg_name',
            'arg_name_kwarg_scope'
        ])
    def test_did_type_success(self, input_did, expected_scope, expected_name):
        assert input_did.scope == expected_scope
        assert input_did.name == expected_name

    def test_non_implicit_single_string(self):
        with pytest.raises(DIDError, match='Error using DID type\nDetails: Object construction from non-splitable string is ambigious'):
            DID('non.implicit.single.string')

    def test_copy(self):
        x = DID('test.scope:test.name')
        y = DID(x)
        assert x == y

    def test_invalid_format_during_construction(self):
        with pytest.raises(DIDError, match='Error using DID type\nDetails: Object has invalid format after construction: invalid:user.implicit:user:invalid'):
            DID('invalid', 'user.implicit:user:invalid')
