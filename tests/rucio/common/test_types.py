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

from rucio.common.types import InternalAccount, InternalScope, InternalType, _RepresentationCalculator


class TestInternalType:
    base = InternalType('test')

    @pytest.mark.parametrize(
        'input_value,input_vo,input_from_external,expected_external,expected_internal,expected_vo',
        [
            (None, 'test_vo', False, None, None, 'test_vo'),
            (None, 'test_vo', True, None, None, 'test_vo'),
            ('test_value', 'test_vo', True, 'test_value', 'test_value@test_vo', 'test_vo'),
            ('test_value', 'test_vo', False, 'test_value', 'test_value', 'def'),
        ],
        ids=[
            'empty',
            'empty_from_external',
            'from_external',
            'from_internal',
        ]
    )
    def test_init(self, input_value, input_vo, input_from_external, expected_external, expected_internal, expected_vo):
        internal_type = InternalType(value=input_value, vo=input_vo, from_external=input_from_external)
        assert internal_type.external == expected_external
        assert internal_type.internal == expected_internal
        assert internal_type.vo == expected_vo

    def test_eq(self):
        same = InternalType('test')
        assert self.base == same

    def test_eq_not_implemented(self):
        assert self.base != 5

    def test_ne(self):
        different = InternalType('different')
        assert self.base != different

    @pytest.mark.parametrize(
        'input_value_less',
        ['test', 'test2', ]
    )
    def test_le(self, input_value_less):
        less = InternalType(input_value_less)
        assert self.base <= less

    def test_lt(self):
        less = InternalType('test2')
        assert self.base < less

    @pytest.mark.parametrize(
        'in_base,in_other',
        [
            (InternalType(None), InternalType(None)),
            (InternalType('test'), InternalType(None)),
            (InternalType(None), InternalType('test')),
            (InternalType('test'), InternalAccount('test')),
        ]
    )
    def test_le_not_implemented(self, in_base, in_other):
        with pytest.raises(TypeError):
            assert in_base <= in_other

    @pytest.mark.parametrize(
        'in_base,in_other',
        [
            (InternalType(None), InternalType(None)),
            (InternalType('test'), InternalType(None)),
            (InternalType(None), InternalType('test')),
            (InternalType('test'), InternalAccount('test')),
        ]
    )
    def test_lt_not_implemented(self, in_base, in_other):
        with pytest.raises(TypeError):
            assert in_base < in_other

    def test_conversion(self):
        internal = self.base.internal
        from_internal = InternalType(internal, from_external=False)
        assert self.base == from_internal

    def test_repr(self):
        assert repr(self.base) == self.base.internal

    def test_str(self):
        assert str(self.base) == self.base.external

    def test_hash(self):
        assert hash(self.base) == hash(self.base.internal)


class TestRepresentationCalculator:
    @pytest.mark.parametrize('input_internal,expected_vo,expected_external', [
        ('test_name', 'def', 'test_name'),
        ('test_name@test_vo', 'test_vo', 'test_name'),
        ('test_name@test_vo@extra_string', 'test_vo@extra_string', 'test_name'),
    ])
    def test_calc_external(self, input_internal, expected_vo, expected_external):
        vo, external = _RepresentationCalculator.calc_external(input_internal)
        assert vo == expected_vo
        assert external == expected_external

    @pytest.mark.parametrize('input_external,input_vo,expected_internal', [
        ('test_name', 'def', 'test_name'),
        ('test_name', 'test_vo', 'test_name@test_vo'),
    ])
    def test_calc_internal(self, input_external, input_vo, expected_internal):
        assert _RepresentationCalculator.calc_internal(input_external, input_vo) == expected_internal


class TestInternalAccount:
    @pytest.mark.parametrize('input_account,input_from_external,expected_external,expected_internal', [
        (None, False, None, None),
        (None, True, None, None),
        ('test', False, 'test', 'test'),
        ('test', True, 'test', 'test'),
    ])
    def test_init(self, input_account, input_from_external, expected_external, expected_internal):
        internal_account = InternalAccount(account=input_account, from_external=input_from_external)
        assert internal_account.external == expected_external
        assert internal_account.internal == expected_internal


class TestInternalScope:
    @pytest.mark.parametrize('input_scope,input_from_external,expected_external,expected_internal', [
        (None, False, None, None),
        (None, True, None, None),
        ('test', False, 'test', 'test'),
        ('test', True, 'test', 'test'),
    ])
    def test_init(self, input_scope, input_from_external, expected_external, expected_internal):
        internal_scope = InternalScope(scope=input_scope, from_external=input_from_external)
        assert internal_scope.external == expected_external
        assert internal_scope.internal == expected_internal
