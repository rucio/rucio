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

from rucio.common.types import InternalScope, InternalAccount, InternalType


class TestInternalType:
    """ Test the base InternalType class """

    def test_equality(self, vo):
        """ INTERNAL TYPES: Equality """
        base = InternalType('test', vo=vo)
        same = InternalType('test', vo=vo)
        diff = InternalType('different', vo=vo)

        base_account = InternalAccount('test', vo=vo)
        base_scope = InternalScope('test', vo=vo)

        assert base == same
        assert base is not same
        assert base != diff
        assert (base.internal == same.internal) \
               & (base.external == same.external)
        assert (base.internal != diff.internal) \
               & (base.external != diff.external)
        assert base_account != base_scope

    def test_conversion(self, vo):
        """ INTERNAL TYPES: Conversion """
        base = InternalType('test', vo=vo)
        internal = base.internal
        from_internal = InternalType(internal, fromExternal=False)
        assert base == from_internal

    def test_str_rep(self, vo):
        """ INTERNAL TYPES: Representation """
        base = InternalType('test', vo=vo)
        base_str = '%s' % base
        assert base_str == base.external
