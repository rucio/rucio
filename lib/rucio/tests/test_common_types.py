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

import unittest

from rucio.common.config import config_get_bool
from rucio.common.types import InternalScope, InternalAccount, InternalType
from rucio.tests.common_server import get_vo


class TestInternalType(unittest.TestCase):
    ''' Test the base InternalType class '''

    def setUp(self):
        ''' INTERNAL TYPES: Setup the tests '''
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

        self.base = InternalType('test', **self.vo)
        self.same = InternalType('test', **self.vo)
        self.diff = InternalType('different', **self.vo)

        self.base_account = InternalAccount('test', **self.vo)
        self.base_scope = InternalScope('test', **self.vo)

    def test_equality(self):
        ''' INTERNAL TYPES: Equality '''
        equal = self.base == self.same
        assert equal

        identical = self.base is self.same
        assert not identical

        different = self.base != self.diff
        assert different

        equal = (self.base.internal == self.same.internal) \
            & (self.base.external == self.same.external)
        assert equal

        different = (self.base.internal != self.diff.internal) \
            & (self.base.external != self.diff.external)
        assert different

        different = self.base_account != self.base_scope
        assert different

    def test_conversion(self):
        ''' INTERNAL TYPES: Conversion '''
        internal = self.base.internal
        from_internal = InternalType(internal, fromExternal=False)

        equal = self.base == from_internal
        assert equal

    def test_str_rep(self):
        ''' INTERNAL TYPES: Representation '''
        base_str = '%s' % self.base
        equal = base_str == self.base.external
        assert equal
