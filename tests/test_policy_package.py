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

import importlib
from configparser import NoOptionError, NoSectionError

import pytest

import rucio.common.config
import rucio.common.schema
import rucio.core.permission
from rucio.common.types import InternalAccount


class TestPolicyPackage:

    @pytest.mark.noparallel(reason='changes global permission modules dictionary')
    # test that permission modules can implement a subset of actions and
    # fall back to generic for others
    def test_diff_based_permission(self):
        # replace permission module
        old_module = rucio.core.permission.permission_modules['def']
        rucio.core.permission.permission_modules['def'] = importlib.import_module('tests.mocks.permission_diff')

        # check that overridden action works as expected
        root_account = InternalAccount('root')
        assert not rucio.core.permission.has_permission(root_account, 'add_account', {})

        # check that omitted action falls back to generic module
        # root should be allowed to add RSE
        assert rucio.core.permission.has_permission(root_account, 'add_rse', {})

        # restore original permission module
        rucio.core.permission.permission_modules['def'] = old_module

    @pytest.mark.noparallel(reason='changes global schema modules dictionary')
    # test that schema modules can define a subset of values and fall back
    # to generic for others
    def test_diff_based_schema(self):
        # determine whether multi VO enabled, schema contents are different if so
        multivo = False
        try:
            multivo = rucio.common.config.config_get_bool('common', 'multi_vo', check_config_table=False)
        except (NoOptionError, NoSectionError):
            pass

        # replace schema module with our mock one
        old_module = rucio.common.schema.schema_modules['def']
        rucio.common.schema.schema_modules['def'] = importlib.import_module('tests.mocks.schema_diff')

        # check that overriden value is as expected
        assert rucio.common.schema.get_schema_value('SCOPE_LENGTH') == 50

        # check that omitted value falls back to generic module
        assert rucio.common.schema.get_schema_value('NAME_LENGTH') == 250

        # check that we can include a value from the fallback schema in our schema
        assert rucio.common.schema.get_schema_value('NAME')['maxLength'] == 250

        # check simple arithmetic on substitutions
        assert rucio.common.schema.get_schema_value('ARITHMETIC_TEST') == 54

        # check that the fallback schema can include a value from our schema
        expected_account_length = 26 if multivo else 30
        assert rucio.common.schema.get_schema_value('ACCOUNT')['maxLength'] == expected_account_length

        # restore original schema module
        rucio.common.schema.schema_modules['def'] = old_module
