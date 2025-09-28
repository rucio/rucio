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
import os

import pytest

import rucio.common.exception
import rucio.common.schema
import rucio.core.permission
from rucio.common.constants import DEFAULT_VO
from rucio.common.plugins import PolicyPackageAlgorithms
from rucio.common.types import InternalAccount


class TestPolicyPackageGeneric:

    @classmethod
    def setup_class(cls):
        # TODO: remove this after the generic schema becomes the default one used in tests (https://github.com/rucio/rucio/issues/7819)
        cls._rucio_default_vo_module = rucio.common.schema.schema_modules[DEFAULT_VO]
        rucio.common.schema.schema_modules[DEFAULT_VO] = importlib.import_module('rucio.common.schema.generic')

    @classmethod
    def teardown_class(cls):
        # TODO: remove this after the generic schema becomes the default one used in tests (https://github.com/rucio/rucio/issues/7819)
        rucio.common.schema.schema_modules[DEFAULT_VO] = cls._rucio_default_vo_module

    @pytest.mark.parametrize("name", [
        'name_with_underscore',
        'name-with-dash',
        'name.with.dot',
        'name/with/slash',
        '/name/starting/with/slash',
        'name/ending/with/slash/',
    ])
    def test_default_schema_did_name_valid(self, name, file_config_mock):
        rucio.common.schema.validate_schema('name', name, vo=DEFAULT_VO)

    @pytest.mark.parametrize("name", [
        '.startingWithDot',
        '-startingWithDash',
        '_startingWithUnderscore',
        '#hash',
        'name with spaces',
        'name*with*asterisk',
        'name\\with\\backslash',
        'name:with:colon',
        'name,with,comma',
    ])
    def test_default_schema_did_name_invalid(self, name, file_config_mock):
        with pytest.raises(rucio.common.exception.InvalidObject):
            rucio.common.schema.validate_schema('name', name, vo=DEFAULT_VO)


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
        # replace schema module with our mock one
        old_module = rucio.common.schema.schema_modules['def']
        rucio.common.schema.schema_modules['def'] = importlib.import_module('tests.mocks.schema_diff')

        # check that overriden value is as expected
        assert rucio.common.schema.get_schema_value('SCOPE_LENGTH') == 50

        # check that omitted value falls back to generic module
        assert rucio.common.schema.get_schema_value('NAME_LENGTH') == 250

        # check that schemas defined in our module override generic
        rucio.common.schema.validate_schema('account', 'this-account-name-is-too-long-for-the-generic-schema-but-should-validate-against-the-mock-one')

        # check that schemas not defined in our module fall back to generic
        rucio.common.schema.validate_schema('r_name', 'name_to_validate')

        # restore original schema module
        rucio.common.schema.schema_modules['def'] = old_module

    @pytest.mark.noparallel(reason='changes environment variable')
    # test that a default algorithm will be loaded correctly
    def test_default_algorithm(self):
        # replace policy package in environment with our mock one
        old_pp_env = os.environ['RUCIO_POLICY_PACKAGE'] if 'RUCIO_POLICY_PACKAGE' in os.environ else None
        os.environ['RUCIO_POLICY_PACKAGE'] = 'tests.mocks.policy_package_algorithm'

        # retrieve default scope extraction algorithm
        algo = PolicyPackageAlgorithms._get_default_algorithm('scope')

        # call it to check we get the expected result
        assert algo('did') == 'Default scope algorithm loaded correctly!'

        # restore original policy package environment variable
        if old_pp_env is not None:
            os.environ['RUCIO_POLICY_PACKAGE'] = old_pp_env
        else:
            del os.environ['RUCIO_POLICY_PACKAGE']
