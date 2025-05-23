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
from unittest.mock import MagicMock, Mock, patch

import pytest
from packaging.specifiers import SpecifierSet

from rucio.common.exception import PolicyPackageIsNotVersioned, PolicyPackageVersionError
from rucio.common.plugins import _get_supported_versions_from_policy_package, check_policy_package_version


class TestPolicyPackageVersion:
    def test_get_supported_versions_from_policy_package_not_versioned(self):
        package = 'unversioned_package'
        module = Mock()
        module.__name__ = package
        delattr(module, 'SUPPORTED_VERSION')
        assert not hasattr(module, 'SUPPORTED_VERSION')
        with pytest.raises(PolicyPackageIsNotVersioned) as e:
            _get_supported_versions_from_policy_package(module)
        assert e.value.package == package

    @pytest.mark.parametrize(
        'module_version,expected_version',
        [
            ('==1.0', SpecifierSet('==1.0')),
            (['>1.0', '!=2.0'], SpecifierSet('>1.0,!=2.0'))
        ],
        ids=['version_as_str', 'version_as_list']
    )
    def test_get_supported_versions_from_policy_package(self, module_version, expected_version):
        module = MagicMock()
        module.SUPPORTED_VERSION = module_version
        assert _get_supported_versions_from_policy_package(module) == expected_version

    @pytest.mark.parametrize('raised_exception', [
        ImportError,
        PolicyPackageIsNotVersioned('bad_package')
    ])
    def test_check_policy_package_version_exceptions(self, raised_exception):
        package = 'bad_package'
        with patch('rucio.common.plugins._get_supported_versions_from_policy_package', side_effect=raised_exception):
            assert check_policy_package_version(package) is None

    def test_check_policy_package_version_supported(self):
        package = 'supported_package'
        with patch('rucio.common.plugins._get_supported_versions_from_policy_package', return_value=SpecifierSet('>=1.0,!=2.0')):
            with patch('rucio.common.plugins.current_version', return_value='1.7'):
                assert check_policy_package_version(package) is None

    def test_check_policy_package_version_unsupported(self):
        package = 'unsupported_package'
        supported_versions = '>=1.0,!=3.0'
        rucio_version = '3.0'
        module = Mock()
        module.__name__ = package
        module.SUPPORTED_VERSION = supported_versions
        with patch('rucio.common.plugins.current_version', return_value=rucio_version):
            with patch('importlib.import_module', return_value=module):
                with pytest.raises(PolicyPackageVersionError) as e:
                    check_policy_package_version(package)
                assert e.value.package == package
                assert e.value.rucio_version == rucio_version
                assert e.value.supported_versionset == SpecifierSet(supported_versions)
