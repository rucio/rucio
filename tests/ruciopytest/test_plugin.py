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

"""Option handling tests for plugin.pytest_configure()."""

from types import SimpleNamespace

import pytest

from tests.ruciopytest import plugin


def _config(**options) -> SimpleNamespace:
    return SimpleNamespace(
        getoption=lambda name, default=None: options.get(name, default),
        option=SimpleNamespace(),
    )


def test_infra_without_suite_is_a_usage_error() -> None:
    with pytest.raises(pytest.UsageError, match="needs --suite"):
        plugin.pytest_configure(_config(infra="postgres14"))


def test_plugin_is_dormant_without_suite() -> None:
    assert plugin.pytest_configure(_config()) is None


def test_keep_db_on_the_host_needs_keep_containers() -> None:
    with pytest.raises(pytest.UsageError, match="--keep-containers"):
        plugin._check_keep_flags(keep_db=True, keep_containers=False)
    plugin._check_keep_flags(keep_db=True, keep_containers=True)
    plugin._check_keep_flags(keep_db=False, keep_containers=False)
