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

"""Tests for :func:`collection.pytest_ignore_collect`.

Host-side suites must not import test modules outside their ``test_paths``:
on the host those modules can fail at import time (no server configuration),
which aborts collection before deselection runs. Forwarded and marker-based
suites keep the default collection.
"""

from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from tests.ruciopytest import suite_profile_key
from tests.ruciopytest.collection import pytest_ignore_collect
from tests.ruciopytest.profiles import SUITE_PROFILES

if TYPE_CHECKING:
    from pathlib import Path


def _config(tmp_path: "Path", profile=None) -> SimpleNamespace:
    stash = pytest.Stash()
    if profile is not None:
        stash[suite_profile_key] = profile
    return SimpleNamespace(stash=stash, rootpath=tmp_path)


def _module(tmp_path: "Path", rel: str) -> "Path":
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# synthetic\n")
    return path


def test_client_suite_skips_modules_outside_test_paths(tmp_path) -> None:
    config = _config(tmp_path, SUITE_PROFILES["client"])
    assert pytest_ignore_collect(_module(tmp_path, "tests/test_trace.py"), config) is True


def test_client_suite_collects_its_own_modules(tmp_path) -> None:
    config = _config(tmp_path, SUITE_PROFILES["client"])
    for rel in SUITE_PROFILES["client"].test_paths:
        assert pytest_ignore_collect(_module(tmp_path, rel), config) is None


def test_directories_and_non_python_files_are_left_alone(tmp_path) -> None:
    config = _config(tmp_path, SUITE_PROFILES["client"])
    (tmp_path / "tests").mkdir()
    assert pytest_ignore_collect(tmp_path / "tests", config) is None
    assert pytest_ignore_collect(_module(tmp_path, "tests/data.txt"), config) is None


def test_node_id_test_paths_keep_their_module(tmp_path) -> None:
    profile = replace(SUITE_PROFILES["client"], test_paths=("tests/test_clients.py::TestBaseClient",))
    config = _config(tmp_path, profile)
    assert pytest_ignore_collect(_module(tmp_path, "tests/test_clients.py"), config) is None


@pytest.mark.parametrize("suite", ["remote_dbs", "multi_vo", "votest"])
def test_forwarded_suites_are_not_narrowed(tmp_path, suite) -> None:
    config = _config(tmp_path, SUITE_PROFILES[suite])
    assert pytest_ignore_collect(_module(tmp_path, "tests/test_trace.py"), config) is None


def test_marker_selected_suites_are_not_narrowed(tmp_path) -> None:
    profile = replace(SUITE_PROFILES["client"], markers=("noparallel",))
    config = _config(tmp_path, profile)
    assert pytest_ignore_collect(_module(tmp_path, "tests/test_trace.py"), config) is None


def test_dormant_plugin_does_not_narrow(tmp_path) -> None:
    assert pytest_ignore_collect(_module(tmp_path, "tests/test_trace.py"), _config(tmp_path)) is None
