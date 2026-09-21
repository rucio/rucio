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

"""End-to-end wiring test for the votest branch of pytest_configure.

Drives ``plugin.pytest_configure`` with a FAKE minimal pytest.Config (no live
pytest session, no rucio import, no container) and asserts the
configure -> stash -> test_paths wiring produces a votest SuiteProfile whose
test_paths has exactly 36 entries for atlas (SUIT-07 guard).
"""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.ruciopytest import plugin, suite_profile_key

REPO_ROOT = Path(__file__).resolve().parents[2]


class _FakePluginManager:
    """Inert plugin manager: nothing is registered or has a plugin."""

    def hasplugin(self, name):
        return False

    def register(self, *args, **kwargs):
        return None

    def get_plugin(self, name):
        return None


class _FakeConfig:
    """Minimal pytest.Config exposing only what the votest block touches."""

    def __init__(self, policy):
        self._opts = {
            "suite": "votest",
            "infra": None,
            "dry_run": False,
            "dry_run_json": False,
            "policy": policy,
            "keep-db": False,
            "run_in_container": None,
        }
        self.rootpath = REPO_ROOT
        self.rootdir = REPO_ROOT
        self.stash = pytest.Stash()
        self.option = SimpleNamespace(dry_run=False)
        self.pluginmanager = _FakePluginManager()
        self.args = ["tests/"]

    def getoption(self, name, default=None):
        key = name.lstrip("-")
        return self._opts.get(key, default)


def _make_inert(monkeypatch):
    # Exercise only the profile-build + stash path, never container setup.
    monkeypatch.setattr(plugin, "_should_forward_to_container", lambda c, p: False)
    monkeypatch.setattr(plugin, "configure_xdist", lambda c, p: None)
    monkeypatch.setattr(plugin, "_print_profile_summary", lambda c, p: None)
    # Force the container probe false. Deleting RUCIO_SOURCE_DIR is NOT enough:
    # inside the rucio container /.dockerenv exists, so pytest_configure would
    # take the in-container branch, build a real InfraManager and purge the LIVE
    # database out from under the run.
    monkeypatch.setattr(plugin, "_detect_in_container", lambda: False)
    # pytest_configure writes os.environ["RUCIO_HOME"/"POLICY"/"SUITE"] directly,
    # and monkeypatch.delenv on an ABSENT var records nothing to undo -- so those
    # writes would escape this test into the worker environment. Swap in a private
    # copy of the environment; monkeypatch restores the original attribute after.
    # Safe: these inert tests spawn no subprocesses.
    monkeypatch.setattr(os, "environ", dict(os.environ))
    monkeypatch.delenv("RUCIO_SOURCE_DIR", raising=False)
    monkeypatch.delenv("POLICY", raising=False)


def test_votest_configure_stashes_atlas_test_paths(monkeypatch):
    _make_inert(monkeypatch)
    config = _FakeConfig(policy="atlas")

    plugin.pytest_configure(config)

    prof = config.stash[suite_profile_key]
    assert prof.name == "votest"
    assert prof.policy == "atlas"
    assert prof.test_paths, "no test paths stashed for atlas"
    assert all(p.startswith("tests/") for p in prof.test_paths)
    assert all(p.endswith(".py") for p in prof.test_paths)
    # POLICY exported for the forwarded in-container run.
    assert os.environ.get("POLICY") == "atlas"


def test_votest_configure_missing_policy_raises(monkeypatch):
    _make_inert(monkeypatch)
    config = _FakeConfig(policy=None)

    with pytest.raises(pytest.UsageError):
        plugin.pytest_configure(config)
