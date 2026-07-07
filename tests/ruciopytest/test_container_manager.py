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

"""Lifecycle tests for container_manager.ContainerManager.

subprocess and the compose steps are replaced by stubs, so no Docker is needed.
"""

import json
from types import SimpleNamespace

import pytest

from tests.ruciopytest import container_manager
from tests.ruciopytest.container_manager import ContainerManager

STEPS = (
    "_register_cleanup_handlers", "_remove_stale_project", "_compose_build", "_compose_up",
    "_install_rucio_from_source", "_bootstrap_rucio_home", "_restart_httpd",
    "_wait_for_readiness", "_capture_logs", "_compose_down", "_restore_signal_handlers",
)


@pytest.fixture
def calls(monkeypatch):
    recorded = []
    for step in STEPS:
        monkeypatch.setattr(ContainerManager, step, lambda self, s=step: recorded.append(s))
    return recorded


def _manager(tmp_path, keep=False, running=False, monkeypatch=None):
    cm = ContainerManager("rucio-test-remote_dbs-postgres14", ("postgres14",), str(tmp_path), keep=keep)
    monkeypatch.setattr(ContainerManager, "_is_running", lambda self: running)
    return cm


def test_fresh_start_removes_only_its_own_stale_stack_and_starts(tmp_path, calls, monkeypatch) -> None:
    cm = _manager(tmp_path, monkeypatch=monkeypatch)
    cm.start()
    assert calls[:4] == ["_register_cleanup_handlers", "_remove_stale_project", "_compose_build", "_compose_up"]
    assert not cm.reused


def test_keep_reuses_a_running_stack(tmp_path, calls, monkeypatch) -> None:
    cm = _manager(tmp_path, keep=True, running=True, monkeypatch=monkeypatch)
    cm.start()
    assert calls == ["_register_cleanup_handlers", "_restart_httpd", "_wait_for_readiness"]
    assert cm.reused


def test_keep_starts_a_fresh_stack_when_none_is_running(tmp_path, calls, monkeypatch) -> None:
    cm = _manager(tmp_path, keep=True, running=False, monkeypatch=monkeypatch)
    cm.start()
    assert "_compose_up" in calls
    assert not cm.reused


@pytest.mark.parametrize("keep, torn_down", [(False, True), (True, False)])
def test_stop_tears_down_unless_kept(tmp_path, calls, monkeypatch, keep, torn_down) -> None:
    cm = _manager(tmp_path, keep=keep, monkeypatch=monkeypatch)
    cm.stop(capture_logs=False)
    assert ("_compose_down" in calls) is torn_down


def _compose_ls(monkeypatch, names):
    downs = []

    def fake_run(cmd, **kwargs):
        if cmd[:3] == ["docker", "compose", "ls"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"Name": n, "ConfigFiles": ""} for n in names]))
        assert cmd[-6:] == ["--profile", "*", "down", "-v", "-t", "10"], "every profile must be torn down"
        downs.append(cmd[cmd.index("-p") + 1])
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(container_manager.subprocess, "run", fake_run)
    return downs


def test_cleanup_all_removes_every_test_stack(monkeypatch) -> None:
    downs = _compose_ls(monkeypatch, ["rucio-test-a", "dev", "rucio-test-b"])
    assert ContainerManager.cleanup_all() == ["rucio-test-a", "rucio-test-b"]
    assert downs == ["rucio-test-a", "rucio-test-b"]


def test_stale_cleanup_leaves_parallel_stacks_alone(tmp_path, monkeypatch) -> None:
    downs = _compose_ls(monkeypatch, ["rucio-test-other", "rucio-test-remote_dbs-postgres14"])
    ContainerManager("rucio-test-remote_dbs-postgres14", ("postgres14",), str(tmp_path))._remove_stale_project()
    assert downs == ["rucio-test-remote_dbs-postgres14"]


def test_logs_are_streamed_to_the_file(tmp_path, monkeypatch) -> None:
    def fake_run(cmd, stdout=None, **kwargs):
        assert hasattr(stdout, "write"), "logs must go straight to the file handle"
        stdout.write("line\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(container_manager.subprocess, "run", fake_run)
    cm = ContainerManager("rucio-test-x", ("postgres14",), str(tmp_path))
    cm._stream_logs(tmp_path / "x.log", "rucio", timeout=5)
    assert (tmp_path / "x.log").read_text() == "line\n"
