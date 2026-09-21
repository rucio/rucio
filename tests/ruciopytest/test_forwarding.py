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

"""Unit tests for the Docker-free forwarding transport core.

These tests cover the pure, unit-testable pieces of the container forwarder:
serialize -> JSON-lines -> replay round-trips, host-only argv filtering, exit-code
mirroring, and curated env-flag construction. No live Docker daemon is required.

Hook signatures (verified against the repo-pinned pytest 7.4.x, _pytest/hookspec.py):
    pytest_report_to_serializable(config, report) -> dict
    pytest_report_from_serializable(config, data) -> report | None
Both accept ``config=`` as a keyword, so forwarding.py calls them with config=...
"""

import json
import types

import _pytest.config
import pytest

from tests.ruciopytest import forwarding
from tests.ruciopytest.forwarding import (
    REPORT_STREAM_ENV,
    ReportStreamEmitter,
    build_env_flags,
    build_forward_xdist_args,
    build_inner_pytest_args,
    make_emitter_from_env,
    mirror_exit_code,
    replay_report_line,
)
from tests.ruciopytest.profiles import resolve_profile

pytest_plugins = ["pytester"]


# Helpers: obtain REAL TestReport objects via an in-process pytest run.

class _ReportRecorder:
    """A plugin that records every TestReport / CollectReport it receives."""

    def __init__(self):
        self.test_reports = []
        self.collect_reports = []

    def pytest_runtest_logreport(self, report):
        self.test_reports.append(report)

    def pytest_collectreport(self, report):
        self.collect_reports.append(report)


def _run_inline_and_collect(pytester, source):
    """Run an inline test module in a nested in-process pytest, return its recorder.

    The recorder holds the real TestReport / CollectReport objects the nested run
    produced.

    Serialization and replay below must NOT use the outer, still-live session
    config (``pytester._request.config``). The to/from_serializable hooks are
    indeed config-agnostic for these report types, but ``replay_report_line``
    ends by BROADCASTING the report over ``config.hook.pytest_runtest_logreport``
    -- to every plugin registered on that config. Under xdist the outer config is
    a worker config carrying xdist's ``WorkerInteractor``, whose hookimpl asserts
    the report's nodeid matches the item it currently believes is running; a
    replayed (synthetic) nodeid trips that assertion and the test dies under
    ``-n`` while passing serially. Use the isolated ``replay_config`` fixture,
    which owns a private plugin manager no live session listens on.
    """
    pytester.makepyfile(source)
    recorder = _ReportRecorder()
    pytester.runpytest_inprocess("-p", "no:cacheprovider", plugins=[recorder])
    return recorder


@pytest.fixture()
def replay_config():
    """Isolated config for report replay: default plugins, no xdist worker."""
    pm = _pytest.config.get_plugin_manager()
    return types.SimpleNamespace(hook=pm.hook, pluginmanager=pm)


@pytest.fixture()
def call_reports(pytester, replay_config):
    """Return (config, calls): real "call"-phase TestReports (one pass, one fail).

    ``config`` is the isolated ``replay_config`` used for serialize/deserialize
    and dispatch; ``pytester`` only produces the real reports via an inline run.
    """
    recorder = _run_inline_and_collect(
        pytester,
        """
        def test_alpha_pass():
            assert True

        def test_beta_fail():
            assert False
        """,
    )
    calls = [r for r in recorder.test_reports if r.when == "call"]
    return replay_config, calls


# Behavior 1: round-trip serialize -> json -> deserialize (1:1 fidelity).

def test_roundtrip_preserves_nodeid_outcome_when(call_reports):
    config, calls = call_reports
    assert calls, "expected at least one call-phase report"

    for report in calls:
        data = config.hook.pytest_report_to_serializable(config=config, report=report)
        # Survive a true JSON encode/decode (the transport is JSON lines).
        data = json.loads(json.dumps(data))
        restored = config.hook.pytest_report_from_serializable(config=config, data=data)

        assert restored is not None
        assert restored.nodeid == report.nodeid
        assert restored.when == report.when
        assert restored.outcome == report.outcome


def test_roundtrip_failure_preserves_longrepr(call_reports):
    config, calls = call_reports
    failing = [r for r in calls if r.outcome == "failed"]
    assert failing, "expected a failing call report"
    report = failing[0]

    data = config.hook.pytest_report_to_serializable(config=config, report=report)
    data = json.loads(json.dumps(data))
    restored = config.hook.pytest_report_from_serializable(config=config, data=data)

    assert restored.longrepr is not None
    # Renders without raising (terminal/junit consume it on the host side).
    assert str(restored.longrepr)


def test_replay_skip_report_restores_longrepr_tuple(pytester, replay_config):
    """A skipped report's (path, lineno, reason) longrepr must replay as a tuple.

    Regression: JSON has no tuples, so the core round-trip restores a skip
    report's longrepr as a list. pytest's terminal reporter asserts
    ``isinstance(report.longrepr, tuple)`` (``_get_raw_skip_reason``), so an
    un-normalized list crashes the whole host session with an INTERNALERROR the
    moment any container test is skipped/xfailed. ``replay_report_line`` must
    hand the host a tuple-shaped longrepr.
    """
    recorder = _run_inline_and_collect(
        pytester,
        """
        import pytest

        def test_skipme():
            pytest.skip("nope")
        """,
    )
    config = replay_config
    skips = [r for r in recorder.test_reports if r.skipped and r.when == "call"]
    assert skips, "expected a skipped call report"
    line = _serialize_line(config, skips[0])

    sink = _ReportRecorder()
    config.pluginmanager.register(sink, name="skip-sink-test")
    try:
        session = type("S", (), {"config": config})()
        dispatched = replay_report_line(session, line)
    finally:
        config.pluginmanager.unregister(name="skip-sink-test")

    assert dispatched is True
    assert len(sink.test_reports) == 1
    replayed = sink.test_reports[0]
    assert replayed.skipped
    assert isinstance(replayed.longrepr, tuple)
    assert len(replayed.longrepr) == 3


# Behavior 2: replay_report_line re-dispatches via the right hook.

def _serialize_line(config, report):
    data = config.hook.pytest_report_to_serializable(config=config, report=report)
    return json.dumps(data)


def test_replay_dispatches_testreport_once(call_reports, monkeypatch):
    config, calls = call_reports
    report = calls[0]
    line = _serialize_line(config, report)

    recorder = _ReportRecorder()
    # Build a tiny session-like object exposing config with our recorder registered.
    config.pluginmanager.register(recorder, name="replay-recorder-test")
    try:
        session = type("S", (), {"config": config})()
        dispatched = replay_report_line(session, line)
    finally:
        config.pluginmanager.unregister(name="replay-recorder-test")

    assert dispatched is True
    assert len(recorder.test_reports) == 1
    assert recorder.test_reports[0].nodeid == report.nodeid
    assert recorder.collect_reports == []


def test_replay_dispatches_collectreport(pytester, replay_config):
    # Produce a real CollectReport by running a tiny module and capturing collect.
    recorder = _run_inline_and_collect(
        pytester,
        """
        def test_gamma():
            assert True
        """,
    )
    config = replay_config
    assert recorder.collect_reports, "expected a collect report"
    creport = recorder.collect_reports[0]
    line = _serialize_line(config, creport)

    sink = _ReportRecorder()
    config.pluginmanager.register(sink, name="collect-sink-test")
    try:
        session = type("S", (), {"config": config})()
        dispatched = replay_report_line(session, line)
    finally:
        config.pluginmanager.unregister(name="collect-sink-test")

    assert dispatched is True
    assert len(sink.collect_reports) == 1


def test_replay_blank_line_is_noop(call_reports):
    config, _calls = call_reports
    sink = _ReportRecorder()
    config.pluginmanager.register(sink, name="blank-sink-test")
    try:
        session = type("S", (), {"config": config})()
        assert replay_report_line(session, "") is False
        assert replay_report_line(session, "   \n") is False
    finally:
        config.pluginmanager.unregister(name="blank-sink-test")
    assert sink.test_reports == []
    assert sink.collect_reports == []


# Behavior 3: 1:1 mapping, never collapse N reports into one wrapper.

def test_replay_three_reports_yields_three_distinct_dispatches(pytester, replay_config):
    recorder = _run_inline_and_collect(
        pytester,
        """
        def test_one():
            assert True

        def test_two():
            assert True

        def test_three():
            assert True
        """,
    )
    config = replay_config
    calls = [r for r in recorder.test_reports if r.when == "call"]
    assert len(calls) == 3

    lines = [_serialize_line(config, r) for r in calls]

    sink = _ReportRecorder()
    config.pluginmanager.register(sink, name="three-sink-test")
    try:
        session = type("S", (), {"config": config})()
        for line in lines:
            assert replay_report_line(session, line) is True
    finally:
        config.pluginmanager.unregister(name="three-sink-test")

    assert len(sink.test_reports) == 3
    nodeids = {r.nodeid for r in sink.test_reports}
    assert len(nodeids) == 3  # never collapsed into a single wrapper


# Behavior 4: build_inner_pytest_args strips only host-only flags.

def test_build_inner_args_strips_host_only_split_form():
    argv = [
        "--suite=remote_dbs",
        "--no-run-in-container",
        "--container-env",
        "A=1",
        "-k",
        "foo",
        "-v",
        "tests/test_x.py",
    ]
    assert build_inner_pytest_args(argv) == [
        "--suite=remote_dbs",
        "-k",
        "foo",
        "-v",
        "tests/test_x.py",
    ]


def test_build_inner_args_strips_attached_and_run_in_container():
    argv = [
        "--run-in-container",
        "--container-env=A=1",
        "--suite=client",
        "-m",
        "noparallel",
        "tests/test_y.py",
    ]
    assert build_inner_pytest_args(argv) == [
        "--suite=client",
        "-m",
        "noparallel",
        "tests/test_y.py",
    ]


def test_build_inner_args_passes_everything_else_through():
    # --junitxml is host-only (host owns the mounted path; the container must not
    # also write there). Everything else flows through in order.
    argv = ["--co", "--dry-run", "-x", "-vv", "tests/"]
    assert build_inner_pytest_args(argv) == argv


def test_build_inner_args_strips_junitxml_attached_and_split():
    # Attached form is dropped.
    assert build_inner_pytest_args(
        ["--suite=remote_dbs", "--junitxml=test-results/remote_dbs.xml", "tests/"]
    ) == ["--suite=remote_dbs", "tests/"]
    # Split form drops both the flag and its path value.
    assert build_inner_pytest_args(
        ["--suite=remote_dbs", "--junitxml", "test-results/remote_dbs.xml", "tests/"]
    ) == ["--suite=remote_dbs", "tests/"]


# Behavior 5: mirror_exit_code surfaces the exact container returncode.

@pytest.mark.parametrize("code", [0, 1, 2, 3, 4, 5])
def test_mirror_exit_code_is_identity(code):
    assert mirror_exit_code(code) == code


# Behavior 5b: finalize_host_exit makes the container code the HOST exit status.
#
# Regression for the live-verification gap: pytest's _main() derives the session
# exit code purely from session.testsfailed / session.testscollected, discarding
# any session.exitstatus set in pytest_runtestloop. Because forwarding suppresses
# host-side collection (config.args = []), testscollected is always 0, so an
# all-pass or --co forwarded run would wrongly exit 5 (NO_TESTS_COLLECTED) and
# codes 2/3/4 could never surface. finalize_host_exit must force the exact code.

# A forwarder-shaped conftest: no host collection happens; the loop is replaced
# and the container's returncode (injected via env) is made authoritative.
_FORWARDER_CONFTEST = """
    import os
    from tests.ruciopytest import forwarding

    def pytest_runtestloop(session):
        forwarding.finalize_host_exit(session, int(os.environ["FAKE_RC"]))
"""

# Documents the ROOT CAUSE: the naive assignment that finalize_host_exit replaces.
_NAIVE_CONFTEST = """
    def pytest_runtestloop(session):
        session.exitstatus = 0   # discarded by _main()
        return True
"""

# Replays one real passing report, then finalizes — proving junitxml (FWD-06)
# and the terminal summary still emit on the pytest.exit path.
_REPLAY_CONFTEST = """
    from _pytest.reports import TestReport
    from tests.ruciopytest import forwarding

    def pytest_runtestloop(session):
        rep = TestReport(
            nodeid="tests/test_fake.py::test_ok",
            location=("tests/test_fake.py", 0, "test_ok"),
            keywords={}, outcome="passed", longrepr=None, when="call",
        )
        session.config.hook.pytest_runtest_logreport(report=rep)
        forwarding.finalize_host_exit(session, 0)
"""


@pytest.mark.parametrize("rc", [0, 1, 2, 5])
def test_finalize_host_exit_mirrors_container_code(pytester, monkeypatch, rc):
    monkeypatch.setenv("FAKE_RC", str(rc))
    pytester.makeconftest(_FORWARDER_CONFTEST)
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
    assert result.ret == rc


def test_naive_exitstatus_assignment_is_overwritten_to_5(pytester):
    # Without finalize_host_exit, a green forwarded run wrongly exits 5.
    pytester.makeconftest(_NAIVE_CONFTEST)
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider")
    assert result.ret == 5


def test_finalize_emits_junitxml_from_replayed_reports(pytester, tmp_path):
    xml = tmp_path / "out.xml"
    pytester.makeconftest(_REPLAY_CONFTEST)
    result = pytester.runpytest_inprocess(
        "-p", "no:cacheprovider", f"--junitxml={xml}"
    )
    assert result.ret == 0
    assert xml.exists()
    assert "<testcase" in xml.read_text()


# Behavior 6: build_env_flags applies the curated allowlist + extras.

def test_build_env_flags_allowlist_and_extras():
    environ = {
        "RUCIO_HOME": "/x",
        "SUITE": "remote_dbs",
        "RDBMS": "postgres14",
        "PATH": "/bin",
        "POLICY": "atlas",
    }
    flags = build_env_flags(environ, ["FOO=bar"])

    # Represent the flag list as (-e, "K=V") pairs for set membership assertions.
    pairs = set(zip(flags[::2], flags[1::2]))
    assert all(flag == "-e" for flag in flags[::2])

    assert ("-e", "RUCIO_HOME=/x") in pairs
    assert ("-e", "SUITE=remote_dbs") in pairs
    assert ("-e", "RDBMS=postgres14") in pairs
    assert ("-e", "POLICY=atlas") in pairs
    assert ("-e", "FOO=bar") in pairs
    assert ("-e", "PATH=/bin") not in pairs


def test_build_env_flags_empty_extras():
    flags = build_env_flags({"RUCIO_CFG": "/etc"}, [])
    assert flags == ["-e", "RUCIO_CFG=/etc"]


# Emitter: env-driven construction + JSON-lines emission.

def test_make_emitter_from_env_none_when_unset(call_reports, monkeypatch):
    config, _calls = call_reports
    monkeypatch.delenv(REPORT_STREAM_ENV, raising=False)
    assert make_emitter_from_env(config) is None


def test_emitter_writes_one_json_object_per_report(call_reports, tmp_path):
    config, calls = call_reports
    assert calls
    stream = tmp_path / "reports.jsonl"

    emitter = ReportStreamEmitter(config, str(stream))
    try:
        for report in calls:
            emitter.emit(report)
    finally:
        emitter.close()

    lines = [ln for ln in stream.read_text().splitlines() if ln.strip()]
    assert len(lines) == len(calls)
    for ln in lines:
        obj = json.loads(ln)  # each line is a standalone JSON object
        assert "$report_type" in obj


# Docker-coupled branches: mount check (FWD-09), staleness (FWD-12),
# interactive TTY passthrough (FWD-08). subprocess is monkeypatched, so these
# stay daemon-free while still exercising the real control flow.

class _FakeCM:
    """Records _compose_cmd(...) calls; returns a plain command list."""

    project_name = "rucio-test-fake"

    def __init__(self):
        self.calls = []

    def _compose_cmd(self, *args):
        self.calls.append(tuple(args))
        return ["docker", "compose", *args]


def _run_result(returncode=0, stdout=b""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=b"")


def test_check_bind_mount_raises_usageerror_when_missing(monkeypatch):
    cm = _FakeCM()
    monkeypatch.setattr(forwarding.subprocess, "run",
                        lambda cmd, **kw: _run_result(returncode=1))
    with pytest.raises(pytest.UsageError):
        forwarding._check_bind_mount(cm)
    # It probed the container source dir.
    assert any("test" in c and forwarding._CONTAINER_SOURCE_DIR in c for c in cm.calls)


def test_check_bind_mount_ok_when_present(monkeypatch):
    cm = _FakeCM()
    monkeypatch.setattr(forwarding.subprocess, "run",
                        lambda cmd, **kw: _run_result(returncode=0))
    forwarding._check_bind_mount(cm)  # must not raise


def test_warn_if_stale_warns_on_hash_mismatch(monkeypatch, capsys, tmp_path):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "requirements.dev.txt").write_bytes(b"host-content")
    cm = _FakeCM()
    monkeypatch.setattr(forwarding.subprocess, "run",
                        lambda cmd, **kw: _run_result(returncode=0, stdout=b"container-content"))
    forwarding._warn_if_stale(cm, str(tmp_path))
    assert "stale" in capsys.readouterr().out.lower()


def test_warn_if_stale_silent_when_hashes_match(monkeypatch, capsys, tmp_path):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "requirements.dev.txt").write_bytes(b"identical")
    cm = _FakeCM()
    monkeypatch.setattr(forwarding.subprocess, "run",
                        lambda cmd, **kw: _run_result(returncode=0, stdout=b"identical"))
    forwarding._warn_if_stale(cm, str(tmp_path))
    assert "stale" not in capsys.readouterr().out.lower()


def test_warn_if_stale_never_raises(monkeypatch, tmp_path):
    # Both the host read (file absent) and the container call blow up -> swallowed.
    cm = _FakeCM()

    def boom(*a, **k):
        raise OSError("docker daemon gone")

    monkeypatch.setattr(forwarding.subprocess, "run", boom)
    forwarding._warn_if_stale(cm, str(tmp_path))  # must not raise


def test_run_forwarded_session_interactive_uses_tty_and_no_stream(monkeypatch, tmp_path):
    cm = _FakeCM()
    monkeypatch.setattr(forwarding, "_check_bind_mount", lambda cm: None)
    monkeypatch.setattr(forwarding, "_warn_if_stale", lambda cm, root: None)
    monkeypatch.setattr(forwarding.subprocess, "run",
                        lambda cmd, **kw: _run_result(returncode=0))
    # Popen must never be used on the interactive path.
    monkeypatch.setattr(forwarding.subprocess, "Popen",
                        lambda *a, **k: pytest.fail("interactive path must not Popen"))

    session = types.SimpleNamespace(config=None)
    rc = forwarding.run_forwarded_session(
        session, cm, container_env=[], interactive=True,
        root_dir=str(tmp_path), project_name="proj",
    )

    assert rc == 0
    # exec -it (TTY) was requested...
    assert any("-it" in c for c in cm.calls)
    # ...and no JSON-lines scratch dir was created (no result stream).
    assert not (tmp_path / forwarding._FORWARD_SCRATCH_DIRNAME).exists()


def _prep_stream_session(monkeypatch, cm):
    """Common stream-branch monkeypatching: mount/staleness no-op."""
    monkeypatch.setattr(forwarding, "_check_bind_mount", lambda cm: None)
    monkeypatch.setattr(forwarding, "_warn_if_stale", lambda cm, root: None)


def test_first_ctrl_c_forwards_graceful_interrupt_and_mirrors_2(monkeypatch, tmp_path):
    cm = _FakeCM()
    _prep_stream_session(monkeypatch, cm)

    class _Proc:
        def __init__(self):
            self._polls = 0
            self.returncode = None

        def poll(self):
            self._polls += 1
            if self._polls == 1:
                raise KeyboardInterrupt  # Ctrl+C during the first wait
            self.returncode = 2
            return 2  # after pkill, process has ended

        def kill(self):  # pragma: no cover - not reached on single Ctrl+C
            raise AssertionError("single Ctrl+C must not hard-kill")

    monkeypatch.setattr(forwarding.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(forwarding.subprocess, "run",
                        lambda cmd, **kw: _run_result(returncode=0))

    session = types.SimpleNamespace(config=None)
    rc = forwarding.run_forwarded_session(
        session, cm, container_env=[], interactive=False,
        root_dir=str(tmp_path), project_name="proj",
    )

    assert rc == 2  # interrupted, mirrored
    # A graceful SIGINT was forwarded into the container.
    assert any("pkill" in c and "-INT" in c for c in cm.calls)


def test_second_ctrl_c_hard_kills_and_mirrors_2(monkeypatch, tmp_path):
    cm = _FakeCM()
    _prep_stream_session(monkeypatch, cm)

    class _Proc:
        def __init__(self):
            self.killed = False
            self.returncode = None

        def poll(self):
            raise KeyboardInterrupt  # Ctrl+C on both the first and second waits

        def kill(self):
            self.killed = True

    proc = _Proc()
    monkeypatch.setattr(forwarding.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(forwarding.subprocess, "run",
                        lambda cmd, **kw: _run_result(returncode=0))

    session = types.SimpleNamespace(config=None)
    rc = forwarding.run_forwarded_session(
        session, cm, container_env=[], interactive=False,
        root_dir=str(tmp_path), project_name="proj",
    )

    assert rc == 2
    assert proc.killed is True  # second Ctrl+C escalated to a hard kill


def test_execution_mode_captures_container_stdout_to_log_not_terminal(monkeypatch, tmp_path):
    cm = _FakeCM()
    _prep_stream_session(monkeypatch, cm)
    popen_kwargs = {}

    class _Proc:
        returncode = 0

        def poll(self):
            return 0

    def fake_popen(cmd, **kw):
        popen_kwargs.update(kw)
        return _Proc()

    monkeypatch.setattr(forwarding.subprocess, "Popen", fake_popen)

    session = types.SimpleNamespace(config=None)
    rc = forwarding.run_forwarded_session(
        session, cm, container_env=[], interactive=False, collect_only=False,
        root_dir=str(tmp_path), project_name="proj",
    )

    assert rc == 0
    # Execution mode redirects the container's stdout away from the terminal...
    assert popen_kwargs.get("stdout") is not None
    assert popen_kwargs.get("stderr") == forwarding.subprocess.STDOUT
    # ...into a per-run log file.
    assert (tmp_path / forwarding._FORWARD_SCRATCH_DIRNAME / "proj.container-stdout.log").exists()


def test_collect_only_mode_inherits_container_stdout(monkeypatch, tmp_path):
    cm = _FakeCM()
    _prep_stream_session(monkeypatch, cm)
    popen_kwargs = {}

    class _Proc:
        returncode = 0

        def poll(self):
            return 0

    def fake_popen(cmd, **kw):
        popen_kwargs.update(kw)
        return _Proc()

    monkeypatch.setattr(forwarding.subprocess, "Popen", fake_popen)

    session = types.SimpleNamespace(config=None)
    rc = forwarding.run_forwarded_session(
        session, cm, container_env=[], interactive=False, collect_only=True,
        root_dir=str(tmp_path), project_name="proj",
    )

    assert rc == 0
    # --co inherits the container's stdout (its listing is the only render).
    assert popen_kwargs.get("stdout") is None
    assert not (tmp_path / forwarding._FORWARD_SCRATCH_DIRNAME / "proj.container-stdout.log").exists()


# build_forward_xdist_args -- forwarded container xdist injection (08.1-A)

def test_forward_xdist_ci_uses_default_workers_ci():
    """On GitHub Actions, remote_dbs resolves N to the profile default_workers_ci (3)."""
    profile = resolve_profile("remote_dbs", "postgres14")
    assert build_forward_xdist_args(profile, {"GITHUB_ACTIONS": "true"}) == [
        "-p", "xdist", "--numprocesses=3",
    ]


def test_forward_xdist_local_uses_auto():
    """Locally (GITHUB_ACTIONS unset), N resolves to default_workers_local ('auto')."""
    profile = resolve_profile("remote_dbs", "postgres14")
    assert build_forward_xdist_args(profile, {}) == [
        "-p", "xdist", "--numprocesses=auto",
    ]


def test_forward_xdist_explicit_override_wins():
    """A host --xdist-workers=K override beats the CI default."""
    profile = resolve_profile("remote_dbs", "postgres14")
    assert build_forward_xdist_args(
        profile, {"GITHUB_ACTIONS": "true"}, explicit_workers=6
    ) == ["-p", "xdist", "--numprocesses=6"]


def test_forward_xdist_votest_enabled():
    """votest is xdist_enabled too -- CI injects numprocesses=3."""
    profile = resolve_profile("votest", "postgres14")
    assert build_forward_xdist_args(profile, {"GITHUB_ACTIONS": "true"}) == [
        "-p", "xdist", "--numprocesses=3",
    ]


def test_forward_xdist_multi_vo_excluded():
    """multi_vo injects nothing on the outer run -- its per-VO children own xdist."""
    profile = resolve_profile("multi_vo", "postgres14")
    assert build_forward_xdist_args(profile, {"GITHUB_ACTIONS": "true"}) == []


def test_forward_xdist_disabled_backend_noop():
    """A non-postgres14 backend (xdist_enabled False) injects nothing."""
    profile = resolve_profile("remote_dbs", "sqlite")
    assert build_forward_xdist_args(profile, {"GITHUB_ACTIONS": "true"}) == []


def test_forward_xdist_none_profile_noop():
    """A None profile injects nothing (defensive)."""
    assert build_forward_xdist_args(None, {"GITHUB_ACTIONS": "true"}) == []
