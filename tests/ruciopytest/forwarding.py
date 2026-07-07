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

"""Docker-free transport core for the container pytest forwarder.

This module holds the pure, unit-testable glue that lets a host-side pytest run
mirror, 1:1, the reports produced by a pytest run *inside* a container -- without
introducing any new pip dependency. It uses ONLY the Python standard library plus
pytest's own core report-serialization hooks.

Pieces:

* ``build_inner_pytest_args`` -- strip host-only forwarding-control flags from the
  argv before it is handed to the inner (container) pytest; everything else passes
  through untouched.
* ``ReportStreamEmitter`` / ``make_emitter_from_env`` -- container side. Serialize
  each report through the core ``pytest_report_to_serializable`` hook and write one
  JSON object per line to a stream file.
* ``replay_report_line`` -- host side. Reconstruct a report through the core
  ``pytest_report_from_serializable`` hook and re-dispatch it through
  ``pytest_runtest_logreport`` / ``pytest_collectreport`` so the host's terminal,
  junitxml and ``session.testsfailed`` all behave as if the test ran locally.
* ``mirror_exit_code`` -- map the container pytest returncode onto the host outcome.
* ``build_env_flags`` -- curated env allowlist + explicit overrides -> ``-e K=V``.

Hook signatures (pytest 7.4.x, _pytest/hookspec.py): both
``pytest_report_to_serializable(config, report)`` and
``pytest_report_from_serializable(config, data)`` accept ``config=`` as a keyword,
so the calls below pass ``config=...`` explicitly.
"""

import hashlib
import json
import os
import subprocess  # noqa: S404 -- used to drive docker compose exec/run
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

# Safe import: __init__ imports only .profiles (no plugin.py), so this does not
# create a circular import into the plugin module.
from . import suite_profile_key

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Iterable, Mapping

    from _pytest.config import Config
    from _pytest.main import Session

    from .profiles import SuiteProfile

__all__ = [
    "REPORT_STREAM_ENV",
    "ReportStreamEmitter",
    "build_env_flags",
    "build_forward_xdist_args",
    "build_inner_pytest_args",
    "finalize_host_exit",
    "make_emitter_from_env",
    "mirror_exit_code",
    "register_container_stream",
    "replay_report_line",
    "run_forwarded_session",
]

# argv filtering

# Host-only store flags: meaningful on the host, never forwarded into the
# container's pytest invocation.
_HOST_ONLY_FLAGS = frozenset({"--run-in-container", "--no-run-in-container"})

# --container-env consumes a following value in split form ("--container-env A=1")
# or carries it attached ("--container-env=A=1"). Both forms are host-only.
_CONTAINER_ENV_FLAG = "--container-env"
_CONTAINER_ENV_ATTACHED_PREFIX = _CONTAINER_ENV_FLAG + "="

# --junitxml is host-only: the host's junitxml plugin already builds the report
# from the replayed container reports (FWD-06), writing it at the host path.
# Forwarding the flag makes the *container's* pytest ALSO write to the same
# host-mounted path; on CI the container user's UID differs from the runner's,
# so that second write fails with PermissionError [Errno 13] and forces a
# nonzero container exit even when every test passes. Strip it so only the host
# (which owns the path) produces the junit XML. Split form ("--junitxml PATH")
# and attached form ("--junitxml=PATH") are both removed.
_JUNITXML_FLAG = "--junitxml"
_JUNITXML_ATTACHED_PREFIX = _JUNITXML_FLAG + "="


def build_inner_pytest_args(argv: list[str]) -> list[str]:
    """Return ``argv`` with host-only forwarding-control flags removed.

    Stripped:
      * ``--run-in-container`` / ``--no-run-in-container`` (store flags)
      * ``--container-env VALUE`` (split form: flag and its value)
      * ``--container-env=VALUE`` (attached form)
      * ``--junitxml VALUE`` / ``--junitxml=VALUE`` (host writes junit; the
        container must not also write to the host-mounted path -- PermissionError)

    Everything else -- ``--suite``, ``--keep-db``, ``--xdist-workers``, ``-k``,
    ``-m``, ``-x``, ``-v``, ``--co``, ``--dry-run`` and test paths --
    passes through in its original order.
    """
    result: list[str] = []
    i = 0
    n = len(argv)
    while i < n:
        token = argv[i]
        if token in _HOST_ONLY_FLAGS:
            i += 1
            continue
        if token == _CONTAINER_ENV_FLAG:
            # Skip the flag and its value (if a value follows).
            i += 2
            continue
        if token.startswith(_CONTAINER_ENV_ATTACHED_PREFIX):
            i += 1
            continue
        if token == _JUNITXML_FLAG:
            # Skip the flag and its following path value.
            i += 2
            continue
        if token.startswith(_JUNITXML_ATTACHED_PREFIX):
            i += 1
            continue
        result.append(token)
        i += 1
    return result


def build_forward_xdist_args(
    profile: "Optional[SuiteProfile]",
    environ: "Mapping[str, str]",
    explicit_workers: Optional[int] = None,
) -> list[str]:
    """Return ``['-p','xdist','--numprocesses=<N>']`` for an xdist_enabled forwarded suite, else ``[]``.

    Mirrors ``InfraManager._multi_vo_pytest_cmd`` so the forwarded container suites
    (remote_dbs, votest) run in parallel INSIDE the container. Precedence for ``<N>``:

      1. ``explicit_workers`` (the host ``--xdist-workers=K`` override) when ``> 0``
      2. ``profile.default_workers_ci`` when ``GITHUB_ACTIONS == 'true'``  (3 on CI)
      3. ``profile.default_workers_local`` otherwise                      ('auto' locally)

    Returns ``[]`` when the profile is ``None``, xdist is disabled, OR the suite is
    multi_vo (multi_vo's per-VO children already inject xdist; the outer forwarded
    run clears ``config.args`` and must not be parallelized).
    """
    if profile is None or not getattr(profile, "xdist_enabled", False):
        return []
    if getattr(profile, "name", None) == "multi_vo":
        return []  # children own xdist

    if explicit_workers is not None and explicit_workers > 0:
        procs = str(explicit_workers)
    elif environ.get("GITHUB_ACTIONS") == "true":
        procs = str(profile.default_workers_ci)
    else:
        procs = str(profile.default_workers_local)

    return ["-p", "xdist", f"--numprocesses={procs}"]


# env flags

# Curated allowlist of environment variables forwarded into the container.
# GITHUB_ACTIONS is forwarded so the in-container run (and the multi_vo per-VO
# xdist children it spawns) detect CI and cap workers at 3 -- legacy
# tools/pytest.sh and InfraManager._multi_vo_pytest_cmd both key the
# "3 procs on CI vs auto locally" decision on GITHUB_ACTIONS=="true", which is
# otherwise invisible inside the forwarded container (auto -> too many DB
# connections -> postgres "too many clients").
_ENV_ALLOWLIST_EXACT = frozenset({"SUITE", "POLICY", "RDBMS", "GITHUB_ACTIONS"})
_ENV_ALLOWLIST_PREFIXES = ("RUCIO_",)


def _is_allowlisted(key: str) -> bool:
    return key in _ENV_ALLOWLIST_EXACT or key.startswith(_ENV_ALLOWLIST_PREFIXES)


def build_env_flags(
    environ: "Mapping[str, str]",
    extra_container_env: "Iterable[str]",
) -> list[str]:
    """Build repeatable ``-e KEY=VALUE`` flags for ``docker exec``/``run``.

    Includes every entry of ``environ`` whose key is in the curated allowlist
    (exact match in :data:`_ENV_ALLOWLIST_EXACT` or carrying an allowlisted
    prefix), followed by each explicit ``KEY=VALUE`` string in
    ``extra_container_env``.
    """
    flags: list[str] = []
    for key, value in environ.items():
        if _is_allowlisted(key):
            flags += ["-e", f"{key}={value}"]
    for kv in extra_container_env:
        flags += ["-e", kv]
    return flags


# report stream emitter (container side)

# Path the host sets when stream mode is active; the container-side hooks emit
# serialized reports here, one JSON object per line.
REPORT_STREAM_ENV = "RUCIO_FORWARD_STREAM"


class ReportStreamEmitter:
    """Serialize reports to a JSON-lines stream using pytest's core hook.

    Each :meth:`emit` call serializes one report through
    ``config.hook.pytest_report_to_serializable`` and writes it as a single JSON
    line, flushing immediately so the host can consume the stream incrementally.
    """

    def __init__(self, config: "Config", path: str) -> None:
        self._config = config
        self._path = path
        # Line-buffered append so concurrent host tailing sees whole lines.
        self._fh = open(path, "a", buffering=1, encoding="utf-8")

    def emit(self, report) -> None:
        data = self._config.hook.pytest_report_to_serializable(
            config=self._config, report=report
        )
        # pytest serializes the report's ``__dict__``; under xdist the controller
        # re-fires worker reports carrying a ``node`` attribute set to the
        # ``WorkerController`` (not JSON-serializable). It is xdist-internal and
        # irrelevant to the host replay, so drop it. ``default=str`` is a
        # belt-and-suspenders fallback for any other non-serializable attribute
        # xdist may attach, so a single report can never abort the whole stream.
        if isinstance(data, dict):
            data.pop("node", None)
        self._fh.write(json.dumps(data, default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh is not None and not self._fh.closed:
            self._fh.flush()
            self._fh.close()


def make_emitter_from_env(config: "Config") -> Optional[ReportStreamEmitter]:
    """Return a :class:`ReportStreamEmitter` if stream mode is active, else ``None``.

    Stream mode is active when :data:`REPORT_STREAM_ENV` is set to a non-empty
    path in the environment (the host sets this before launching the container's
    pytest). When unset/empty, returns ``None`` so the container-side hooks no-op.
    """
    path = os.environ.get(REPORT_STREAM_ENV)
    if not path:
        return None
    return ReportStreamEmitter(config, path)


class _StreamReportPlugin:
    """Container-side pytest plugin that emits every report through an emitter.

    Registered (only when stream mode is active) on the in-container pytest's
    plugin manager so that each ``TestReport`` / ``CollectReport`` is serialized
    to the JSON-lines stream the host tails. Under xdist this lives on the
    controller, which receives the worker reports too -- so every test surfaces
    exactly once on the host (Pitfall 5).
    """

    def __init__(self, emitter: "ReportStreamEmitter") -> None:
        self._emitter = emitter

    def pytest_runtest_logreport(self, report) -> None:
        self._emitter.emit(report)

    def pytest_collectreport(self, report) -> None:
        self._emitter.emit(report)


def register_container_stream(config: "Config") -> bool:
    """Attach the stream-emitter plugin if :data:`REPORT_STREAM_ENV` is set.

    Called from the container-side ``pytest_configure``. Registers
    unconditionally (no ``is_worker`` gate) so the xdist controller -- which
    fires ``pytest_runtest_logreport`` for worker reports -- emits every test's
    reports. Stores the emitter on ``config._rucio_forward_emitter`` so
    ``pytest_unconfigure`` can close it. Returns ``True`` when registered.
    """
    emitter = make_emitter_from_env(config)
    if emitter is None:
        return False
    config.pluginmanager.register(_StreamReportPlugin(emitter), "rucio_forward_stream")
    config._rucio_forward_emitter = emitter  # closed at unconfigure
    return True


# replay (host side)

def replay_report_line(session: "Session", line: str) -> bool:
    """Reconstruct one serialized report from ``line`` and re-dispatch it.

    Returns ``True`` if a report was dispatched, ``False`` for blank/whitespace
    lines or data the core could not deserialize. ``CollectReport`` payloads are
    routed through ``pytest_collectreport``; everything else (``TestReport``)
    through ``pytest_runtest_logreport`` -- preserving the host's per-test
    accounting so N container tests surface as N host reports (never collapsed
    into a single wrapper).
    """
    line = line.strip()
    if not line:
        return False

    data = json.loads(line)
    config = session.config
    report = config.hook.pytest_report_from_serializable(config=config, data=data)
    if report is None:
        return False

    # JSON has no tuples: pytest serializes a skipped report's ``longrepr``
    # (path, lineno, reason) 3-tuple and the core round-trip restores it as a
    # list. The terminal reporter's ``_get_raw_skip_reason`` asserts the skip
    # ``longrepr`` is a tuple, so an un-normalized list crashes the whole host
    # session with an INTERNALERROR the moment any container test is skipped or
    # xfailed. Restore the tuple shape the reporter contracts on.
    longrepr = getattr(report, "longrepr", None)
    if getattr(report, "skipped", False) and isinstance(longrepr, list) and len(longrepr) == 3:
        report.longrepr = tuple(longrepr)

    if data.get("$report_type") == "CollectReport":
        config.hook.pytest_collectreport(report=report)
    else:
        config.hook.pytest_runtest_logreport(report=report)
    return True


# exit code mirror

def mirror_exit_code(returncode: int) -> int:
    """Mirror the container pytest returncode onto the host outcome.

    A deliberately trivial identity seam (0 OK, 1 failed, 2 interrupted,
    3 internal error, 4 usage error, 5 no tests collected) so the host has a
    single tested home for the exit-mirror requirement (FWD-05). The actual
    application of the code happens in :func:`finalize_host_exit`.
    """
    return int(returncode)


def finalize_host_exit(session: "Session", returncode: int) -> None:
    """Force the container's ``returncode`` to be the host's exact exit status.

    ``_pytest.main.wrap_session`` sets ``session.exitstatus`` from ``_main``'s
    return value, which is derived **only** from ``session.testsfailed`` /
    ``session.testscollected`` -- so any ``session.exitstatus`` assigned inside
    ``pytest_runtestloop`` is silently discarded. Because forwarding suppresses
    host-side collection (``config.args = []``), ``testscollected`` is always 0
    on the host; an all-pass or ``--co`` container run would therefore exit 5
    (NO_TESTS_COLLECTED), and codes 2/3/4 could never surface (FWD-05 violated).

    ``pytest.exit(returncode=...)`` is the one mechanism ``wrap_session`` honors
    verbatim -- it reads ``exit.Exception.returncode`` directly -- so every
    container exit code (0,1,2,3,4,5) mirrors exactly. This raises ``Exit`` and
    therefore does not return; ``pytest_sessionfinish`` and ``pytest_unconfigure``
    still run in ``wrap_session``'s ``finally`` block, so replayed reports flush
    to ``--junitxml`` (FWD-06), the terminal summary prints, and the containers
    are torn down.
    """
    import pytest

    code = mirror_exit_code(returncode)
    # Honored by any hook that reads exitstatus before the unwind; the authoritative
    # value is carried by the Exit exception below.
    session.exitstatus = code
    pytest.exit(reason=f"forwarded container pytest exited {code}", returncode=code)


# host orchestration (Docker-coupled)

# Bind-mount target inside the rucio dev container (etc/docker/dev compose).
_CONTAINER_SOURCE_DIR = "/rucio_source"
# Host-relative scratch dir (also visible in-container under the bind mount).
_FORWARD_SCRATCH_DIRNAME = ".test-forward"
# Requirements file used for the best-effort staleness check.
_STALENESS_REQUIREMENTS = "requirements/requirements.dev.txt"
# Tail polling interval while the inner pytest is running.
_TAIL_POLL_SECONDS = 0.02


def _short_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def _check_bind_mount(cm) -> None:
    """Raise ``pytest.UsageError`` if the repo is not bind-mounted in the container.

    No copy fallback -- forwarding requires the live source mount so that the
    JSON-lines stream the container writes is visible on the host (FWD-09).
    """
    import pytest

    cmd = cm._compose_cmd("exec", "-T", "rucio", "test", "-d", _CONTAINER_SOURCE_DIR)
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        raise pytest.UsageError(
            "rucio source is not bind-mounted at /rucio_source in the container; "
            "cannot forward -- check the dev compose mount"
        )


def _warn_if_stale(cm, root_dir: str) -> None:
    """Best-effort staleness warning (FWD-12): compare dev-requirements hashes.

    Any failure is a silent skip -- this must never raise or block forwarding.
    """
    try:
        host_path = Path(root_dir) / _STALENESS_REQUIREMENTS
        host_hash = _short_hash(host_path.read_bytes())

        cmd = cm._compose_cmd(
            "exec", "-T", "rucio", "cat", f"{_CONTAINER_SOURCE_DIR}/{_STALENESS_REQUIREMENTS}"
        )
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            return
        container_hash = _short_hash(result.stdout)

        if host_hash != container_hash:
            # ANSI yellow; degrade gracefully if the terminal ignores it.
            print(
                "\033[33mWARNING: container image may be stale -- host "
                f"{_STALENESS_REQUIREMENTS} differs from the container copy "
                "(host={} vs container={}). Rebuild the dev image if tests "
                "behave unexpectedly.\033[0m".format(host_hash, container_hash)
            )
    except Exception:  # noqa: BLE001 - staleness check is strictly best-effort
        return


def _drain_stream(session: "Session", fh) -> None:
    """Replay every complete line currently available on ``fh``."""
    while True:
        line = fh.readline()
        if not line:
            break
        if line.endswith("\n"):
            replay_report_line(session, line)
        else:
            # Partial line: rewind so we re-read it once it's complete.
            fh.seek(fh.tell() - len(line))
            break


def run_forwarded_session(
    session: "Session",
    cm,
    *,
    container_env: "Iterable[str]",
    interactive: bool,
    root_dir: str,
    project_name: str,
    collect_only: bool = False,
) -> int:
    """Run the host's pytest session inside the rucio container, 1:1.

    Orchestrates the Docker-coupled half of the forwarder:

    1. Verify the repo bind mount exists (raises ``pytest.UsageError`` if not).
    2. Best-effort staleness warning comparing dev-requirements hashes.
    3. Interactive runs (``--pdb``/``--trace``) go through ``docker compose
       exec -it`` raw TTY passthrough -- no result stream.
    4. Default runs stream JSON-lines reports through a host-visible mounted
       file, replaying each report so N container tests surface as N host
       reports, then mirror the container exit code.
    5. First Ctrl+C forwards a graceful interrupt into the container and keeps
       draining; second Ctrl+C hard-kills. Teardown is left to the caller
       (Phase 3 ``ContainerManager.stop``).

    Terminal rendering (avoid double output): during **execution** the host
    replays reports through its own terminalreporter, so the container's
    identical pytest rendering is captured to a log file instead of inherited to
    the terminal. During **collect-only** the host has no items of its own to
    list, so the container's stdout (its collected-test listing) is inherited to
    the terminal -- it is the only place that listing is rendered.
    """
    _check_bind_mount(cm)
    _warn_if_stale(cm, root_dir)

    inner_args = build_inner_pytest_args(sys.argv[1:])

    # Forwarded xdist parity (Phase 08.1-A): the host configure_xdist runs on the
    # SUPPRESSED host session, so worker args never reach the container. Inject them
    # here for xdist_enabled suites -- mirroring _multi_vo_pytest_cmd. Skip for
    # interactive runs (pdb+xdist are incompatible) and when inner_args already carry
    # a worker flag (idempotent -- never double-inject).
    config = getattr(session, "config", None)
    if config is not None and not interactive and not any(
        a in ("-n", "-p") or a.startswith("--numprocesses") or a == "xdist"
        for a in inner_args
    ):
        profile = config.stash.get(suite_profile_key, None)
        explicit = config.getoption("xdist_workers", default=None)
        inner_args = inner_args + build_forward_xdist_args(profile, os.environ, explicit)

    env_flags = build_env_flags(os.environ, container_env)

    # --- interactive branch: raw TTY passthrough, no stream (FWD-08) ---------
    if interactive:
        cmd = cm._compose_cmd(
            "exec", "-it", *env_flags, "-w", _CONTAINER_SOURCE_DIR,
            "rucio", "python", "-m", "pytest", *inner_args,
        )
        return mirror_exit_code(subprocess.run(cmd).returncode)

    # --- stream branch: tail the mounted JSON-lines file (FWD-04/05) ---------
    stream_dir = Path(root_dir) / _FORWARD_SCRATCH_DIRNAME
    stream_dir.mkdir(parents=True, exist_ok=True)
    stream_file = stream_dir / f"{project_name}.jsonl"
    # Truncate/create empty so we only see this run's reports.
    stream_file.write_text("", encoding="utf-8")

    container_stream_path = (
        f"{_CONTAINER_SOURCE_DIR}/{_FORWARD_SCRATCH_DIRNAME}/{project_name}.jsonl"
    )
    env_flags = list(env_flags) + ["-e", f"{REPORT_STREAM_ENV}={container_stream_path}"]

    cmd = cm._compose_cmd(
        "exec", "-T", *env_flags, "-w", _CONTAINER_SOURCE_DIR,
        "rucio", "python", "-m", "pytest", *inner_args,
    )

    # Choose who renders to the terminal (see docstring). We always read results
    # only from the mounted file (Pitfall 4 -- never also drain the pipe).
    container_stdout_fh = None
    if collect_only:
        # Container is the sole renderer of the collected listing -> inherit.
        proc = subprocess.Popen(cmd)
    else:
        # Host replays + renders live; capture the container's duplicate pytest
        # rendering to a log file rather than echoing it to the terminal.
        container_log = stream_dir / f"{project_name}.container-stdout.log"
        container_stdout_fh = open(container_log, "w", encoding="utf-8")
        print(f"[plugin] container pytest output -> {container_log}")
        proc = subprocess.Popen(
            cmd, stdout=container_stdout_fh, stderr=subprocess.STDOUT
        )

    try:
        returncode: int
        with open(stream_file, "r", encoding="utf-8") as fh:
            try:
                # First-level wait: graceful on the first Ctrl+C.
                while proc.poll() is None:
                    _drain_stream(session, fh)
                    time.sleep(_TAIL_POLL_SECONDS)
                _drain_stream(session, fh)
                returncode = proc.returncode
            except KeyboardInterrupt:
                # First Ctrl+C: forward a graceful interrupt into the container.
                try:
                    subprocess.run(
                        cm._compose_cmd(
                            "exec", "-T", "rucio", "pkill", "-INT", "-f", "python -m pytest"
                        ),
                        capture_output=True,
                    )
                    while proc.poll() is None:
                        _drain_stream(session, fh)
                        time.sleep(_TAIL_POLL_SECONDS)
                    _drain_stream(session, fh)
                except KeyboardInterrupt:
                    # Second Ctrl+C: hard kill.
                    proc.kill()
                    _drain_stream(session, fh)
                returncode = 2
    finally:
        if container_stdout_fh is not None:
            container_stdout_fh.close()

    return mirror_exit_code(returncode)
