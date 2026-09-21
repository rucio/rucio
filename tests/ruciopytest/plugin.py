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

import os
import sys
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from .profiles import SuiteProfile, resolve_profile

if TYPE_CHECKING:
    from typing import Optional
from . import (
    container_manager_key,
    delegate_to_container_key,
    multi_vo_forward_rc_key,
    suite_profile_key,
)
from .xdist_config import configure_xdist

try:
    from .xdist_noparallel_scheduler import noparallel_report_key
except ImportError:
    noparallel_report_key = None


# Hooks


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register rucio-specific CLI options."""
    group = parser.getgroup("rucio", "Rucio test framework")
    group.addoption(
        "--suite",
        choices=["client", "remote_dbs", "multi_vo", "votest"],
        default=None,
        help="Test suite to run",
    )
    group.addoption(
        "--keep-db",
        action="store_true",
        default=False,
        help="Keep database from previous run (skip purge/rebuild/seed)",
    )
    group.addoption(
        "--policy",
        action="store",
        dest="policy",
        default=None,
        help="votest policy package (e.g. atlas, belleii); falls back to POLICY env",
    )
    group.addoption(
        "--xdist-workers",
        type=int,
        default=None,
        dest="xdist_workers",
        help="Number of xdist workers (overrides auto-detection)",
    )
    group.addoption(
        "--infra",
        type=str,
        default=None,
        help="Override infrastructure (comma-separated compose profiles or service names)",
    )
    group.addoption(
        "--dry-run",
        action="store_true",
        default=False,
        dest="dry_run",
        help="Show infrastructure plan and test collection without executing",
    )
    group.addoption(
        "--dry-run-json",
        action="store_true",
        default=False,
        dest="dry_run_json",
        help="Output dry-run report as JSON (implies --dry-run)",
    )
    group.addoption(
        "--run-in-container",
        dest="run_in_container",
        action="store_const",
        const=True,
        default=None,
        help="Force forwarding test execution into the rucio container",
    )
    group.addoption(
        "--no-run-in-container",
        dest="run_in_container",
        action="store_const",
        const=False,
        help="Force running tests on the host even for container suites (results may be unreliable)",
    )
    group.addoption(
        "--container-env",
        dest="container_env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set an arbitrary env var inside the container for the forwarded run (repeatable)",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Resolve suite profile, start containers if needed, and configure xdist.

    Execution model:
    - **Inside container** (detected via ``/.dockerenv`` or ``RUCIO_SOURCE_DIR``):
      Run InfraManager directly, then let pytest collect and run tests normally.
    - **On host with compose_profiles** (e.g. ``remote_dbs``, ``multi_vo``):
      Start containers via ContainerManager, then delegate the entire pytest
      session into the rucio container via ``docker compose exec``.  Host-side
      collection is skipped (``config.args = []``).
    - **On host without compose_profiles** (e.g. ``client``):
      No containers, no InfraManager.  Tests run on the host against an
      externally managed Rucio server.
    """
    is_worker = hasattr(config, "workerinput")

    suite_name = config.getoption("suite", default=None)
    infra_arg = config.getoption("infra", default=None)
    dry_run = config.getoption("dry_run", default=False)
    dry_run_json = config.getoption("dry_run_json", default=False)

    # --dry-run-json implies --dry-run
    if dry_run_json:
        dry_run = True
        config.option.dry_run = True

    if suite_name is None and infra_arg is None:
        return  # Plugin dormant when neither --suite nor --infra provided

    # Register collection.py hooks
    from . import collection as collection_module
    if not config.pluginmanager.hasplugin("rucio_collection"):
        config.pluginmanager.register(collection_module, "rucio_collection")

    # Ensure RUCIO_HOME is set so config loading works during collection.
    # Must happen before any rucio module is imported.
    if "RUCIO_HOME" not in os.environ:
        os.environ["RUCIO_HOME"] = str(config.rootdir)

    # Known RDBMS profiles for inferring rdbms from --infra
    rdbms_profiles = {"postgres14", "mysql8", "oracle"}

    if suite_name is not None and infra_arg is not None:
        # --suite WITH --infra: use suite's test collection, override infrastructure
        from .collection import _resolve_infra

        rdbms_override = os.environ.get("RDBMS")
        profile = resolve_profile(suite_name, rdbms_override)

        resolved_profiles, _raw_services = _resolve_infra(infra_arg)
        # Infer RDBMS from resolved profiles
        rdbms_from_infra = next(
            (p for p in resolved_profiles if p in rdbms_profiles), None
        )
        override_rdbms = rdbms_from_infra or profile.rdbms

        profile = SuiteProfile(
            name=profile.name,
            rdbms=override_rdbms,
            compose_profiles=tuple(sorted(resolved_profiles)),
            xdist_enabled=profile.xdist_enabled,
            run_in_container=profile.run_in_container,
            default_workers_ci=profile.default_workers_ci,
            default_workers_local=profile.default_workers_local,
            test_paths=profile.test_paths,
            markers=profile.markers,
            exclude_paths=profile.exclude_paths,
            env_vars=profile.env_vars,
            policy=profile.policy,
        )

    elif infra_arg is not None and suite_name is None:
        # --infra WITHOUT --suite: infer suites from infrastructure
        from .collection import _infer_suites_from_infra, _resolve_infra

        resolved_profiles, _raw_services = _resolve_infra(infra_arg)
        matching_suites = _infer_suites_from_infra(resolved_profiles)

        if not matching_suites:
            raise pytest.UsageError(
                f"No suites match infrastructure: {infra_arg}"
            )

        # Create a synthetic merged profile from all matching suites
        all_test_paths: set[str] = set()
        all_markers: set[str] = set()
        all_exclude_paths: set[str] = set()
        all_env_vars: dict[str, str] = {}
        suite_names = []

        for s in matching_suites:
            all_test_paths.update(s.test_paths)
            all_markers.update(s.markers)
            all_exclude_paths.update(s.exclude_paths)
            all_env_vars.update(s.env_vars)
            suite_names.append(s.name)

        # Infer RDBMS from resolved profiles
        rdbms_from_infra = next(
            (p for p in resolved_profiles if p in rdbms_profiles), None
        )

        profile = SuiteProfile(
            name="+".join(sorted(suite_names)),
            rdbms=rdbms_from_infra or matching_suites[0].rdbms,
            compose_profiles=tuple(sorted(resolved_profiles)),
            xdist_enabled=any(s.xdist_enabled for s in matching_suites),
            run_in_container=any(s.run_in_container for s in matching_suites),
            default_workers_ci=max(s.default_workers_ci for s in matching_suites),
            default_workers_local=matching_suites[0].default_workers_local,
            test_paths=tuple(sorted(all_test_paths)),
            markers=tuple(sorted(all_markers)),
            exclude_paths=tuple(sorted(all_exclude_paths)),
            env_vars=all_env_vars,
            policy=None,
        )

    else:
        # --suite only (no --infra): standard profile resolution
        rdbms_override = os.environ.get("RDBMS")
        profile = resolve_profile(suite_name, rdbms_override)

    # votest: compute the explicit POLICY-driven test_paths from the matrix YAML
    # ONCE, after the profile is finalized for all branches and before the stash
    # set. The existing collection path-filter then deselects everything else.
    if profile.name == "votest":
        from .votest_support import collect_votest_paths, load_matrix, resolve_policy

        policy = resolve_policy(config, os.environ)
        if not policy:
            raise pytest.UsageError(
                "--suite=votest requires --policy=<name> or the POLICY env var"
            )
        matrix = load_matrix(
            config.rootpath / "etc/docker/test/matrix_policy_package_tests.yml"
        )
        if policy not in matrix:
            raise pytest.UsageError(
                f"Unknown policy {policy!r}; available: {sorted(matrix)}"
            )
        paths = collect_votest_paths(matrix, policy, config.rootpath)
        profile = replace(profile, test_paths=tuple(paths), policy=policy)
        # Backward compat: the forwarded in-container run inherits POLICY.
        os.environ["POLICY"] = policy

    # Store in stash (available on both controller and workers)
    config.stash[suite_profile_key] = profile

    # Backward compatibility: many existing tests check os.environ["SUITE"]
    if suite_name is not None:
        os.environ["SUITE"] = suite_name

    if not is_worker:
        configure_xdist(config, profile)
        _print_profile_summary(config, profile)

        _in_container = _detect_in_container()

        # Reconcile Phase 4's dry-run early-exit with Phase 6 forwarding (FWD-11).
        # Forwarding wins for container suites: when forwarding applies, --dry-run
        # (and --co) must fall through to start containers and delegate so the
        # in-container pytest produces the authoritative listing/report (truthful
        # over fast). Compute the forwarding decision ONCE (single side-effecting
        # _should_forward_to_container call) and reuse it for both the dry-run
        # guard and the delegation branch below.
        forwarding_applies = (
            not _in_container
            and bool(profile.compose_profiles)
            and _should_forward_to_container(config, profile)
        )

        # --dry-run on a host-side / non-forwarded run: keep Phase 4's fast path
        # and skip container lifecycle entirely.
        if dry_run and not forwarding_applies:
            return  # host-side fast path: skip container lifecycle for non-forwarded dry-run

        if _in_container:
            # Inside container: run InfraManager directly for non-client suites
            print("[plugin] Running inside container, skipping Docker Compose lifecycle")
            if profile.name != "client":
                keep_db = config.getoption("--keep-db", default=False)
                from .infra_manager import InfraManager
                manager = InfraManager(profile, keep_db=keep_db)
                manager.setup()

                # multi_vo: setup() already drove the per-VO xdist children
                # (run_multi_vo) -- the faithful, gating execution -- and the
                # tst child streamed its reports to the host. Do NOT let this
                # outer forwarded session ALSO collect+run the suite (that was a
                # second, serial, non-xdist pass that became the WRONG gate and
                # double-executed the suite). Suppress its own collection and
                # mirror the children's aggregate exit code in pytest_runtestloop.
                if profile.name == "multi_vo":
                    config.stash[multi_vo_forward_rc_key] = manager._multi_vo_rc
                    config.args = []
                    return  # children own the host stream; nothing else to do

            # If the host launched us with RUCIO_FORWARD_STREAM set, attach the
            # report-stream emitter so each in-container report is mirrored back.
            from . import forwarding
            forwarding.register_container_stream(config)

        elif forwarding_applies:
            # On host with a forwarding container suite: start containers and
            # delegate test execution (forwarding_applies already encodes
            # compose_profiles + not in-container + _should_forward_to_container).
            # Set RDBMS so the container entrypoint generates the right config
            os.environ.setdefault("RDBMS", profile.rdbms)
            from .container_manager import ContainerManager

            # Two parallel multi_vo VO legs need distinct compose stacks, so
            # thread the leg selector into the project name (per-VO-unique).
            mv_leg = os.environ.get("RUCIO_MULTI_VO_LEG") if profile.name == "multi_vo" else None
            project_name = ContainerManager.make_project_name(profile.name, profile.rdbms, mv_leg)
            cm = ContainerManager(project_name, profile.compose_profiles, str(config.rootdir))
            cm.start()
            config.stash[container_manager_key] = cm
            config.stash[delegate_to_container_key] = True

            # Prevent host-side test collection — tests will be collected
            # inside the container.  This avoids import errors from rucio
            # modules that require in-container config/services.
            config.args = []

        # else: on host, no compose_profiles (client suite) — nothing to do


def pytest_runtestloop(session: pytest.Session) -> "Optional[object]":
    """Forward test execution into the rucio container with 1:1 result mirroring.

    When ``delegate_to_container_key`` is set, delegate the whole run to
    :func:`forwarding.run_forwarded_session`, which runs the suite *inside* the
    container, streams per-test reports back to the host (replayed natively so
    each container test surfaces individually -- never a single wrapper), and
    returns the container's pytest exit code. ``finalize_host_exit`` then raises
    ``pytest.exit(returncode=...)`` so the host exit status mirrors the container
    code exactly -- codes 0/1/2/3/4/5 all stay faithful (FWD-05). (A plain
    ``session.exitstatus = ...`` here would be discarded by pytest's ``_main``.)

    FWD-06 (junitxml): no extra code -- the replayed reports flow through the
    host's junitxml plugin (subscribed to ``pytest_runtest_logreport``), so
    ``--junitxml=<host path>`` populates at the host path automatically. Do NOT
    re-add any XML copying here.

    Returns ``None`` to let pytest handle execution normally (in-container /
    client suite). On the delegating path it does not return -- ``finalize_host_exit``
    raises ``pytest.exit`` -- which also prevents the default test loop.
    """
    config = session.config

    # In-container multi_vo outer session: the per-VO xdist children already ran
    # (run_multi_vo) and the tst child streamed its reports to the host. This
    # session collected nothing (config.args was cleared); exit with the
    # children's aggregate code so the host -- and therefore CI -- gates on the
    # faithful per-VO xdist execution rather than a redundant serial pass.
    mv_rc = config.stash.get(multi_vo_forward_rc_key, None)
    if mv_rc is not None:
        from . import forwarding
        forwarding.finalize_host_exit(session, mv_rc)  # raises pytest.exit
        return None  # not reached

    if not config.stash.get(delegate_to_container_key, False):
        return None  # Normal execution

    cm = config.stash[container_manager_key]
    container_env = config.getoption("container_env", default=[])
    interactive = (
        bool(config.getoption("usepdb", default=False))
        or any(
            a in ("--pdb", "--trace") or a.startswith("--pdbcls")
            for a in sys.argv[1:]
        )
    )

    from . import forwarding

    print("\n[plugin] Forwarding test execution into the rucio container "
          "(1:1 result mirroring)\n")
    returncode = forwarding.run_forwarded_session(
        session, cm,
        container_env=container_env,
        interactive=interactive,
        root_dir=str(config.rootdir),
        project_name=cm.project_name,
        collect_only=bool(config.getoption("collectonly", default=False)),
    )
    # Make the container's exit code authoritative. pytest's _main() derives the
    # session exit status from testsfailed/testscollected only -- and host
    # collection is suppressed (config.args = []), so testscollected == 0 would
    # otherwise force exit 5 on any all-pass or --co forwarded run. This raises
    # pytest.exit(returncode=...) so the code mirrors exactly (FWD-05);
    # sessionfinish/unconfigure still run for junitxml (FWD-06) and teardown.
    forwarding.finalize_host_exit(session, returncode)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print container log file locations and add to JUnit XML."""
    cm = config.stash.get(container_manager_key, None)
    if cm is None:
        return

    log_dir = cm.log_dir
    if not log_dir.exists():
        return

    log_files = sorted(log_dir.glob("*.log"))
    if not log_files:
        return

    # Print log file locations in terminal
    terminalreporter.write_sep("=", "Container Logs")
    for log_file in log_files:
        terminalreporter.write_line(f"  {log_file}", yellow=True)
    terminalreporter.write_sep("=")

    # Add to JUnit XML if --junitxml was specified
    xml_plugin = config.pluginmanager.get_plugin("junitxml")
    if xml_plugin is not None:
        try:
            for log_file in log_files:
                xml_plugin.add_global_property(
                    f"container_log:{log_file.name}",
                    str(log_file)
                )
        except (AttributeError, TypeError):
            # Fallback: junitxml API may vary across pytest versions
            pass

    # NoParallel conflict report
    if noparallel_report_key is not None:
        scheduler_report = config.stash.get(noparallel_report_key, None)
        if scheduler_report:
            terminalreporter.write_sep("=", "NoParallel Conflict Summary")
            for group, tests in sorted(scheduler_report.items()):
                terminalreporter.write_line(f"  Group '{group}': {len(tests)} tests")
                for t in tests[:5]:  # Show first 5
                    terminalreporter.write_line(f"    - {t}")
                if len(tests) > 5:
                    terminalreporter.write_line(f"    ... and {len(tests) - 5} more")
            terminalreporter.write_sep("=")


def pytest_unconfigure(config: pytest.Config) -> None:
    """Stop containers on session end and close any forward-stream emitter."""
    emitter = getattr(config, "_rucio_forward_emitter", None)
    if emitter is not None:
        emitter.close()

    cm = config.stash.get(container_manager_key, None)
    if cm is not None:
        cm.stop(capture_logs=True)


# Internal helpers


def _detect_in_container() -> bool:
    """Return whether this process is running inside the rucio container.

    True when Docker's ``/.dockerenv`` marker file exists, or when the
    container image's ``RUCIO_SOURCE_DIR`` is exported into the environment.
    """
    return bool(os.path.exists("/.dockerenv") or os.environ.get("RUCIO_SOURCE_DIR"))


def _should_forward_to_container(config, profile) -> bool:
    """Resolve whether to forward this run into the container.

    Tri-state CLI override wins; otherwise the profile default. Emits a
    prominent warning (but does NOT raise) when the user opts out of a
    suite that normally runs in-container.
    """
    override = config.getoption("run_in_container", default=None)
    decided = override if override is not None else profile.run_in_container
    if not decided and profile.run_in_container:
        _warn_host_run_optout(config, profile)
    return decided


def _warn_host_run_optout(config, profile) -> None:
    msg = (f"WARNING: suite '{profile.name}' normally runs inside the rucio container; "
           f"running on the host as requested (--no-run-in-container) — results may be unreliable.")
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter._tw.line()
        reporter._tw.line(msg, red=True, bold=True)
        reporter._tw.line()
    else:
        print(msg)


def _print_profile_summary(config: pytest.Config, profile: SuiteProfile) -> None:
    """Print a summary box of the resolved suite profile."""
    if config.pluginmanager.hasplugin("xdist"):
        workers = getattr(config.option, "numprocesses", 0)
    else:
        workers = 0

    infra_arg = config.getoption("infra", default=None)

    # Build the lines to print
    lines = [
        f"  Suite:          {profile.name}",
        f"  RDBMS:          {profile.rdbms}",
        f"  xdist enabled:  {profile.xdist_enabled}",
        f"  Workers:        {workers}",
        f"  Test paths:     {', '.join(profile.test_paths)}",
    ]
    if profile.exclude_paths:
        lines.append(f"  Exclude paths:  {', '.join(profile.exclude_paths)}")
    if infra_arg:
        lines.append(f"  Infra override: {infra_arg}")
    if profile.env_vars:
        lines.append(f"  Env vars:       {profile.env_vars}")

    # Terminal reporter may not be registered yet during early pytest_configure.
    # Use pluginmanager to check; fall back to plain print if unavailable.
    terminalreporter = config.pluginmanager.get_plugin("terminalreporter")
    if terminalreporter is not None:
        tw = terminalreporter._tw
        tw.line()
        tw.sep("=", "Rucio Test Suite Configuration")
        for line in lines:
            tw.line(line)
        if not profile.xdist_enabled:
            tw.line("  NOTE: xdist disabled, noparallel markers have no effect")
        tw.sep("=")
        tw.line()
    else:
        # Fallback: plain print when terminal writer is not yet available
        print()
        print("=" * 60)
        print("  Rucio Test Suite Configuration")
        print("=" * 60)
        for line in lines:
            print(line)
        if not profile.xdist_enabled:
            print("  NOTE: xdist disabled, noparallel markers have no effect")
        print("=" * 60)
        print()
