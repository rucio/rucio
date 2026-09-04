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

"""Infrastructure manager for Rucio test database lifecycle and bootstrap.

Encapsulates the full DB lifecycle sequence previously embedded in
conftest.py's ``pytest_configure``: flush memcache, cleanup temp files,
purge DB, build schema, create base VO and root account, fix SQLite
permissions, restart httpd, bootstrap test data, sync RSEs, and sync
metadata.

All ``rucio.*`` imports are **lazy** (inside method bodies) because Rucio
modules trigger config loading and DB connections on import.
"""

import glob
import os
import shutil
import socket
import subprocess  # noqa: S404 -- used to drive docker compose / local tooling
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

    from .profiles import SuiteProfile


class InfraManager:
    """Orchestrates DB lifecycle and test-data bootstrap for a test suite.

    Parameters
    ----------
    profile:
        The resolved :class:`SuiteProfile` for the current test run.
    keep_db:
        When ``True``, :meth:`setup` returns immediately without
        performing any operations.  Used by ``--keep-db`` CLI flag.
    """

    def __init__(self, profile: "SuiteProfile", keep_db: bool = False) -> None:
        self._profile = profile
        self._keep_db = keep_db
        # Cached flag: whether the current DB is SQLite (set during purge)
        self._is_sqlite: "Optional[bool]" = None
        # Aggregate exit code of the per-VO multi_vo execution (run_multi_vo).
        # The outer forwarded session mirrors this so CI gates on the per-VO
        # xdist children rather than a redundant serial pass. 0 for non-multi_vo.
        self._multi_vo_rc: int = 0

    # Public API

    def setup(self) -> None:
        """Execute the full DB lifecycle sequence.

        Returns immediately when *keep_db* is ``True``.
        """
        if self._keep_db:
            print("[infra_manager] keep_db=True, skipping DB lifecycle")
            return

        print(f"\n[infra_manager] Setting up database for suite: {self._profile.name}")

        # Best-effort steps (swallow all exceptions)
        self._start_memcache()
        self._flush_memcache()
        self._cleanup_temp_files()

        # Critical steps (raise RuntimeError on failure)

        # multi_vo: mirror run_multi_vo_tests_docker.sh, which exports
        # RUCIO_HOME=/opt/rucio/etc/multi_vo/tst BEFORE running
        # reset_database.py. That makes create_root_account() execute under
        # multi_vo=True, so it provisions the `super_root` account (in the base
        # VO `def`) carrying the `ddmlab`/`secret` USERPASS identity. add_vo()
        # later copies super_root's identities onto each per-VO root -- which is
        # exactly what lets the client authenticate as root@<vo> with
        # ddmlab/secret. Generate the per-VO cfgs first (so the tst cfg exists),
        # then point RUCIO_HOME at it and drop the cached config singleton so
        # the whole base bring-up runs under the multi_vo config.
        if self._profile.name == "multi_vo":
            self._setup_multi_vo()
            self._activate_multi_vo_base_config()

        self._purge_database()
        self._build_database()
        self._create_base_vo_and_root_account()
        self._fix_sqlite_permissions()
        self._apply_votest_policy()
        # Generate both VO configs BEFORE httpd restart so the restart picks
        # them up. No-op for non-multi_vo suites; for multi_vo this already ran
        # above (idempotent regeneration is skipped here to avoid re-pointing).
        if self._profile.name != "multi_vo":
            self._setup_multi_vo()
        # multi_vo: make the LIVE SERVER cfg multi_vo-aware BEFORE the httpd
        # restart so the WSGI workers resolve the generic_multi_vo schema
        # (SCOPE_LENGTH=29) and the <scope>@<vo> internal scopes fit.
        if self._profile.name == "multi_vo":
            self._apply_multi_vo_server_config()
        self._restart_httpd()
        self._bootstrap_test_data()
        self._sync_rses()
        self._sync_metadata()

        # For the multi_vo suite, drive the legacy per-VO execution (tst, then
        # ts2 on tst success) as the FINAL step. This is the ONLY trigger for
        # run_multi_vo(); no plugin.py change is required (plugin already calls
        # manager.setup() in-container). No-op for other suites.
        if self._profile.name == "multi_vo":
            self._multi_vo_rc = self.run_multi_vo()

        print("[infra_manager] Database lifecycle complete\n")

    # Multi-VO setup + per-VO execution

    def _setup_multi_vo(self) -> None:
        """Generate both VO ``rucio.cfg`` files for the multi_vo suite.

        Reproduces the legacy ``test.sh`` two-merge step: merges
        ``rucio_autotests_common.cfg`` with each of the per-VO source cfgs
        into the live per-VO etc dirs
        (``/opt/rucio/etc/multi_vo/{tst,ts2}/etc/rucio.cfg``). Runs strictly
        BEFORE :meth:`_restart_httpd` so the restart picks up the new configs.

        No-op for non-multi_vo suites.

        :raises RuntimeError: when a source cfg is missing or a write fails.
        """
        if self._profile.name != "multi_vo":
            return

        from . import multi_vo_support

        # repo_root = in-container source dir (matches the convention used by
        # _apply_votest_policy / _sync_rses, which read RUCIO_SOURCE_DIR).
        repo_root = Path(os.environ.get("RUCIO_SOURCE_DIR", "/opt/rucio"))
        try:
            multi_vo_support.generate_multi_vo_configs(repo_root)
        except Exception as e:
            raise RuntimeError(
                f"[infra_manager] multi_vo config generation failed: {e}"
            ) from e
        print("[infra_manager] Generated multi_vo configs (tst, ts2)")

    def _activate_multi_vo_base_config(self) -> None:
        """Point ``RUCIO_HOME`` at the tst (multi_vo) cfg for the base bring-up.

        Mirrors ``run_multi_vo_tests_docker.sh`` exporting
        ``RUCIO_HOME=/opt/rucio/etc/multi_vo/tst`` before ``reset_database.py``.
        With that cfg active, ``common.multi_vo=True``, so
        :func:`create_root_account` provisions the ``super_root`` account in the
        base VO ``def`` (instead of ``root``) together with the ``ddmlab``/
        ``secret`` USERPASS identity. :func:`add_vo` later copies super_root's
        identities onto each per-VO root, which is what lets the client
        authenticate as ``root@<vo>`` with ``ddmlab``/``secret``.

        The tst cfg shares the default ``[database]`` target
        (``postgresql+psycopg://rucio:rucio@postgres14/rucio``, ``schema=dev``),
        so the cached DB session/engine keep operating on the same schema; only
        the config singleton needs dropping so ``multi_vo`` is re-read as True.

        Leg-aware: when ``RUCIO_MULTI_VO_LEG`` selects a single VO, the base
        bring-up activates THAT leg's per-VO cfg. For the ``ts2`` leg the base
        bring-up runs under the ts2 cfg so :meth:`_bootstrap_test_data`
        provisions ``testvo2`` (client ``vo=testvo2``); for ``tst`` (or when the
        selector is unset/unrecognized, which defaults to tst) it provisions
        ``testvo1``. Either way ``super_root``/``ddmlab`` in DEFAULT_VO ``def``
        is provisioned because both per-VO cfgs are ``multi_vo=True``. This
        keeps every 08-04 fix in force per leg (super_root/ddmlab, the
        generic_multi_vo server schema via :meth:`_apply_multi_vo_server_config`,
        the ``[alembic]`` carry-over, per-VO ``_flush_memcache`` in
        :meth:`bootstrap_vo`, and the GITHUB_ACTIONS numprocesses cap).
        """
        homes = {
            "tst": "/opt/rucio/etc/multi_vo/tst",
            "ts2": "/opt/rucio/etc/multi_vo/ts2",
        }
        leg = os.environ.get("RUCIO_MULTI_VO_LEG", "").strip()
        home = homes.get(leg, "/opt/rucio/etc/multi_vo/tst")
        os.environ["RUCIO_HOME"] = home
        try:
            from rucio.common.config import clean_cached_config
            clean_cached_config()
        except Exception as e:  # pragma: no cover - defensive
            print(f"[infra_manager] Warning: could not clear cached config: {e}")
        print(
            f"[infra_manager] multi_vo: RUCIO_HOME -> {home} "
            "(multi_vo=True active for base bring-up)"
        )

    def bootstrap_vo(self, vo_home: str) -> None:
        """Re-point ``RUCIO_HOME`` and bootstrap a single VO (no DB reset).

        Runs ONLY the bootstrap/sync steps -- deliberately NOT
        ``_purge_database``/``_build_database`` -- so the second VO (ts2)
        reuses the schema created for tst, mirroring
        ``run_multi_vo_tests_docker.sh`` (no 2nd DB reset).

        Drops the cached config singleton after re-pointing ``RUCIO_HOME`` so
        ``_bootstrap_test_data`` reads THIS VO's ``[client] vo`` (testvo1 vs
        testvo2) and ``[common] multi_vo=True``. Without the reload the parent
        process keeps the previous VO's cached config and ``add_vo`` for the
        second VO never runs -- so root@ts2 never inherits super_root's
        ``ddmlab`` identity. All per-VO cfgs share the same ``[database]``
        target (postgres14/rucio, schema=dev), so the cached DB session is
        unaffected.

        Also flushes memcache per VO, mirroring ``run_multi_vo_tests_docker.sh``
        which ``echo flush_all`` before each VO's bootstrap. The RSE-expression
        parser (``rucio.core.rse_expression_parser``) caches results under
        ``sha256(expression)`` with NO VO in the key, then filters by VO
        afterwards. When the tst run cached e.g. ``'MOCK'`` -> ``[MOCK@tst]``
        (ts2's MOCK not yet created), the ts2 leg would get that stale,
        VO-independent cache hit, filter it down to the empty set, and raise
        ``InvalidRSEExpression: ... resulted in an empty set`` for every
        ``rse_expression='MOCK'`` test (test_dataset_replicas et al.). Flushing
        between VOs forces a recompute so ts2 resolves ``MOCK@ts2``.
        """
        os.environ["RUCIO_HOME"] = vo_home
        try:
            from rucio.common.config import clean_cached_config
            clean_cached_config()
        except Exception as e:  # pragma: no cover - defensive
            print(f"[infra_manager] Warning: could not clear cached config: {e}")
        # Legacy parity: flush memcache before each VO bootstrap so the
        # VO-independent RSE-expression cache cannot bleed across VOs.
        self._flush_memcache()
        print(f"[infra_manager] Bootstrapping VO at RUCIO_HOME={vo_home}")
        self._create_base_vo_and_root_account()
        self._bootstrap_test_data()
        self._sync_rses()
        self._sync_metadata()

    def _apply_multi_vo_server_config(self) -> None:
        """Make the LIVE SERVER ``rucio.cfg`` multi_vo-aware before httpd restart.

        The httpd/WSGI server reads the entrypoint-generated
        ``/opt/rucio/etc/rucio.cfg``; its ``RUCIO_HOME=/opt/rucio`` is fixed when
        the daemon master starts, so re-pointing the harness env at the per-VO
        cfg does NOT change which cfg the server loads. That entrypoint cfg has
        no ``[common] multi_vo`` and no multi_vo schema, so the server resolves
        the SINGLE-VO schema (``generic`` -> ``SCOPE_LENGTH=25``). In multi_vo
        every request's internal scope is ``<scope>@<vo>`` (e.g. a 25-char scope
        + ``@tst`` = 29 chars), which overflows the 25-char
        ``TEMPORARY_SCOPE_NAME`` column the recursive-list / bulk-attach path
        builds -> ``psycopg StringDataRightTruncation``, surfaced to the client
        as the masked ``DatabaseException: An unknown Database Exception has
        occurred`` (e.g. ``test_did::test_list_recursive``). This is xdist-
        independent -- it fails identically under serial AND xdist execution.

        Legacy ``run_multi_vo_tests_docker.sh`` avoids it by running the server
        with ``RUCIO_HOME`` pointed at the tst (multi_vo) cfg, so the server uses
        ``generic_multi_vo`` (``SCOPE_LENGTH=29``). We mirror that by copying the
        multi_vo markers from the generated tst cfg into the live server cfg:
        ``[common] multi_vo=True`` and ``[policy] permission/schema=
        generic_multi_vo``. Must run BEFORE the httpd graceful restart so the new
        workers pick it up.
        """
        import configparser

        server_cfg = "/opt/rucio/etc/rucio.cfg"
        tst_cfg = "/opt/rucio/etc/multi_vo/tst/etc/rucio.cfg"
        if not os.path.exists(server_cfg):
            print(f"[infra_manager] multi_vo: server cfg not found: {server_cfg}")
            return

        tst = configparser.ConfigParser()
        tst.read(tst_cfg)

        cfg = configparser.ConfigParser()
        cfg.read(server_cfg)
        if not cfg.has_section("common"):
            cfg.add_section("common")
        cfg.set("common", "multi_vo", "True")
        if not cfg.has_section("policy"):
            cfg.add_section("policy")
        for key in ("permission", "schema"):
            value = tst.get("policy", key, fallback="generic_multi_vo")
            cfg.set("policy", key, value)

        with open(server_cfg, "w") as f:
            cfg.write(f)
        print(
            "[infra_manager] multi_vo: live server cfg -> multi_vo=True + "
            "generic_multi_vo schema (SCOPE_LENGTH=29)"
        )

    def _multi_vo_pytest_cmd(self, forward_stream: bool = False) -> list[str]:
        """Build the per-VO child pytest argv, mirroring the legacy multi_vo run.

        Legacy ``tools/run_multi_vo_tests_docker.sh`` runs each VO leg via
        ``tools/pytest.sh -v --tb=short``. That wrapper (and therefore the
        legacy multi_vo suite) executes with two properties our previous bare
        ``pytest tests/`` did NOT reproduce -- both are pure execution-model
        parity gaps in OUR harness, fixed here:

        1. **xdist (the noparallel scheduler).** ``tools/pytest.sh`` runs the
           suite under pytest-xdist (``--numprocesses=3`` on GitHub Actions,
           ``auto`` locally). With xdist present, ``tests/conftest.py`` registers
           the rucio noparallel scheduler, so ``@pytest.mark.noparallel`` tests
           are isolated/grouped exactly as under legacy. Our prior bare serial
           ``pytest tests/`` loaded NO xdist and NO scheduler -- a real
           execution-model delta vs legacy multi_vo that changes test ordering
           and cross-test isolation (the off-by-N shared-DB leaks and the
           cross-scope attach failures seen on noparallel tests trace to this).

        2. **exclusion of the Phase-8 plugin meta-tests.** This child runs
           WITHOUT ``--suite`` (the rucio plugin is dormant), so
           ``collection.py``'s ``exclude_paths`` filter -- which the in-process
           suites rely on -- never applies. The new meta-tests under
           ``tests/ruciopytest/`` (notably ``test_plugin_votest``, which
           re-enters ``pytest_configure`` -> ``InfraManager.setup`` and purges
           the LIVE DB mid-suite) would otherwise be collected and run here.
           Translate the profile's ``exclude_paths`` into ``--ignore`` /
           ``--ignore-glob`` so the child skips them -- matching what the
           in-process suites already do (legacy never carried these files at
           all, so this preserves legacy product-test selection exactly).
        """
        cmd = [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"]

        if self._profile.xdist_enabled:
            procs = "3" if os.environ.get("GITHUB_ACTIONS") == "true" else "auto"
            cmd += ["-p", "xdist", f"--numprocesses={procs}"]

        for pattern in self._profile.exclude_paths:
            cmd.append(f"--ignore-glob={pattern}")
            # A trailing '/*' pattern also names the directory itself; ignore it
            # outright so collection never descends into it.
            if pattern.endswith("/*"):
                cmd.append(f"--ignore={pattern[:-2]}")

        # When forwarding is active (the host launched the outer session with
        # RUCIO_FORWARD_STREAM set), make THIS child stream its per-test reports
        # back to the host's JSONL file. The child runs WITHOUT --suite, so the
        # main rucio plugin is dormant and never registers the emitter itself;
        # load the dedicated forwarder plugin explicitly so the host's junit
        # reflects this faithful xdist+noparallel execution (Session A) instead
        # of the suppressed serial outer pass.
        if forward_stream and os.environ.get("RUCIO_FORWARD_STREAM"):
            cmd += ["-p", "tests.ruciopytest.forward_stream_plugin"]

        return cmd

    def run_multi_vo(self) -> int:
        """Run the full ``tests/`` suite once per VO (tst, then ts2 on success).

        COMMITTED design: each VO leg is a CHILD ``python -m pytest`` process
        (mirrors ``run_multi_vo_tests_docker.sh``'s ``tools/pytest.sh -v
        --tb=short`` -- see :meth:`_multi_vo_pytest_cmd` for the xdist/exclusion
        parity). This keeps all ownership inside InfraManager with no plugin.py
        change. Legacy "stop if tst fails" semantics are preserved: ts2 only
        runs when tst passes, and there is NO 2nd DB reset.

        Single-leg selector: when ``RUCIO_MULTI_VO_LEG`` is ``tst`` or ``ts2``,
        this runs EXACTLY that one VO and returns its exit code. Because the leg
        has exactly one VO, that VO streams its reports to the host
        (``forward_stream=True``) with no duplicate-node-id risk. This is the
        harness contract the parallel-matrix workflow depends on: two runner
        jobs each run one VO leg. When the selector is unset (local/dev default)
        the sequential tst->ts2 path below is preserved unchanged.

        :returns: The exit code of the tst run if it failed, otherwise the ts2 code.
        """
        tst_home = "/opt/rucio/etc/multi_vo/tst"
        ts2_home = "/opt/rucio/etc/multi_vo/ts2"
        homes = {"tst": tst_home, "ts2": ts2_home}

        leg = os.environ.get("RUCIO_MULTI_VO_LEG", "").strip()
        if leg in homes:
            # Single-VO parallel leg: run exactly this one VO, streamed.
            cmd = self._multi_vo_pytest_cmd(forward_stream=True)
            self.bootstrap_vo(homes[leg])
            print(
                f"[infra_manager] Running tests for VO {leg} "
                "(single-leg selector)"
            )
            result = subprocess.run(
                cmd, env={**os.environ, "RUCIO_HOME": homes[leg]}
            )
            return result.returncode

        # The tst child streams its reports to the host (forward_stream=True) so
        # the host junit reflects the faithful xdist+noparallel execution. The
        # ts2 child does NOT stream: replaying the SAME node ids a second time
        # would corrupt the host junitxml (duplicate <testcase> per node). ts2
        # still runs and still gates -- its exit code is the aggregate return
        # below -- mirroring legacy's "tst must pass, then ts2 must pass".
        tst_cmd = self._multi_vo_pytest_cmd(forward_stream=True)
        ts2_cmd = self._multi_vo_pytest_cmd(forward_stream=False)

        # --- VO tst (streamed to host) ---
        self.bootstrap_vo(tst_home)
        print("[infra_manager] Running tests for VO tst")
        tst = subprocess.run(tst_cmd, env={**os.environ, "RUCIO_HOME": tst_home})
        if tst.returncode != 0:
            print(
                f"[infra_manager] tst VO failed (rc={tst.returncode}); "
                "not attempting ts2"
            )
            return tst.returncode

        # --- VO ts2 (only on tst success; no DB reset; not streamed) ---
        self.bootstrap_vo(ts2_home)
        print("[infra_manager] Running tests for VO ts2")
        ts2_env = {**os.environ, "RUCIO_HOME": ts2_home}
        ts2_env.pop("RUCIO_FORWARD_STREAM", None)
        ts2 = subprocess.run(ts2_cmd, env=ts2_env)
        return ts2.returncode

    # Best-effort steps

    def _start_memcache(self) -> None:
        """Start a local ``memcached`` daemon (best-effort, legacy parity).

        The live server rucio.cfg leaves ``[cache] url`` at its default
        ``127.0.0.1:11211`` (see :data:`rucio.common.cache.CACHE_URL`), so the
        dogpile ``MemcacheRegion`` used by the RSE-expression parser, the OIDC
        token cache, and the judge daemon expects a memcached listening on
        localhost INSIDE the container. Legacy ``tools/run_tests.sh`` starts it
        (``memcached -u root -d``) at the top of every run; the plugin's
        in-container bring-up replaces run_tests.sh, so we must start it here.

        Without this, anything cache-backed fails in our suite but passes under
        legacy: ``test_oidc::test_token_cache`` (set/get round-trips to a dead
        socket -> get returns ``None``), ``TestJudgeRepairer`` (``region.delete``
        raises ``ConnectionRefused [Errno 111]``), and
        ``test_cli_client_structure::test_rse`` (a cache MISS re-evaluates a
        just-removed RSE expression to the empty set -> ``InvalidRSEExpression``
        instead of returning the cached result). Idempotent: if memcached is
        already listening on 11211 this is a no-op.
        """
        # Already up? (e.g. entrypoint started it, or a previous setup pass.)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect(('127.0.0.1', 11211))
            print("[infra_manager] memcached already running on 11211")
            return
        except Exception:
            pass

        # Mirror tools/run_tests.sh: `memcached -u root -d`.
        try:
            subprocess.run(['memcached', '-u', 'root', '-d'], check=False,  # noqa: S607 -- memcached resolved from the container PATH
                           capture_output=True, timeout=10)
        except FileNotFoundError:
            print("[infra_manager] Warning: memcached not found, skipping start")
            return
        except Exception as e:
            print(f"[infra_manager] Warning: could not start memcached: {e}")
            return

        # Wait (up to ~10s) for the daemon to accept connections.
        for _ in range(10):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    sock.connect(('127.0.0.1', 11211))
                print("[infra_manager] memcached started on 11211")
                return
            except Exception:
                time.sleep(1)
        print("[infra_manager] Warning: memcached did not become ready on 11211")

    def _flush_memcache(self) -> None:
        """Send ``flush_all`` to a local memcache instance (best-effort)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect(('127.0.0.1', 11211))
                sock.sendall(b'flush_all\r\n')
            print("[infra_manager] Memcache cleared")
        except Exception:
            pass  # Not critical, memcache might not be running

    def _cleanup_temp_files(self) -> None:
        """Remove authentication tokens, RSE dirs, and .pyc files."""
        # Clean authentication tokens
        for pattern in ['/tmp/.rucio_*']:
            try:
                for path in glob.glob(pattern):
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
            except Exception:
                pass  # Not critical

        # Clean RSE directories
        try:
            rse_dir = '/tmp/rucio_rse'
            if os.path.exists(rse_dir):
                shutil.rmtree(rse_dir, ignore_errors=True)
                os.makedirs(rse_dir, exist_ok=True)
        except Exception:
            pass  # Not critical

        # Clean .pyc files
        try:
            subprocess.run(
                ['find', 'lib', '-iname', '*.pyc', '-delete'],  # noqa: S607 -- find resolved from the container PATH
                check=False, capture_output=True, timeout=5,
            )
        except Exception:
            pass  # Not critical

        print("[infra_manager] Temp file cleanup completed")

    # Critical DB steps

    def _purge_database(self) -> None:
        """Purge the database: delete SQLite file or call ``purge_db()``.

        Raises :class:`RuntimeError` on unrecoverable failure.
        """
        print("[infra_manager] Resetting database tables")

        if self._profile.rdbms == "sqlite":
            self._is_sqlite = True
            self._delete_sqlite_file()

        elif self._profile.name == "remote_dbs":
            self._is_sqlite = False
            self._purge_remote_db()

        else:
            # Auto-detect from engine URL
            from rucio.db.sqla.session import get_engine
            engine = get_engine()
            self._is_sqlite = 'sqlite' in str(engine.url).lower()

            if self._is_sqlite:
                print("[infra_manager] Detected SQLite, deleting database file")
                self._delete_sqlite_file()
            else:
                print("[infra_manager] Detected remote database, purging")
                self._purge_remote_db()

    def _delete_sqlite_file(self) -> None:
        """Delete the SQLite database file at ``/tmp/rucio.db``."""
        db_path = '/tmp/rucio.db'
        if os.path.exists(db_path):
            print(f"[infra_manager] Removing old SQLite database: {db_path}")
            try:
                os.remove(db_path)
                print(f"[infra_manager] SQLite database {db_path} deleted successfully")
            except Exception as e:
                print(f"[infra_manager] Warning: Could not remove {db_path}: {e}")
        else:
            print(f"[infra_manager] SQLite database {db_path} does not exist (will be created fresh)")

    def _purge_remote_db(self) -> None:
        """Purge a remote database, tolerating fresh-database errors."""
        from rucio.db.sqla.util import purge_db

        try:
            purge_db()
            print("[infra_manager] Database purge completed")
        except Exception as e:
            error_str = str(e).lower()
            if 'does not exist' in error_str or 'invalidschemaname' in error_str:
                print("[infra_manager] Schema doesn't exist (fresh database), skipping purge")
            else:
                print(f"[infra_manager] Database purge failed: {e}")
                import traceback
                traceback.print_exc()
                raise RuntimeError("Failed to purge database") from e

    def _build_database(self) -> None:
        """Build database schema and tables via ``build_database()``.

        Raises :class:`RuntimeError` on failure.
        """
        from rucio.db.sqla.util import build_database

        try:
            print("[infra_manager] Building database schema and tables")
            build_database()
            print("[infra_manager] Database build completed")
        except Exception as e:
            print(f"[infra_manager] Database build failed: {e}")
            import traceback
            traceback.print_exc()
            raise RuntimeError("Failed to build database") from e

    @staticmethod
    def _is_already_exists_error(exc: Exception) -> bool:
        """Return ``True`` when *exc* signals an idempotent already-exists insert.

        The multi_vo suite bootstraps each VO (tst, then ts2) against the SAME
        shared schema after the main setup already created the base VO ``def``
        and the root account. The per-VO re-create therefore hits a uniqueness
        violation (e.g. ``UniqueViolation`` on ``VOS_PK``) -- which is benign and
        must be swallowed rather than aborting collection.
        """
        from rucio.common.exception import Duplicate, RucioException

        if isinstance(exc, (Duplicate, RucioException)):
            text = str(exc).lower()
            if "duplicate" in text or "already exists" in text or "unique" in text:
                return True
        # SQLAlchemy IntegrityError / driver UniqueViolation surface by message.
        text = (str(exc) + " " + type(exc).__name__).lower()
        return (
            "uniqueviolation" in text
            or "integrityerror" in text
            or "duplicate key" in text
            or "already exists" in text
        )

    def _create_base_vo_and_root_account(self) -> None:
        """Create the base VO and root account (idempotent).

        Tolerates already-exists violations so the multi_vo per-VO bootstrap
        (which reuses the schema/data created by the main setup) does not crash
        on the second pass. Raises :class:`RuntimeError` only on genuine errors.
        """
        from rucio.db.sqla.session import get_session
        from rucio.db.sqla.util import create_base_vo, create_root_account

        print("[infra_manager] Creating base VO and root account")

        for label, fn in (("base VO", create_base_vo), ("root account", create_root_account)):
            try:
                fn()
                print(f"[infra_manager] Created {label}")
            except Exception as e:
                if self._is_already_exists_error(e):
                    print(f"[infra_manager] {label} already exists, skipping")
                    # A failed INSERT may leave the scoped session in an aborted
                    # transaction; roll it back so subsequent work can proceed.
                    try:
                        get_session().remove()
                    except Exception:
                        pass
                    continue
                print(f"[infra_manager] Failed to create {label}: {e}")
                import traceback
                traceback.print_exc()
                raise RuntimeError("Failed to build database") from e

        print("[infra_manager] Base VO and root account ready")

    def _fix_sqlite_permissions(self) -> None:
        """Set ``/tmp/rucio.db`` to world-readable/writable (0o666).

        Only runs when the database is SQLite.
        """
        if not self._is_sqlite:
            return

        db_path = '/tmp/rucio.db'
        if os.path.exists(db_path):
            print(f"[infra_manager] Setting SQLite database permissions: {db_path}")
            os.chmod(db_path, 0o666)  # noqa: S103 -- sqlite file must stay writable across differing container UIDs

    def _resolve_live_rucio_cfg(self) -> str:
        """Return the path to the live server ``rucio.cfg`` inside the container.

        Tries, in order:
          1. ``$RUCIO_HOME/etc/rucio.cfg`` -- the container install layout.
          2. ``$RUCIO_HOME/rucio.cfg``    -- RUCIO_HOME already pointed at etc/.
          3. ``/opt/rucio/etc/rucio.cfg`` -- the standard container fallback when
             RUCIO_HOME was inherited from the host and is not a real path here.

        The first existing candidate wins; otherwise the first candidate is
        returned so the caller can raise a clear "not found" error.
        """
        rucio_home = os.environ.get("RUCIO_HOME", "/opt/rucio")
        candidates = [
            os.path.join(rucio_home, "etc", "rucio.cfg"),
            os.path.join(rucio_home, "rucio.cfg"),
            "/opt/rucio/etc/rucio.cfg",
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        return candidates[0]

    def _apply_votest_policy(self) -> None:
        """Rewrite the live rucio.cfg ``[policy]`` section for votest.

        Runs only for the votest suite when a policy is set. The rewrite must
        happen before the httpd restart so the server picks up the new config.
        No policy-package pip install is performed (live CI installs none; the
        rewrite alone is sufficient).

        :raises RuntimeError: if the live ``rucio.cfg`` or the matrix YAML is missing.
        """
        if not self._profile.policy or self._profile.name != "votest":
            return

        # Resolve the live server rucio.cfg that httpd reads. Inside the runtime
        # container the layout is ``$RUCIO_HOME/etc/rucio.cfg`` (RUCIO_HOME is the
        # install root, e.g. /opt/rucio -- NOT the etc dir). When the forwarded
        # run inherits a host RUCIO_HOME (e.g. /home/runner/work/rucio/rucio),
        # that path does not exist in the container, so fall back to the standard
        # container location. The rewrite must target the cfg the server actually
        # loads so the httpd restart below picks up the new [policy] section.
        rucio_cfg = self._resolve_live_rucio_cfg()
        matrix_path = (
            Path(os.environ["RUCIO_SOURCE_DIR"])
            / "etc/docker/test/matrix_policy_package_tests.yml"
        )

        if not os.path.exists(rucio_cfg):
            raise RuntimeError(
                f"[infra_manager] votest: live rucio.cfg not found: {rucio_cfg}"
            )
        if not matrix_path.exists():
            raise RuntimeError(
                f"[infra_manager] votest: matrix YAML not found: {matrix_path}"
            )

        from . import votest_support

        matrix = votest_support.load_matrix(matrix_path)
        votest_support.rewrite_policy_section(
            rucio_cfg, matrix[self._profile.policy]["config_overrides"]
        )
        print(f"[infra_manager] Rewrote [policy] for votest policy={self._profile.policy}")

    def _restart_httpd(self) -> None:
        """Gracefully restart Apache httpd and wait for readiness.

        Raises :class:`RuntimeError` on ``CalledProcessError``.
        Silently skips when httpd is not installed (``FileNotFoundError``).
        """
        try:
            subprocess.run(['httpd', '-k', 'graceful'], check=True, capture_output=True)  # noqa: S607 -- httpd resolved from the container PATH
            print("[infra_manager] Apache httpd restarted")
            time.sleep(2)
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Failed to restart httpd") from e
        except FileNotFoundError:
            print("[infra_manager] Warning: httpd not found, skipping Apache restart")

    # Bootstrap steps

    def _bootstrap_test_data(self) -> None:
        """Create accounts, scopes, and multi-VO setup.

        Mirrors the ``_run_bootstrap_tests()`` helper in conftest.py.
        Raises :class:`RuntimeError` on failure.
        """
        from rucio.client import Client
        from rucio.common.config import config_get, config_get_bool
        from rucio.common.constants import DEFAULT_VO
        from rucio.common.exception import Duplicate, DuplicateContent, RucioException
        from rucio.common.types import InternalAccount
        from rucio.common.utils import extract_scope
        from rucio.core.account import add_account_attribute
        from rucio.core.vo import map_vo
        from rucio.db.sqla.constants import DatabaseOperationType
        from rucio.db.sqla.session import db_session
        from rucio.gateway.vo import add_vo
        from rucio.tests.common_server import reset_config_table

        try:
            print("[infra_manager] Bootstrapping test data")

            # Create config table including the long VO mappings
            reset_config_table()

            if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
                vo = {'vo': map_vo(config_get('client', 'vo', raise_exception=False, default='tst'))}
                try:
                    add_vo(
                        new_vo=vo['vo'],
                        issuer='super_root',
                        description='A VO to test multi-vo features',
                        email='N/A',
                        vo=DEFAULT_VO,
                    )
                except Duplicate:
                    print(f'[infra_manager] VO {vo["vo"]} already added')
            else:
                vo = {}

            try:
                client = Client()
            except RucioException as e:
                error_msg = str(e)
                print(f'[infra_manager] Creating client failed: {error_msg}')
                if 'Internal Server Error' in error_msg:
                    server_log = '/var/log/rucio/httpd_error_log'
                    if os.path.exists(server_log):
                        time.sleep(5)
                        with open(server_log, 'r') as fhandle:
                            print(fhandle.readlines()[-200:], file=sys.stderr)
                raise

            try:
                client.add_account('jdoe', 'SERVICE', 'jdoe@email.com')
            except Duplicate:
                print('[infra_manager] Account jdoe already added')

            try:
                with db_session(DatabaseOperationType.WRITE) as session:
                    add_account_attribute(account=InternalAccount('root', **vo), key='admin', value=True, session=session)  # bypass client as schema validation fails at API level
            except Exception as error:
                print(f'[infra_manager] {error}')

            try:
                client.add_account('panda', 'SERVICE', 'panda@email.com')
                with db_session(DatabaseOperationType.WRITE) as session:
                    add_account_attribute(account=InternalAccount('panda', **vo), key='admin', value=True, session=session)  # bypass client as schema validation fails at API level
            except Duplicate:
                print('[infra_manager] Account panda already added')

            try:
                client.add_scope('jdoe', 'mock')
            except Duplicate:
                print('[infra_manager] Scope mock already added')

            try:
                client.add_scope('root', 'archive')
            except Duplicate:
                print('[infra_manager] Scope archive already added')

            # The belleii votest DIRAC tests build LFNs under ``/belle`` and
            # resolve their scope against the set of EXISTING scopes, then require
            # that scope + the ``/belle*`` container DID hierarchy to exist (see
            # lib/rucio/core/dirac.py). Upstream provisions these in a separate
            # bootstrap step (tools/bootstrap_tests.py::belleii_bootstrap); the
            # plugin path must do the same, otherwise the DIRAC tests raise
            # ScopeNotFound. Ported verbatim from belleii_bootstrap(), kept
            # idempotent (Duplicate/DuplicateContent tolerant).
            if self._profile.policy == 'belleii':
                print('[infra_manager] Bootstrapping belleii scopes and /belle DID hierarchy')
                belleii_scopes = ['raw', 'hraw', 'other', 'mc_tmp', 'mc', 'test',
                                  'user', 'data', 'data_tmp', 'group', 'mock']
                for scope in belleii_scopes:
                    try:
                        client.add_scope(scope=scope, account='root')
                    except Duplicate:
                        pass
                    except Exception as err:
                        print(f'[infra_manager] {err}')

                belleii_lpns = ['/belle', '/belle/mc', '/belle/Data', '/belle/user',
                                '/belle/raw', '/belle/mock']
                for lpn in belleii_lpns:
                    scope, name = extract_scope(lpn)
                    try:
                        client.add_did(scope=scope, name=name, did_type='CONTAINER')
                    except Duplicate:
                        pass
                    except Exception as err:
                        print(f'[infra_manager] {err}')
                    if name != '/belle':
                        try:
                            client.attach_dids(scope='other', name='/belle',
                                               dids=[{'scope': str(scope), 'name': str(name)}])
                        except DuplicateContent:
                            pass
                        except Exception as err:
                            print(f'[infra_manager] {err}')

            print("[infra_manager] Test data bootstrap completed")

        except Exception as e:
            print(f"[infra_manager] Bootstrap failed: {e}")
            import traceback
            traceback.print_exc()
            raise RuntimeError("Failed to bootstrap test data") from e

    def _sync_rses(self) -> None:
        """Load RSE repository JSON and create RSEs via Client.

        Uses ``etc/rse_repository.json`` by default; falls back to
        ``etc/rse_repository.json.special`` for the *special* suite.
        Raises :class:`RuntimeError` on failure.
        """
        import json
        import traceback as tb

        from rucio.client import Client
        from rucio.common.exception import Duplicate

        try:
            print("[infra_manager] Syncing RSE repository")

            # Resolve paths relative to source dir when running inside
            # a container (CWD=/opt/rucio, source at /rucio_source).
            source_dir = os.environ.get('RUCIO_SOURCE_DIR', '')
            if self._profile.name == "special":
                special = os.path.join(source_dir, 'etc/rse_repository.json.special')
                if os.path.exists(special):
                    rse_repo = special
                else:
                    rse_repo = os.path.join(source_dir, 'etc/rse_repository.json')
            else:
                rse_repo = os.path.join(source_dir, 'etc/rse_repository.json')

            with open(rse_repo) as f:
                rses_list = json.load(f)

            c = Client()

            for rse in rses_list:
                try:
                    c.add_rse(rse)
                except Duplicate:
                    pass
                except Exception:
                    print("[infra_manager] Failed to add RSE " + rse)
                    tb.print_exc()

                try:
                    supported = rses_list[rse]['protocols'].get('supported', {})
                    for scheme, proto in supported.items():
                        try:
                            c.add_protocol(rse, {**proto, 'scheme': scheme})
                        except Duplicate:
                            pass
                        except Exception:
                            print("[infra_manager] Failed to add protocol to RSE " + rse + ": " + scheme)
                            tb.print_exc()
                except KeyError:
                    pass

                try:
                    for attr in rses_list[rse]['attributes']:
                        try:
                            c.add_rse_attribute(rse, attr, rses_list[rse]['attributes'][attr])
                        except Duplicate:
                            pass
                        except Exception:
                            print("[infra_manager] Failed to add attribute " + attr + " to RSE " + rse)
                            tb.print_exc()
                except KeyError:
                    pass

            print("[infra_manager] RSE repository sync completed")

        except Exception as e:
            print(f"[infra_manager] RSE sync failed: {e}")
            import traceback
            traceback.print_exc()
            raise RuntimeError("Failed to sync RSE repository") from e

    def _sync_metadata(self) -> None:
        """Create DID metadata keys via Client.

        Raises :class:`RuntimeError` on failure.
        """
        import traceback as tb

        from rucio.client import Client
        from rucio.common.exception import Duplicate

        try:
            print("[infra_manager] Syncing metadata keys")

            meta_keys = [
                ('project', 'ALL', None, ['data13_hip', 'NoProjectDefined']),
                ('run_number', 'ALL', None, ['NoRunNumberDefined']),
                ('stream_name', 'ALL', None, ['NoStreamNameDefined']),
                ('prod_step', 'ALL', None, ['merge', 'recon', 'simul', 'evgen', 'NoProdstepDefined', 'user']),
                ('datatype', 'ALL', None, ['HITS', 'AOD', 'EVNT', 'NTUP_TRIG', 'NTUP_SMWZ', 'NoDatatypeDefined', 'DPD']),
                ('version', 'ALL', None, []),
                ('campaign', 'ALL', None, []),
                ('guid', 'FILE', r'^(\{){0,1}[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}(\}){0,1}$', []),
                ('events', 'DERIVED', r'^\d+$', []),
            ]

            c = Client()

            for key, key_type, value_regexp, values in meta_keys:
                try:
                    c.add_key(key, key_type, value_regexp=value_regexp)
                except Duplicate:
                    pass
                except Exception:
                    print("[infra_manager] Failed to add key " + key)
                    tb.print_exc()

                for value in values:
                    try:
                        c.add_value(key, value)
                    except Duplicate:
                        pass
                    except Exception:
                        print("[infra_manager] Failed to add value " + value + " to key " + key)
                        tb.print_exc()

                    # Legacy parity: tools/sync_meta.py creates a scope named
                    # after every ``project`` value (``c.add_scope('root',
                    # value)``). This is how the hardcoded ``data13_hip`` scope
                    # used by test_reaper / test_did exists under legacy. Without
                    # it those tests hit ``ForeignKeyViolation: Key
                    # (scope)=(data13_hip) is not present in table "scopes"``.
                    if key == 'project':
                        try:
                            c.add_scope('root', value)
                        except Duplicate:
                            pass
                        except Exception:
                            print("[infra_manager] Failed to add scope " + value)
                            tb.print_exc()

            print("[infra_manager] Metadata sync completed\n")

        except Exception as e:
            print(f"[infra_manager] Metadata sync failed: {e}")
            import traceback
            traceback.print_exc()
            raise RuntimeError("Failed to sync metadata") from e
