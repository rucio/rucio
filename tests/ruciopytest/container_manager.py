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

"""Docker Compose container lifecycle manager for Rucio test suites.

This module runs on the **host side** -- it manages Docker containers from
the pytest process running on the host (or CI runner).  It does NOT run
inside a container; the rucio container has no Docker socket access.

Lifecycle:
    1. Detect and remove orphaned ``rucio-test-*`` compose projects
    2. ``docker compose up -d --wait`` with the correct project name,
       compose files, and profiles
    3. Wait for httpd readiness inside the rucio container
    4. Run tests (handled by pytest, not this module)
    5. ``docker compose down -v`` on session end, signal, or atexit
"""

import atexit
import json
import os
import signal
import subprocess  # noqa: S404 -- used to drive docker compose
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class ContainerManager:
    """Manages Docker Compose container lifecycle for a test suite.

    Parameters
    ----------
    project_name:
        Compose project name, e.g. ``rucio-test-remote_dbs-postgres14``.
    profiles:
        Tuple of compose profile names to activate (from
        ``SuiteProfile.compose_profiles``).
    root_dir:
        Repository root directory (``config.rootdir``).  Compose file
        paths are resolved relative to this directory to avoid
        CWD-relative path issues (Pitfall 5).
    """

    COMPOSE_DIR = "etc/docker/dev"
    COMPOSE_FILES = (
        "docker-compose.yml",
        "docker-compose.test.override.yml",
    )
    PROJECT_PREFIX = "rucio-test-"
    LOG_DIR = ".test-logs"
    TEST_DOCKERFILE = "etc/docker/test/runtime.Dockerfile"

    def __init__(
        self,
        project_name: str,
        profiles: tuple[str, ...],
        root_dir: str,
    ) -> None:
        self._project_name = project_name
        self._profiles = profiles
        self._root_dir = root_dir
        self._started = False
        self._cleaned_up = False
        self._original_sigterm: "Any" = None
        self._original_sigint: "Any" = None

    # Public API

    @property
    def project_name(self) -> str:
        """The compose project name."""
        return self._project_name

    @property
    def log_dir(self) -> Path:
        """Path to the container log output directory."""
        return Path(self._root_dir) / self.LOG_DIR

    def start(self) -> None:
        """Start containers: clean orphans, build/pull, compose up, readiness check."""
        self._ensure_network_name_env()
        self._ensure_container_name_env()
        self._register_cleanup_handlers()
        self._cleanup_orphans()
        self._compose_build()
        self._compose_up()
        self._started = True
        self._install_rucio_from_source()
        self._bootstrap_rucio_home()
        self._restart_httpd()
        self._wait_for_readiness()

    def stop(self, capture_logs: bool = True) -> None:
        """Stop and remove containers.

        Idempotent -- subsequent calls are no-ops (Pitfall 3).
        """
        if self._cleaned_up:
            return
        self._cleaned_up = True

        if capture_logs and self._started:
            self._capture_logs()

        self._compose_down()
        self._restore_signal_handlers()

    @staticmethod
    def make_project_name(
        suite_name: str, rdbms: str, vo: "str | None" = None
    ) -> str:
        """Build a compose project name from suite, RDBMS, and optional VO.

        Returns a string like ``rucio-test-remote_dbs-postgres14``
        (SUIT-05). When ``vo`` is truthy, the VO is inserted to yield a
        per-VO-unique name like ``rucio-test-multi_vo-tst-postgres14``.

        The per-VO variant keeps the compose *network* name unique per VO too
        (the network name derives from the project name), so two multi_vo VO
        legs (tst, ts2) can run as parallel matrix legs without their compose
        stacks colliding. ``PROJECT_PREFIX`` is unchanged either way, so
        orphan-cleanup still matches on ``rucio-test-``.
        """
        if vo:
            return f"rucio-test-{suite_name}-{vo}-{rdbms}"
        return f"rucio-test-{suite_name}-{rdbms}"

    # Environment setup

    def _compose_build(self) -> None:
        """Build the rucio test image from source if not already built.

        The test override compose file defines a ``build`` section for the
        rucio service.  If ``RUCIO_TEST_IMAGE`` is set, compose will skip
        the build when the image already exists.  Otherwise it builds from
        ``etc/docker/test/runtime.Dockerfile``.
        """
        cmd = self._compose_cmd("build", "rucio")
        print("[container_manager] Building rucio test image from source...")
        try:
            result = subprocess.run(
                cmd,
                # The py3.10 image builds boost + gfal2-python from source
                # (no prebuilt gfal2-python3 package for 3.10), which runs
                # ~9-10 min and sits right at the old 600s ceiling -- causing
                # intermittent "Timed out building rucio test image" failures
                # on slower runners. 1200s gives that from-source build headroom.
                timeout=1200,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Timed out building rucio test image")

        if result.returncode != 0:
            raise RuntimeError("Failed to build rucio test image")

        print("[container_manager] Image build complete")

    def _install_rucio_from_source(self) -> None:
        """Install rucio from the mounted source inside the container.

        The volume-mounted source at ``/rucio_source`` may differ from what
        was baked into the image.  A dev-install ensures the container runs
        the current working-tree code.
        """
        print("[container_manager] Installing rucio from source in container...")
        cmd = self._compose_cmd(
            "exec", "-T", "rucio",
            "pip", "install", "--no-cache-dir", "-e", "/rucio_source",
        )
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            print("[container_manager] Warning: pip install timed out")
            return

        if result.returncode != 0:
            print(f"[container_manager] Warning: pip install failed:\n{result.stderr}")
        else:
            print("[container_manager] Rucio installed from source")

    def _bootstrap_rucio_home(self) -> None:
        """Bridge the mounted source ``bin/`` and ``etc/`` into ``RUCIO_HOME``.

        The dev compose mounts the repo at ``/rucio_source`` while
        ``RUCIO_HOME=/opt/rucio``, and the container entrypoint only generates
        ``rucio.cfg``/``alembic.ini`` there. Legacy autotest instead runs from a
        ``/opt/rucio`` that already contains the full source tree, so tests can
        resolve the ``rucio`` CLI on ``PATH`` and read fixtures under
        ``$RUCIO_HOME/etc`` (``mail_templates/``, ``rse_repository.json``,
        ``google-cloud-storage-test.json``, ...). Without this bridge the
        forwarded suites hit ``rucio: command not found`` (exit 127) on every
        CLI test and ``FileNotFoundError`` on every fixture lookup.

        Symlink the source ``bin/*`` onto the venv ``bin`` (already first on
        ``PATH``) and fill in any *missing* ``$RUCIO_HOME/etc`` entries -- never
        clobbering the entrypoint-generated ``rucio.cfg``/``alembic.ini``.
        """
        script = (
            "ln -sf /rucio_source/bin/* /opt/venv/bin/ 2>/dev/null || true; "
            "for f in /rucio_source/etc/*; do "
            'n=$(basename "$f"); '
            '[ -e "/opt/rucio/etc/$n" ] || ln -sf "$f" "/opt/rucio/etc/$n"; '
            "done"
        )
        cmd = self._compose_cmd("exec", "-T", "rucio", "bash", "-c", script)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            print("[container_manager] Warning: RUCIO_HOME bootstrap timed out")
            return

        if result.returncode != 0:
            print(
                "[container_manager] Warning: RUCIO_HOME bootstrap failed:\n"
                f"{result.stderr}"
            )
        else:
            print("[container_manager] Bridged source bin/ + etc/ into RUCIO_HOME")

    def _restart_httpd(self) -> None:
        """Restart httpd inside the rucio container after rucio installation."""
        cmd = self._compose_cmd(
            "exec", "-T", "rucio",
            "httpd", "-k", "graceful",
        )
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print("[container_manager] httpd restarted")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[container_manager] Warning: could not restart httpd")

    def _ensure_network_name_env(self) -> None:
        """Set ``RUCIO_NETWORK_NAME`` to a project-specific value.

        The compose file uses ``${RUCIO_NETWORK_NAME:-ruciodevnetwork}``
        for the default network.  Without a unique name per project,
        multiple compose projects would share a network or conflict.
        """
        if os.environ.get("RUCIO_NETWORK_NAME"):
            return
        os.environ["RUCIO_NETWORK_NAME"] = f"{self._project_name}-network"

    def _ensure_container_name_env(self) -> None:
        """Project-scope the parameterized ``container_name`` fields.

        The dev compose file uses ``${RUCIO_<SVC>_CONTAINER_NAME:-dev-<svc>-1}``
        for its container names.  Without unique names per project, parallel
        compose projects would collide on container names.  Only set when
        unset (an explicit override wins); with none set, compose defaults
        (``dev-<svc>-1``) apply and existing flows are unchanged.
        """
        container_name_vars = {
            "rucio": "RUCIO_HTTPD_CONTAINER_NAME",
            "rucioclient": "RUCIO_RUCIOCLIENT_CONTAINER_NAME",
            "ruciodb": "RUCIO_RUCIODB_CONTAINER_NAME",
            "postgres14": "RUCIO_POSTGRES14_CONTAINER_NAME",
        }
        for svc, var in container_name_vars.items():
            if os.environ.get(var):
                continue
            os.environ[var] = f"{self._project_name}-{svc}-1"

    # Compose command builder

    def _compose_cmd(self, *args: str) -> list[str]:
        """Build a full ``docker compose`` command with project/file/profile flags."""
        cmd = ["docker", "compose", "-p", self._project_name]
        for fname in self.COMPOSE_FILES:
            fpath = os.path.join(self._root_dir, self.COMPOSE_DIR, fname)
            cmd.extend(["-f", fpath])
        for profile in self._profiles:
            cmd.extend(["--profile", profile])
        cmd.extend(args)
        return cmd

    # Lifecycle methods

    def _cleanup_orphans(self) -> None:
        """Detect and remove orphaned ``rucio-test-*`` compose projects."""
        try:
            result = subprocess.run(
                ["docker", "compose", "ls", "--format", "json", "-a"],  # noqa: S607 -- docker resolved from PATH
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"[container_manager] Warning: could not list compose projects: {exc}")
            return

        if result.returncode != 0:
            print("[container_manager] Warning: could not list compose projects")
            return

        try:
            projects = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("[container_manager] Warning: could not parse compose project list")
            return

        for project in projects:
            name = project.get("Name", "")
            if name.startswith(self.PROJECT_PREFIX):
                print(f"[container_manager] Removing orphaned project: {name}")
                try:
                    down_cmd = ["docker", "compose", "-p", name]
                    config_files = project.get("ConfigFiles", "")
                    if config_files:
                        for cf in config_files.split(","):
                            cf = cf.strip()
                            if cf:
                                down_cmd.extend(["-f", cf])
                    down_cmd.extend(["down", "-v", "-t", "10"])
                    subprocess.run(
                        down_cmd,
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    print(f"[container_manager] Warning: failed to remove orphan {name}")

    def _compose_up(self) -> None:
        """Run ``docker compose up -d --wait`` and raise on failure."""
        cmd = self._compose_cmd("up", "-d", "--wait", "--wait-timeout", "120")
        print(f"[container_manager] Starting containers: {self._project_name}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Timed out waiting for containers to start: {self._project_name}"
            )

        if result.returncode != 0:
            print(f"[container_manager] compose up failed:\n{result.stderr}")
            raise RuntimeError(f"Failed to start containers: {result.stderr}")

        print("[container_manager] Containers started and healthy")

    def _wait_for_readiness(self) -> None:
        """Wait for httpd readiness inside the rucio container.

        Database readiness is handled by ``docker compose up --wait``
        which respects the healthcheck blocks in docker-compose.yml.
        This method adds an extra check for httpd (Apache) inside the
        rucio service container.
        """
        cmd = self._compose_cmd(
            "exec", "-T", "rucio",
            "curl",
            "--retry", "15",
            "--retry-all-errors",
            "--retry-delay", "2",
            "-k", "-s", "-o", "/dev/null",
            "-w", "%{http_code}",
            "https://localhost/ping",
        )
        print("[container_manager] Waiting for httpd readiness...")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("httpd readiness check timed out")

        if result.returncode != 0:
            print(f"[container_manager] httpd readiness check failed:\n{result.stderr}")
            raise RuntimeError(f"httpd readiness check failed: {result.stderr}")

        print("[container_manager] httpd is ready")

    def _compose_down(self) -> None:
        """Run ``docker compose down -v`` (best-effort, does not raise)."""
        cmd = self._compose_cmd("down", "-v", "-t", "30")
        print(f"[container_manager] Stopping containers: {self._project_name}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                start_new_session=True,
            )
            if result.returncode != 0:
                print(
                    f"[container_manager] Warning: compose down returned "
                    f"exit code {result.returncode}: {result.stderr}"
                )
            else:
                print("[container_manager] Containers stopped and removed")
        except subprocess.TimeoutExpired:
            print("[container_manager] Warning: compose down timed out")
        except FileNotFoundError:
            print("[container_manager] Warning: docker not found during cleanup")

    def _capture_logs(self) -> None:
        """Capture container logs to .test-logs/ directory.

        Saves a combined log file (all services) and individual per-service
        log files.  All errors are handled gracefully -- log capture must
        never prevent cleanup.
        """
        log_dir = self.log_dir
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"[container_manager] Warning: could not create log directory: {exc}")
            return

        # Combined log from all services
        try:
            result = subprocess.run(
                self._compose_cmd("logs", "--no-color", "--timestamps"),
                capture_output=True,
                text=True,
                timeout=60,
            )
            combined_log = log_dir / f"{self._project_name}.log"
            combined_log.write_text(result.stdout)
            print(f"[container_manager] Combined logs saved to {combined_log}")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            print(f"[container_manager] Warning: failed to capture combined logs: {exc}")

        # Per-service logs
        try:
            svc_result = subprocess.run(
                self._compose_cmd("config", "--services"),
                capture_output=True,
                text=True,
                timeout=10,
            )
            services = [s.strip() for s in svc_result.stdout.splitlines() if s.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            print(f"[container_manager] Warning: could not list services: {exc}")
            return

        for service in services:
            try:
                result = subprocess.run(
                    self._compose_cmd("logs", "--no-color", "--timestamps", service),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.stdout:
                    service_log = log_dir / f"{service}.log"
                    service_log.write_text(result.stdout)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                print(f"[container_manager] Warning: failed to capture logs for {service}: {exc}")

        print(f"[container_manager] Per-service logs saved to {log_dir}")

    # Cleanup handlers

    def _register_cleanup_handlers(self) -> None:
        """Register atexit and signal handlers for belt-and-suspenders cleanup."""
        atexit.register(self.stop, capture_logs=False)

        self._original_sigterm = signal.getsignal(signal.SIGTERM)
        self._original_sigint = signal.getsignal(signal.SIGINT)

        def _signal_handler(signum: int, frame: "Any") -> None:
            self.stop(capture_logs=True)

            # Restore original handler and re-raise so the process exits
            # with the correct signal status.
            original = (
                self._original_sigterm
                if signum == signal.SIGTERM
                else self._original_sigint
            )
            if callable(original):
                original(signum, frame)
            elif original == signal.SIG_DFL:
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)

        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)

    def _restore_signal_handlers(self) -> None:
        """Restore original signal handlers saved during registration."""
        if self._original_sigterm is not None:
            signal.signal(signal.SIGTERM, self._original_sigterm)
            self._original_sigterm = None
        if self._original_sigint is not None:
            signal.signal(signal.SIGINT, self._original_sigint)
            self._original_sigint = None
