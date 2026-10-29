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

This module runs on the host side -- it manages Docker containers from
the pytest process running on the host (or CI runner).  It does NOT run
inside a container; the rucio container has no Docker socket access.

Lifecycle:
    1. Remove a stale stack with the same project name (other rucio-test-*
       projects are left alone, so suites can run in parallel)
    2. `docker compose up -d --wait` with the correct project name,
       compose files, and profiles
    3. Install the source and wait for httpd readiness inside the rucio container
    4. Run tests (handled by pytest, not this module)
    5. `docker compose down -v` on session end, signal, or atexit

With keep=True (--keep-containers) a running stack is reused in step 1-3 and
left running in step 5. cleanup_all() (--cleanup) removes every rucio-test-*
stack on demand.
"""

import atexit
import json
import logging
import os
import signal
import subprocess  # noqa: S404 -- used to drive docker compose
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger(__name__)


class ContainerManager:
    """Manages Docker Compose container lifecycle for a test suite.

    Parameters
    ----------
    project_name:
        Compose project name, e.g. rucio-test-remote_dbs-postgres14.
    profiles:
        Tuple of compose profile names to activate (from
        SuiteProfile.compose_profiles).
    root_dir:
        Repository root directory (config.rootdir).  Compose file
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
        keep: bool = False,
    ) -> None:
        self._project_name = project_name
        self._profiles = profiles
        self._root_dir = root_dir
        self._keep = keep
        self._reused = False
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
    def reused(self) -> bool:
        """True when start() picked up an already running stack (keep=True)."""
        return self._reused

    @property
    def log_dir(self) -> Path:
        """Path to the container log output directory."""
        return Path(self._root_dir) / self.LOG_DIR

    def start(self) -> None:
        """Start containers: build/pull, compose up, install source, readiness check.

        With keep=True and this project's rucio container already running, the
        running stack is reused: only httpd is reloaded so server code changes
        apply (the source is bind-mounted and installed in editable mode).
        """
        self._register_cleanup_handlers()
        if self._keep and self._is_running():
            logger.info(f"Reusing running containers: {self._project_name}")
            self._reused = True
            self._started = True
            self._restart_httpd()
            self._wait_for_readiness()
            return
        self._remove_stale_project()
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

        if self._keep:
            logger.info(
                f"Leaving containers running: {self._project_name} "
                "(remove them with `pytest --cleanup`)"
            )
        else:
            self._compose_down()
        self._restore_signal_handlers()

    @staticmethod
    def make_project_name(
        suite_name: str, rdbms: str, vo: "str | None" = None
    ) -> str:
        """Build a compose project name from suite, RDBMS, and optional VO.

        Returns a string like rucio-test-remote_dbs-postgres14.
        When vo is truthy, the VO is inserted to yield a
        per-VO-unique name like rucio-test-multi_vo-tst-postgres14.

        The per-VO variant keeps the compose network name unique per VO too
        (the network name derives from the project name), so two multi_vo VO
        legs (tst, ts2) can run as parallel matrix legs without their compose
        stacks colliding. PROJECT_PREFIX is unchanged either way, so
        orphan-cleanup still matches on rucio-test-.
        """
        if vo:
            return f"rucio-test-{suite_name}-{vo}-{rdbms}"
        return f"rucio-test-{suite_name}-{rdbms}"

    # Environment setup

    def _compose_build(self) -> None:
        """Build the rucio test image from source if not already built.

        The test override compose file defines a build section for the
        rucio service.  If RUCIO_TEST_IMAGE is set, compose will skip
        the build when the image already exists.  Otherwise it builds from
        etc/docker/test/runtime.Dockerfile.
        """
        cmd = self._compose_cmd("build", "rucio")
        logger.info("Building rucio test image from source...")
        try:
            result = subprocess.run(
                cmd,
                # The py3.10 image builds boost + gfal2-python from source
                # (no prebuilt gfal2-python3 package for 3.10), which can take
                # well over 20 minutes on slower machines.
                timeout=1800,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Timed out building rucio test image")

        if result.returncode != 0:
            raise RuntimeError("Failed to build rucio test image")

        logger.info("Image build complete")

    def _install_rucio_from_source(self) -> None:
        """Install rucio from the mounted source inside the container.

        The volume-mounted source at /rucio_source may differ from what
        was baked into the image.  A dev-install ensures the container runs
        the current working-tree code.
        """
        logger.info("Installing rucio from source in container...")
        cmd = self._compose_cmd(
            "exec", "-T", "rucio",
            "pip", "install", "--no-cache-dir", "-e", "/rucio_source",
        )
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            logger.warning("pip install timed out")
            return

        if result.returncode != 0:
            logger.warning(f"pip install failed:\n{result.stderr}")
        else:
            logger.info("Rucio installed from source")

    def _bootstrap_rucio_home(self) -> None:
        """Link the mounted source etc/ fixtures into RUCIO_HOME.

        The dev compose mounts the repo at /rucio_source while
        RUCIO_HOME=/opt/rucio, and the container entrypoint only generates
        rucio.cfg and alembic.ini there. Tests read fixtures from
        $RUCIO_HOME/etc (mail_templates/, rse_repository.json, ...), so link in
        every missing entry, never replacing the generated files. The rucio CLI
        scripts come from `pip install -e` via script-files in pyproject.toml.
        """
        script = (
            "for f in /rucio_source/etc/*; do "
            'n=$(basename "$f"); '
            '[ -e "/opt/rucio/etc/$n" ] || ln -sf "$f" "/opt/rucio/etc/$n"; '
            "done"
        )
        cmd = self._compose_cmd("exec", "-T", "rucio", "bash", "-c", script)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            logger.warning("RUCIO_HOME bootstrap timed out")
            return

        if result.returncode != 0:
            logger.warning(f"RUCIO_HOME bootstrap failed:\n{result.stderr}")
        else:
            logger.info("Linked source etc/ into RUCIO_HOME")

    def _restart_httpd(self) -> None:
        """Restart httpd inside the rucio container after rucio installation."""
        cmd = self._compose_cmd(
            "exec", "-T", "rucio",
            "httpd", "-k", "graceful",
        )
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            logger.info("httpd restarted")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("could not restart httpd")

    # Compose command builder

    def _compose_cmd(self, *args: str) -> list[str]:
        """Build a full docker compose command with project/file/profile flags."""
        cmd = ["docker", "compose", "-p", self._project_name]
        for fname in self.COMPOSE_FILES:
            fpath = os.path.join(self._root_dir, self.COMPOSE_DIR, fname)
            cmd.extend(["-f", fpath])
        for profile in self._profiles:
            cmd.extend(["--profile", profile])
        cmd.extend(args)
        return cmd

    # Lifecycle methods

    def _is_running(self) -> bool:
        """True when this project's rucio container is running."""
        cmd = self._compose_cmd("ps", "--status", "running", "--quiet", "rucio")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
        return result.returncode == 0 and bool(result.stdout.strip())

    def _remove_stale_project(self) -> None:
        """Remove a leftover stack with this project's name (e.g. from a crashed run).

        Other rucio-test-* projects are left alone, so suites can run in
        parallel. `pytest --cleanup` removes all of them on demand.
        """
        self.cleanup_all(only=self._project_name)

    @classmethod
    def cleanup_all(cls, only: "str | None" = None) -> list[str]:
        """Tear down rucio-test-* compose projects (or just the one named only).

        :returns: The names of the projects that were removed.
        """
        removed: list[str] = []
        try:
            result = subprocess.run(
                ["docker", "compose", "ls", "--format", "json", "-a"],  # noqa: S607 -- docker resolved from PATH
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.warning(f"could not list compose projects: {exc}")
            return removed

        if result.returncode != 0:
            logger.warning("could not list compose projects")
            return removed

        try:
            projects = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("could not parse compose project list")
            return removed

        for project in projects:
            name = project.get("Name", "")
            if name.startswith(cls.PROJECT_PREFIX) and (only is None or name == only):
                logger.info(f"Removing project: {name}")
                try:
                    down_cmd = ["docker", "compose", "-p", name]
                    config_files = project.get("ConfigFiles", "")
                    if config_files:
                        for cf in config_files.split(","):
                            cf = cf.strip()
                            if cf:
                                down_cmd.extend(["-f", cf])
                    # Enable every profile, otherwise profile-gated services (e.g. the DB) are left behind.
                    down_cmd.extend(["--profile", "*", "down", "-v", "-t", "10"])
                    subprocess.run(
                        down_cmd,
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    logger.warning(f"failed to remove project {name}")
                    continue
                removed.append(name)
        return removed

    def _compose_up(self) -> None:
        """Run `docker compose up -d --wait` and raise on failure."""
        cmd = self._compose_cmd("up", "-d", "--wait", "--wait-timeout", "120")
        logger.info(f"Starting containers: {self._project_name}")
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
            logger.error(f"compose up failed:\n{result.stderr}")
            raise RuntimeError(f"Failed to start containers: {result.stderr}")

        logger.info("Containers started and healthy")

    def _wait_for_readiness(self) -> None:
        """Wait until httpd answers again after the restart in start().

        The first start is already covered by the rucio healthcheck, which
        `docker compose up --wait` waits for. The plugin then restarts httpd to
        load the freshly installed source, so httpd is checked once more here.
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
        logger.info("Waiting for httpd readiness...")
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
            logger.error(f"httpd readiness check failed:\n{result.stderr}")
            raise RuntimeError(f"httpd readiness check failed: {result.stderr}")

        logger.info("httpd is ready")

    def _compose_down(self) -> None:
        """Run `docker compose down -v` (best-effort, does not raise)."""
        cmd = self._compose_cmd("down", "-v", "-t", "30")
        logger.info(f"Stopping containers: {self._project_name}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                start_new_session=True,
            )
            if result.returncode != 0:
                logger.warning(
                    f"compose down returned exit code {result.returncode}: {result.stderr}"
                )
            else:
                logger.info("Containers stopped and removed")
        except subprocess.TimeoutExpired:
            logger.warning("compose down timed out")
        except FileNotFoundError:
            logger.warning("docker not found during cleanup")

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
            logger.warning(f"could not create log directory: {exc}")
            return

        # Combined log from all services
        combined_log = log_dir / f"{self._project_name}.log"
        try:
            self._stream_logs(combined_log, timeout=60)
            logger.info(f"Combined logs saved to {combined_log}")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning(f"failed to capture combined logs: {exc}")

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
            logger.warning(f"could not list services: {exc}")
            return

        for service in services:
            service_log = log_dir / f"{service}.log"
            try:
                self._stream_logs(service_log, service, timeout=30)
                if service_log.stat().st_size == 0:
                    service_log.unlink()
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                logger.warning(f"failed to capture logs for {service}: {exc}")

        logger.info(f"Per-service logs saved to {log_dir}")

    def _stream_logs(self, path: Path, *services: str, timeout: int) -> None:
        """Write `docker compose logs` for the given services (all if none) straight to path.

        The output goes to the file as it is produced instead of being held in
        memory, since container logs can be large.
        """
        cmd = self._compose_cmd("logs", "--no-color", "--timestamps", *services)
        with open(path, "w", encoding="utf-8") as fh:
            subprocess.run(cmd, stdout=fh, stderr=subprocess.DEVNULL, timeout=timeout)

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
