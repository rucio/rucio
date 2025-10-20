#!/usr/bin/env python3
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

"""
Test runner used by Rucio's CI/autotest tooling.

``donkeyrider.py`` collects matrix entries from ``etc/docker/test/matrix.yml``
(via :mod:`tools.test.matrix_parser`), resolves runtime images, and pipes a JSON
payload into this module. From that payload we derive a sequence of *cases*
(distribution × python version × test suite × database) and execute them either
as ad-hoc containers or through the development docker-compose stack.

The intent is to centralise all orchestration concerns in a single place so
that higher level tooling can simply call :func:`run_tests`.

Execution modes
===============
Two execution strategies are supported and are selected on a per-case basis:

``RUN_HTTPD`` true (default)
    Bring up the development compose stack from ``etc/docker/dev/docker-compose.yml``.
    The ``rucio`` service is temporarily overridden to use the desired runtime image while
    mounting the working tree, and the tests are triggered via ``docker compose exec``.

``RUN_HTTPD`` false
    Start a single throw-away container from the resolved image and run ``./tools/test/test.sh``
    directly. Syntax-only suites use this path as it avoids the httpd/database dependencies.

Environment variables honoured by this module
=============================================
``USE_PODMAN``
    When set to ``"1"`` the runner assumes that the Docker-compatible CLI is
    provided by Podman. Commands still go through the ``docker`` entrypoint
    (via Podman's compatibility shim) but we additionally create per-case pods
    and namespaces to keep networking consistent when running in parallel.

``PARALLEL_AUTOTESTS`` and ``PARALLEL_AUTOTESTS_PROCNUM``
    Toggle whether cases are executed concurrently (via :class:`multiprocessing.Pool`)
    and configure the worker pool size.

``PARALLEL_AUTOTESTS_FAILFAST``
    Instructs the parallel executor to abort remaining
    cases as soon as one failure is observed.

``COPY_AUTOTEST_LOGS``
    When using the compose/httpd path, copy the service
    logs into a per-case directory for later inspection.

``GITHUB_ACTIONS``
    Injected into every container through :func:`env_args` so downstream
    scripts can detect whether they run in CI.

The module is structured as a few small helpers:

``main``
    Reads the JSON payload from ``stdin`` and prepares the ``cases`` and
    ``images`` structures used by :func:`run_tests`.

``run_tests``
    Handles parallelism, logging, and success aggregation across cases.

``run_case``
    Implements the per-case orchestration, deciding between direct execution and compose-based
    execution, managing pods/namespaces and delegating log capture to the specialised helpers.

``run_test_directly`` and ``run_with_httpd``
    The low-level primitives that actually launch containers or compose stacks.
"""

import itertools
import json
import multiprocessing
import os
import pathlib
import shutil
import subprocess
import sys
import time
import traceback
import uuid
from datetime import datetime
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING, NoReturn, Optional, Union

import yaml

if TYPE_CHECKING:
    import io


def run(*args, check=True, return_stdout=False, env=None) -> Union[NoReturn, 'io.TextIOBase']:
    """
    Invoke ``subprocess.run`` with verbose logging and optional capture.

    ``run`` is deliberately verbose: every command is echoed before execution so the CI logs
    contain the full docker/podman history leading up to a failure. The helper also mirrors
    :func:`subprocess.run`'s ``check`` semantics and exposes a lightweight ``return_stdout``
    flag that switches to capturing stdout when the caller needs the produced value.
    """
    kwargs = {'check': check, 'stdout': sys.stderr, 'stderr': subprocess.STDOUT}
    if env is not None:
        kwargs['env'] = env
    if return_stdout:
        kwargs['stderr'] = sys.stderr
        kwargs['stdout'] = subprocess.PIPE
    args = [str(a) for a in args]
    print("** Running", " ".join(map(lambda a: repr(a) if ' ' in a else a, args)), kwargs, file=sys.stderr, flush=True)
    proc = subprocess.run(args, **kwargs)
    if return_stdout:
        return proc.stdout


def env_args(caseenv):
    """
    Expand a case environment mapping into CLI ``--env`` fragments.

    ``caseenv`` is derived from the matrix entry and contains the suite name, optional
    database, and other flags consumed by ``test.sh``. We flatten the mapping into a list
    ``['--env', 'KEY=value', ...]`` suitable for ``docker/podman run`` while force-injecting
    ``GITHUB_ACTIONS`` so that downstream shell scripts retain awareness of the CI context
    even when the surrounding orchestrator is not GitHub Actions.
    """
    environment_args = list(itertools.chain(*map(lambda x: ('--env', f'{x[0]}={x[1]}'), caseenv.items())))
    environment_args.append('--env')
    environment_args.append('GITHUB_ACTIONS')
    return environment_args


def matches(small: dict, group: dict):
    """
    Return ``True`` when ``group`` contains all key/value pairs from ``small``.

    Image metadata and matrix entries are represented as loose dictionaries. The helper
    isolates the "does this image satisfy the required characteristics?" check used by
    :func:`find_image`.
    """
    for key in small.keys():
        if key not in group or small[key] != group[key]:
            return False
    return True


def stringify_dict(inp: dict):
    """
    Coerce mapping keys/values to strings for JSON/YAML consumption.

    The matrix originates from YAML where types may be integers or booleans; container
    environment variables expect strings, so we normalise to avoid differences between
    Python/YAML types later in the pipeline.
    """
    return {str(k): str(v) for k, v in inp.items()}


def find_image(images: dict, case: dict):
    """
    Return the runtime image tag matching the matrix attributes.

    ``images`` is the structure produced by :mod:`tools.test.build_images` (and forwarded
    through ``donkeyrider``). Each entry describes the image in terms of distribution, Python
    version, and optional identifiers. The metadata recorded for the image must be a subset
    of the matrix case so that the case attributes satisfy the requirements encoded by the image.
    """
    for image, idgroup in images.items():
        if matches(idgroup, case):
            return image
    raise RuntimeError("Could not find image for case " + str(case))


def case_id(case: dict) -> str:
    """
    Generate a human-readable identifier from the matrix attributes.

    The resulting string is used for log file names and stderr prefixes, e.g.
    ``alma9-py3.9-client-postgres14``.
    """
    parts = [case["DIST"], 'py' + case["PYTHON"], case["SUITE"], case.get("RDBMS", "")]
    return '-'.join(filter(bool, parts))


def case_log(caseid, msg, file=sys.stderr):
    """
    Print ``msg`` with the case identifier prefix for consistent logging.
    """
    print(caseid, msg, file=file, flush=True)


def run_tests(cases: list, images: dict, tests: Optional[list[str]] = None):
    """
    Execute all matrix cases serially or in parallel.

    Parameters
    ----------
    cases:
        Case dictionaries produced by :mod:`tools.test.matrix_parser`. These contain env
        variables and flags such as ``RUN_HTTPD`` which choose the orchestration mode.
    images:
        Mapping used by :func:`find_image` to resolve cases to container images. When ``runtime_images``
        are provided by :mod:`tools.test.donkeyrider`, they override the default build matrix.
    tests:
        Optional test selectors forwarded to ``tools/test/test.sh`` and, in turn, to ``tools/run_tests.sh``.
        When set, the runner drops to a filtered pytest invocation rather than executing the full suite.

    High-level behaviour
    --------------------
    * honours ``PARALLEL_AUTOTESTS`` (and related variables) to decide whether
      to spawn a :class:`multiprocessing.Pool`.
    * normalises each case environment to strings so it can be passed to the
      shell wrappers without surprises.
    * records stdout/stderr for each case in dedicated log files when running
      in parallel, making it possible to inspect failures after the workers exit.
    * surfaces worker failures via the ``sys.exit`` calls in :func:`run_case`.
      Unexpected exceptions caught by :func:`run_case_logger` cause the worker
      to return ``False`` so ``PARALLEL_AUTOTESTS_FAILFAST`` can stop the pool
      early; when fail-fast is disabled these errors are left to the logs for
      later inspection.
    """
    use_podman = 'USE_PODMAN' in os.environ and os.environ['USE_PODMAN'] == '1'
    parallel = 'PARALLEL_AUTOTESTS' in os.environ and os.environ['PARALLEL_AUTOTESTS'] == '1'
    failfast = 'PARALLEL_AUTOTESTS_FAILFAST' in os.environ and os.environ['PARALLEL_AUTOTESTS_FAILFAST'] == '1'
    copy_rucio_logs = 'COPY_AUTOTEST_LOGS' in os.environ and os.environ['COPY_AUTOTEST_LOGS'] == '1'
    logs_dir = pathlib.Path('.autotest')
    if parallel or copy_rucio_logs:
        logs_dir.mkdir(exist_ok=True)

    def gen_case_kwargs(case: dict):
        use_httpd = case.get('RUN_HTTPD', True)
        return {
            'caseenv': stringify_dict(case),
            'image': find_image(images=images, case=case),
            'use_podman': use_podman,
            'use_namespace': use_podman and parallel,
            'use_httpd': use_httpd,
            'copy_rucio_logs': copy_rucio_logs and use_httpd,
            'logs_dir': logs_dir / f'log-{case_id(case)}',
            'tests': tests or [],
        }

    if parallel:
        parallel_num = min(int(os.environ.get('PARALLEL_AUTOTESTS_PROCNUM', 3)), len(cases))
        with multiprocessing.Pool(processes=parallel_num, maxtasksperchild=1) as prpool:
            tasks = [
                (
                    _case,
                    prpool.apply_async(
                        run_case_logger,
                        (),
                        {'run_case_kwargs': gen_case_kwargs(_case), 'stdlog': logs_dir / f'log-{case_id(_case)}.txt'},
                    ),
                )
                for _case in cases
            ]
            start_time = time.time()
            for _case, task in tasks:
                timeleft = start_time + 21600 - time.time()  # 6 hour overall timeout
                if timeleft <= 0:
                    print(
                        "Timeout exceeded, still running:",
                        list(map(lambda t: case_id(t[0]), filter(lambda t: not t[1].ready(), tasks))),
                        file=sys.stderr,
                        flush=True,
                    )
                    prpool.close()
                    sys.exit(1)

                # throwing an exception in the task will not exit task.get immediately, so a success variable is used
                success = task.get(timeout=timeleft)
                if not success and failfast:
                    prpool.close()
                    sys.exit(1)
    else:
        for _case in cases:
            run_case(**gen_case_kwargs(_case))


def run_case_logger(run_case_kwargs: dict, stdlog=sys.stderr):
    """
    Wrap :func:`run_case` to add per-case log files and error reporting.

    The multiprocessing pool cannot share file descriptors with the parent, so we open the
    log file inside the worker process and temporarily redirect ``sys.stderr``. Any
    exception is recorded in the case log and translated into ``False`` so the caller can
    decide whether to abort the run (``FAILFAST``) or continue with the remaining cases.
    """
    caseid = case_id(run_case_kwargs['caseenv'])
    case_log(caseid, 'started task. Logging to ' + repr(stdlog))
    defaultstderr = sys.stderr
    startmsg = f'{("=" * 80)}\nStarting test case {caseid}\n  at {datetime.now().isoformat()}\n{"=" * 80}\n'
    if isinstance(stdlog, pathlib.PurePath):
        with open(str(stdlog), 'a') as logfile:
            logfile.write(startmsg)
            logfile.flush()
            sys.stderr = logfile
            try:
                run_case(**run_case_kwargs)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                case_log(caseid, f'errored with {sys.exc_info()[0].__name__}: {sys.exc_info()[1]}', file=defaultstderr)
                return False
            finally:
                sys.stderr = defaultstderr
    else:
        sys.stderr = stdlog
        try:
            print(startmsg, file=sys.stderr)
            run_case(**run_case_kwargs)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            case_log(caseid, f'errored with {sys.exc_info()[0].__name__}: {sys.exc_info()[1]}', file=defaultstderr)
            return False
        finally:
            sys.stderr = defaultstderr
    case_log(caseid, 'completed successfully!')
    return True


def run_case(caseenv, image, use_podman, use_namespace, use_httpd, copy_rucio_logs, logs_dir: pathlib.Path, tests: list[str]):
    """
    Run a single matrix case using the requested container orchestration.

    ``run_case`` normalises all per-case decisions before delegating to the execution primitives.
    Responsibilities include:

    * invoking ``docker image ls`` upfront so connectivity issues with the
      container runtime surface before any orchestration begins.
    * creating/tearing down Podman pods or namespaces when parallel execution
      would otherwise result in conflicting container names.
    * dispatching to :func:`run_test_directly` or :func:`run_with_httpd`
      depending on ``RUN_HTTPD``.
    * forwarding log-copy requests to :func:`run_with_httpd` and converting the boolean
      success back into the ``sys.exit`` contract expected by the outer control flow.
    """
    if use_namespace:
        namespace = str(uuid.uuid4())
        namespace_args = ['--namespace', namespace]
        namespace_env = {"NAMESPACE": namespace}
    else:
        namespace_args = []
        namespace_env = {}

    run('docker', 'image', 'ls', image)

    pod = ""
    if use_podman:
        print("*** Starting with pod for", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)
        stdout = run('podman', *namespace_args, 'pod', 'create', return_stdout=True)
        pod = stdout.decode().strip()
        if not pod:
            raise RuntimeError("Could not determine pod id")
    else:
        print("*** Starting", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)

    try:
        if use_httpd:
            print("* Using httpd for test", file=sys.stderr, flush=True)
            success = run_with_httpd(
                caseenv=caseenv,
                image=image,
                namespace_args=namespace_args,
                namespace_env=namespace_env,
                copy_rucio_logs=copy_rucio_logs,
                logs_dir=logs_dir,
                tests=tests,
            )
        else:
            print("* Running test directly without httpd", file=sys.stderr, flush=True)
            success = run_test_directly(
                caseenv=caseenv,
                image=image,
                use_podman=use_podman,
                pod=pod,
                namespace_args=namespace_args,
                tests=tests,
            )
    finally:
        print("*** Finalizing", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)
        if pod:
            run('podman', *namespace_args, 'pod', 'stop', '-t', '10', pod, check=False)
            run('podman', *namespace_args, 'pod', 'rm', '--force', pod, check=False)

    if not success:
        sys.exit(1)


def run_test_directly(
        caseenv: dict[str, str],
        image: str,
        use_podman: bool,
        pod: str,
        namespace_args: list[str],
        tests: list[str],
):
    """
    Execute the suite by invoking ``tools/test/test.sh`` directly.

    The direct path keeps orchestration costs low. We start a single container, mount the
    relevant parts of the repository (``/rucio_source`` plus ``/opt/rucio/{tools,bin,lib,tests}``)
    and then execute the shell helper that performs dependency installation, bootstrapping,
    and pytest execution. Additional matrix-provided environment variables are passed in via
    ``--env`` flags and optional ``tests`` selectors are surfaced through the ``TESTS`` variable.

    Returns
    -------
    bool
        ``True`` on success, ``False`` on failure (the caller will handle logging and exiting).
    """
    pod_net_arg = ['--pod', pod] if use_podman else []
    scripts_to_run = ' && '.join(
        [
            # Install Rucio directly from the mounted source
            'pip install --no-cache-dir -e /rucio_source',
            # Change to the source directory so that relative paths work
            'cd /rucio_source',
            './tools/test/test.sh' + (' -p' if tests else ''),
        ]
    )

    try:
        if tests:
            caseenv = dict(caseenv)
            caseenv['TESTS'] = ' '.join(tests)

        # Running rucio container from given image with special entrypoint
        run(
            'docker',
            *namespace_args,
            'run',
            '--rm',
            *pod_net_arg,
            # Mount the source code from the PR as writable
            '-v', f"{os.path.abspath(os.curdir)}:/rucio_source",
            '-v', f"{os.path.abspath(os.curdir)}/tools:/opt/rucio/tools:Z",
            '-v', f"{os.path.abspath(os.curdir)}/bin:/opt/rucio/bin:Z",
            '-v', f"{os.path.abspath(os.curdir)}/lib:/opt/rucio/lib:Z",
            '-v', f"{os.path.abspath(os.curdir)}/tests:/opt/rucio/tests:Z",
            # Mount specific etc subdirectories instead of the entire etc to keep certificates (Copying the entire etc overrides the certificates)
            '-v', f"{os.path.abspath(os.curdir)}/etc/mail_templates:/opt/rucio/etc/mail_templates:Z",
            '-v', f"{os.path.abspath(os.curdir)}/etc/automatix.json:/opt/rucio/etc/automatix.json:Z",
            '-v', f"{os.path.abspath(os.curdir)}/etc/google-cloud-storage-test.json:/opt/rucio/etc/google-cloud-storage-test.json:Z",
            '-v', f"{os.path.abspath(os.curdir)}/etc/idpsecrets.json:/opt/rucio/etc/idpsecrets.json:Z",
            '-v', f"{os.path.abspath(os.curdir)}/etc/rse_repository.json:/opt/rucio/etc/rse_repository.json:Z",
            '-v', f"{os.path.abspath(os.curdir)}/etc/docker/test/matrix_policy_package_tests.yml:/opt/rucio/etc/docker/test/matrix_policy_package_tests.yml:Z",
            *(env_args(caseenv)),
            image,
            'sh',
            '-c',
            scripts_to_run,
        )

        return True
    except subprocess.CalledProcessError as error:
        print(
            f"** Running tests '{error.cmd}' exited with code {error.returncode}",
            {**caseenv, "IMAGE": image},
            file=sys.stderr,
            flush=True,
        )
    return False


def run_with_httpd(
        caseenv: dict[str, str],
        image: str,
        namespace_args: list[str],
        namespace_env: dict[str, str],
        copy_rucio_logs: bool,
        logs_dir: pathlib.Path,
        tests: list[str],
) -> bool:
    """
    Execute a test case by overlaying the development docker-compose stack.

    The httpd-enabled suites require the full service stack (web server, daemons, databases).
    We therefore:

    * render a temporary compose override file that replaces the ``rucio``
      service image and mounts the repository checkout.
    * start the stack via ``docker compose up``
      (optionally scoped by the requested ``RDBMS`` profile).
    * ``docker compose exec`` into the running ``rucio`` container
      to trigger ``./tools/test/test.sh``.
    * optionally collect container logs into ``logs_dir`` for later analysis
      before tearing everything down with ``docker compose down``.

    The ``namespace_args``/``namespace_env`` parameters keep the interface consistent with Podman
    invocations where ``docker`` commands are wrapped in ``podman --namespace <name>``.

    Returns
    -------
    bool
        ``True`` when the suite completes successfully, ``False`` otherwise.
    """

    with (NamedTemporaryFile() as compose_override_file):
        compose_override_content = yaml.dump({
            'services': {
                'rucio': {
                    'image': image,
                    'environment': [f'{k}={v}' for k, v in caseenv.items()],
                    'working_dir': '/rucio_source',
                    'entrypoint': ['/rucio_source/etc/docker/dev/rucio/entrypoint.sh'],
                    'volumes': [
                        # Mount the current source code from the PR as writable
                        f"{os.path.abspath(os.curdir)}:/rucio_source",
                        f"{os.path.abspath(os.curdir)}/tools:/opt/rucio/tools:Z",
                        f"{os.path.abspath(os.curdir)}/bin:/opt/rucio/bin:Z",
                        f"{os.path.abspath(os.curdir)}/lib:/opt/rucio/lib:Z",
                        f"{os.path.abspath(os.curdir)}/tests:/opt/rucio/tests:Z",
                        # Mount specific etc subdirectories
                        f"{os.path.abspath(os.curdir)}/etc/mail_templates:/opt/rucio/etc/mail_templates:Z",
                        f"{os.path.abspath(os.curdir)}/etc/automatix.json:/opt/rucio/etc/automatix.json:Z",
                        f"{os.path.abspath(os.curdir)}/etc/google-cloud-storage-test.json:/opt/rucio/etc/google-cloud-storage-test.json:Z",
                        f"{os.path.abspath(os.curdir)}/etc/idpsecrets.json:/opt/rucio/etc/idpsecrets.json:Z",
                        f"{os.path.abspath(os.curdir)}/etc/rse_repository.json:/opt/rucio/etc/rse_repository.json:Z",
                        f"{os.path.abspath(os.curdir)}/etc/docker/test/matrix_policy_package_tests.yml:/opt/rucio/etc/docker/test/matrix_policy_package_tests.yml:Z",
                    ],
                },
                'ruciodb': {
                    'profiles': ['donotstart'],
                }
            }
        })
        print("Overriding docker compose configuration with: \n", compose_override_content, flush=True)
        with open(compose_override_file.name, 'w') as f:
            f.write(compose_override_content)

        rdbms = caseenv.get('RDBMS', '')
        project = os.urandom(8).hex()
        compose_env = os.environ.copy()
        compose_env.update(namespace_env)
        rucio_container = f'{project}-rucio-1'
        compose_env['RUCIO_HTTPD_CONTAINER_NAME'] = rucio_container
        compose_env['RUCIO_INFLUXDB_CONTAINER_NAME'] = f'{project}-influxdb-1'
        compose_env['RUCIO_GRAPHITE_CONTAINER_NAME'] = f'{project}-graphite-1'
        compose_env['RUCIO_ELASTICSEARCH_CONTAINER_NAME'] = f'{project}-elasticsearch-1'
        compose_env['RUCIO_ACTIVEMQ_CONTAINER_NAME'] = f'{project}-activemq-1'
        compose_env['RUCIO_WEB1_CONTAINER_NAME'] = f'{project}-web1-1'
        rdbms_container_env = {
            'postgres14': 'RUCIO_POSTGRES14_CONTAINER_NAME',
            'mysql8': 'RUCIO_MYSQL8_CONTAINER_NAME',
            'oracle': 'RUCIO_ORACLE_CONTAINER_NAME',
        }
        rdbms_env = rdbms_container_env.get(rdbms)
        if rdbms_env:
            compose_env[rdbms_env] = f'{project}-{rdbms}-1'
        up_down_args = (
            '--file', 'etc/docker/dev/docker-compose.yml',
            '--file', compose_override_file.name,
            '--profile', rdbms,
        )
        try:
            # Start docker compose
            run('docker', 'compose', '-p', project, *up_down_args, 'up', '-d', env=compose_env)

            # Install Rucio directly from the mounted source
            run('docker', *namespace_args, 'exec', rucio_container, 'pip', 'install', '--no-cache-dir', '-e', '/rucio_source')

            # Running test.sh
            if tests:
                tests_env = ('--env', 'TESTS=' + ' '.join(tests))
                tests_arg = ('-p', )
            else:
                tests_env = ()
                tests_arg = ()

            run('docker', *namespace_args, 'exec', *tests_env, rucio_container, './tools/test/test.sh', *tests_arg)

            # if everything went through without an exception, mark this case as a success
            return True
        except subprocess.CalledProcessError as error:
            print(
                f"** Process '{error.cmd}' exited with code {error.returncode}",
                {**caseenv, "IMAGE": image},
                file=sys.stderr,
                flush=True,
            )
        finally:
            run('docker', *namespace_args, 'logs', rucio_container, check=False)
            if copy_rucio_logs:
                try:
                    if logs_dir.exists():
                        shutil.rmtree(logs_dir)
                    run('docker', *namespace_args, 'cp', f'{rucio_container}:/var/log', str(logs_dir))
                except Exception:
                    print(
                        "** Error on retrieving logs for",
                        {**caseenv, "IMAGE": image},
                        '\n',
                        traceback.format_exc(),
                        '\n**',
                        file=sys.stderr,
                        flush=True,
                    )
            run('docker', 'compose', '-p', project, *up_down_args, 'down', '-t', '30', check=False, env=compose_env)
        return False


def main():
    """
    Entry point consumed by ``donkeyrider.py`` via ``python -m``.

    ``donkeyrider`` serialises the expanded matrix, resolved images and optional runtime
    overrides into JSON and pipes it into ``run_tests``. The function keeps backward
    compatibility with historical payloads.
    """
    obj = json.load(sys.stdin)
    cases = (obj["matrix"],) if isinstance(obj["matrix"], dict) else obj["matrix"]

    # Use runtime images if provided
    if "runtime_images" in obj:
        images = {}
        for case in cases:
            python_version = case.get("PYTHON", "3.9")
            if python_version in obj["runtime_images"]:
                images[obj["runtime_images"][python_version]] = {"PYTHON": python_version}
    else:
        # Fallback to old behavior (Keeping this here in case we need to change testing startegy in the future)
        images = obj["images"]

    run_tests(cases, images)


if __name__ == "__main__":
    main()
