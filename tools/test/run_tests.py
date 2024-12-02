#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

import json
import io
import itertools
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
from typing import Optional, Union, NoReturn

import yaml


def run(*args, check=True, return_stdout=False, env=None) -> Union[NoReturn, io.TextIOBase]:
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
    environment_args = list(itertools.chain(*map(lambda x: ('--env', f'{x[0]}={x[1]}'), caseenv.items())))
    environment_args.append('--env')
    environment_args.append('GITHUB_ACTIONS')
    return environment_args


def matches(small: dict, group: dict):
    for key in small.keys():
        if key not in group or small[key] != group[key]:
            return False
    return True


def stringify_dict(inp: dict):
    return {str(k): str(v) for k, v in inp.items()}


def find_image(images: dict, case: dict):
    for image, idgroup in images.items():
        if matches(idgroup, case):
            return image
    raise RuntimeError("Could not find image for case " + str(case))


def case_id(case: dict) -> str:
    parts = [case["DIST"], 'py' + case["PYTHON"], case["SUITE"], case.get("RDBMS", "")]
    return '-'.join(filter(bool, parts))


def case_log(caseid, msg, file=sys.stderr):
    print(caseid, msg, file=file, flush=True)


def run_tests(cases: list, images: dict, tests: Optional[list[str]] = None):
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
            except:
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
        except:
            traceback.print_exc(file=sys.stderr)
            case_log(caseid, f'errored with {sys.exc_info()[0].__name__}: {sys.exc_info()[1]}', file=defaultstderr)
            return False
        finally:
            sys.stderr = defaultstderr
    case_log(caseid, 'completed successfully!')
    return True


def run_case(caseenv, image, use_podman, use_namespace, use_httpd, copy_rucio_logs, logs_dir: pathlib.Path, tests: list[str]):
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
    pod_net_arg = ['--pod', pod] if use_podman else []
    scripts_to_run = ' && '.join(
        [
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
    compose_version = int(run('docker compose', 'version', '--short', return_stdout=True).decode().split('.')[0])

    with (NamedTemporaryFile() as compose_override_file):
        compose_override_content = yaml.dump({
            'services': {
                'rucio': {
                    'image': image,
                    'environment': [f'{k}={v}' for k, v in caseenv.items()],
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
        up_down_args = (
            '--file', 'etc/docker/dev/docker-compose.yml',
            '--file', compose_override_file.name,
            '--profile', rdbms,
        )
        rucio_container = None
        try:
            # Start docker compose
            run('docker compose', '-p', project, *up_down_args, 'up', '-d')

            # Retrieve container names from docker compose
            # or use pre-defined names for old, v1, docker compose
            rucio_container = f'{project}_rucio_1'
            if compose_version > 1:
                rucio_container = next(filter(
                    lambda c: c['Service'] == 'rucio',
                    json.loads(run('docker compose', '-p', project, 'ps', '--format', 'json', return_stdout=True))
                ), {}).get('Name', rucio_container)

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
            if rucio_container:
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
            run('docker compose', '-p', project, *up_down_args, 'down', '-t', '30', check=False)
        return False


def main():
    obj = json.load(sys.stdin)
    cases = (obj["matrix"],) if isinstance(obj["matrix"], dict) else obj["matrix"]
    run_tests(cases, obj["images"])


if __name__ == "__main__":
    main()
