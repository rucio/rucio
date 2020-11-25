#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 CERN
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
#
# Authors:
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Martin Barisits <martin.barisits@cern.ch>, 2020

import io
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
import typing
import uuid
from datetime import datetime


def matches(small: typing.Dict, group: typing.Dict):
    for key in small.keys():
        if key not in group or small[key] != group[key]:
            return False
    return True


def run(*args, check=True, return_stdout=False, env=None) -> typing.Union[typing.NoReturn, io.TextIOBase]:
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


def stringify_dict(inp: typing.Dict):
    return {str(k): str(v) for k, v in inp.items()}


def find_image(images: typing.Dict, case: typing.Dict):
    for image, idgroup in images.items():
        if matches(idgroup, case):
            return image
    raise RuntimeError("Could not find image for case " + str(case))


def case_id(case: typing.Dict) -> str:
    parts = [
        case["DIST"],
        'py' + case["PYTHON"],
        case["SUITE"],
        case.get("RDBMS", ""),
        case.get("REST_BACKEND", "")
    ]
    return '-'.join(filter(bool, parts))


def case_log(caseid, msg, file=sys.stderr):
    print(caseid, msg, file=file, flush=True)


def main():
    obj = json.load(sys.stdin)
    cases = (obj["matrix"],) if isinstance(obj["matrix"], dict) else obj["matrix"]
    use_podman = 'USE_PODMAN' in os.environ and os.environ['USE_PODMAN'] == '1'
    parallel = 'PARALLEL_AUTOTESTS' in os.environ and os.environ['PARALLEL_AUTOTESTS'] == '1'
    failfast = 'PARALLEL_AUTOTESTS_FAILFAST' in os.environ and os.environ['PARALLEL_AUTOTESTS_FAILFAST'] == '1'
    copy_rucio_logs = 'COPY_AUTOTEST_LOGS' in os.environ and os.environ['COPY_AUTOTEST_LOGS'] == '1'
    logs_dir = pathlib.Path('.autotest')
    if parallel or copy_rucio_logs:
        logs_dir.mkdir(exist_ok=True)

    def gen_case_kwargs(case: typing.Dict):
        use_httpd = case.get('RUN_HTTPD', True)
        return {'caseenv': stringify_dict(case),
                'image': find_image(images=obj["images"], case=case),
                'use_podman': use_podman,
                'use_namespace': use_podman and parallel,
                'use_httpd': use_httpd,
                'copy_rucio_logs': copy_rucio_logs and use_httpd,
                'logs_dir': logs_dir / f'log-{case_id(case)}'}

    if parallel:
        with multiprocessing.Pool(processes=min(int(os.environ.get('PARALLEL_AUTOTESTS_PROCNUM', 3)), len(cases)), maxtasksperchild=1) as prpool:
            tasks = [(_case, prpool.apply_async(run_case_logger, (),
                                                {'run_case_kwargs': gen_case_kwargs(_case),
                                                 'stdlog': logs_dir / f'log-{case_id(_case)}.txt'})) for _case in cases]
            start_time = time.time()
            for _case, task in tasks:
                timeleft = start_time + 21600 - time.time()  # 6 hour overall timeout
                if timeleft <= 0:
                    print("Timeout exceeded, still running:",
                          list(map(lambda t: case_id(t[0]), filter(lambda t: not t[1].ready(), tasks))),
                          file=sys.stderr, flush=True)
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


def run_case_logger(run_case_kwargs: typing.Dict, stdlog=sys.stderr):
    caseid = case_id(run_case_kwargs['caseenv'])
    case_log(caseid, 'started task.')
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


def run_case(caseenv, image, use_podman, use_namespace, use_httpd, copy_rucio_logs, logs_dir: pathlib.Path):
    if use_namespace:
        namespace = str(uuid.uuid4())
        namespace_args = ('--namespace', namespace)
        namespace_env = {"NAMESPACE": namespace}
    else:
        namespace_args = ()
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
                use_podman=use_podman,
                pod=pod,
                namespace_args=namespace_args,
                namespace_env=namespace_env,
                copy_rucio_logs=copy_rucio_logs,
                logs_dir=logs_dir,
            )
        else:
            print("* Running test directly without httpd", file=sys.stderr, flush=True)
            success = run_test_directly(
                caseenv=caseenv,
                image=image,
                use_podman=use_podman,
                pod=pod,
                namespace_args=namespace_args,
            )
    finally:
        print("*** Finalizing", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)
        if pod:
            run('podman', *namespace_args, 'pod', 'stop', '-t', '10', pod, check=False)
            run('podman', *namespace_args, 'pod', 'rm', '--force', pod, check=False)

    if not success:
        sys.exit(1)


def run_test_directly(caseenv, image, use_podman, pod, namespace_args):
    pod_net_arg = ('--pod', pod) if use_podman else ()
    docker_env_args = list(itertools.chain(*map(lambda x: ('--env', f'{x[0]}={x[1]}'), caseenv.items())))
    scripts_to_run = ' && '.join([
        # before_script.sh is not included since it is written to run outside
        # the container and does not contribute to running without httpd
        './tools/test/install_script.sh',
        './tools/test/test.sh',
    ])

    try:
        # Running rucio container from given image with special entrypoint
        run('docker', *namespace_args, 'run', '--rm', *pod_net_arg, *docker_env_args, image, 'sh', '-c', scripts_to_run)

        return True
    except subprocess.CalledProcessError as error:
        print(f"** Running tests '{error.cmd}' exited with code {error.returncode}", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)
    return False


def run_with_httpd(caseenv, image, use_podman, pod, namespace_args, namespace_env, copy_rucio_logs, logs_dir: pathlib.Path) -> bool:
    cid = ""
    try:
        pod_net_arg = ('--pod', pod) if use_podman else ()
        docker_env_args = list(itertools.chain(*map(lambda x: ('--env', f'{x[0]}={x[1]}'), caseenv.items())))

        # Running rucio container from given image
        stdout = run('docker', *namespace_args, 'run', '--detach', *pod_net_arg,
                     *docker_env_args, image, return_stdout=True)
        cid = stdout.decode().strip()
        if not cid:
            raise RuntimeError("Could not determine container id after docker run")

        network_arg = ('--network', 'container:' + cid)
        container_run_args = ' '.join(pod_net_arg if use_podman else network_arg)
        container_runtime_args = ' '.join(namespace_args)

        # Running before_script.sh
        run('./tools/test/before_script.sh', env={**os.environ, **caseenv, **namespace_env,
                                                  "CONTAINER_RUNTIME_ARGS": container_runtime_args,
                                                  "CONTAINER_RUN_ARGS": container_run_args,
                                                  "CON_RUCIO": cid})

        # output registered hostnames
        run('docker', *namespace_args, 'exec', cid, 'cat', '/etc/hosts')

        # Running install_script.sh
        run('docker', *namespace_args, 'exec', cid, './tools/test/install_script.sh')

        # Running test.sh
        run('docker', *namespace_args, 'exec', cid, './tools/test/test.sh')

        # if everything went through without an exception, mark this case as a success
        return True
    except subprocess.CalledProcessError as error:
        print(f"** Process '{error.cmd}' exited with code {error.returncode}", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)
    finally:
        if cid:
            run('docker', *namespace_args, 'logs', cid, check=False)
            run('docker', *namespace_args, 'stop', cid, check=False)
            if copy_rucio_logs:
                try:
                    if logs_dir.exists():
                        shutil.rmtree(logs_dir)
                    run('docker', *namespace_args, 'cp', f'{cid}:/var/log', str(logs_dir))
                except Exception:
                    print("** Error on retrieving logs for", {**caseenv, "IMAGE": image}, '\n', traceback.format_exc(), '\n**', file=sys.stderr, flush=True)
            run('docker', *namespace_args, 'rm', '-v', cid, check=False)
    return False


if __name__ == "__main__":
    main()
