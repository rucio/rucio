#!/usr/bin/env python3
# Copyright 2020 CERN for the benefit of the ATLAS collaboration.
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
    print("** Running", " ".join(args), kwargs, file=sys.stderr, flush=True)
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
    return f'{case["DIST"]}-py{case["PYTHON"]}-{case["SUITE"]}{"-" + case["RDBMS"] if "RDBMS" in case else ""}'


def case_log(caseid, msg, file=sys.stderr):
    print(caseid, msg, file=file, flush=True)


def main():
    obj = json.load(sys.stdin)
    cases = (obj["matrix"],) if isinstance(obj["matrix"], dict) else obj["matrix"]
    use_podman = 'USE_PODMAN' in os.environ and os.environ['USE_PODMAN'] == '1'
    parallel = 'PARALLEL_AUTOTESTS' in os.environ and os.environ['PARALLEL_AUTOTESTS'] == '1'
    failfast = 'PARALLEL_AUTOTESTS_FAILFAST' in os.environ and os.environ['PARALLEL_AUTOTESTS_FAILFAST'] == '1'

    def gen_case_kwargs(case: typing.Dict):
        return {'caseenv': stringify_dict(case),
                'image': find_image(images=obj["images"], case=case),
                'use_podman': use_podman,
                'use_namespace': use_podman and parallel}

    if parallel:
        with multiprocessing.Pool(processes=min(int(os.environ.get('PARALLEL_AUTOTESTS_PROCNUM', 3)), len(cases)), maxtasksperchild=1) as prpool:
            tasks = [(_case, prpool.apply_async(run_case_logger, (),
                                                {'run_case_kwargs': gen_case_kwargs(_case),
                                                 'stdlog': pathlib.Path(f'.autotest/log-{case_id(_case)}.txt')})) for _case in cases]
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
        pathlib.Path(stdlog.parent).mkdir(parents=True, exist_ok=True)
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


def run_case(caseenv, image, use_podman, use_namespace):
    if use_namespace:
        namespace = str(uuid.uuid4())
        namespace_args = ('--namespace', namespace)
        namespace_env = {"NAMESPACE": namespace}
    else:
        namespace_args = ()
        namespace_env = {}

    pod = ""
    cid = "rucio"
    if use_podman:
        print("*** Starting with pod for", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)
        stdout = run('podman', *namespace_args, 'pod', 'create', return_stdout=True, check=True)
        pod = stdout.decode().strip()
        if not pod:
            raise RuntimeError("Could not determine pod id")
    else:
        print("*** Starting", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)

    success = False
    try:
        docker_env_args = list(itertools.chain(*map(lambda x: ('--env', f'{x[0]}={x[1]}'), caseenv.items())))
        pod_net_arg = ('--pod', pod) if use_podman else ()
        # Running rucio container from given image
        stdout = run('docker', *namespace_args, 'run', '--detach', *pod_net_arg,
                     *docker_env_args, image, return_stdout=True, check=True)
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
        success = True
    except subprocess.CalledProcessError as error:
        print(f"** Process '{error.cmd}' exited with code {error.returncode}", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)
    finally:
        print("*** Finalizing", {**caseenv, "IMAGE": image}, file=sys.stderr, flush=True)

        if cid:
            run('docker', *namespace_args, 'stop', cid, check=False)
            run('docker', *namespace_args, 'rm', '-v', cid, check=False)
        if pod:
            run('podman', *namespace_args, 'pod', 'stop', '-t', '10', pod, check=False)
            run('podman', *namespace_args, 'pod', 'rm', '--force', pod, check=False)

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
