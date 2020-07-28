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

import io
import itertools
import json
import os
import subprocess
import sys
import typing


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
        del kwargs['stderr']
        kwargs['stdout'] = subprocess.PIPE
    print("** Running", " ".join(args), kwargs, file=sys.stderr, flush=True)
    proc = subprocess.run(args, **kwargs)
    if return_stdout:
        return proc.stdout


def main():
    obj = json.load(sys.stdin)
    cases = (obj["matrix"], ) if isinstance(obj["matrix"], dict) else obj["matrix"]

    for case in cases:
        for image, idgroup in obj["images"].items():
            if matches(idgroup, case):
                case = {str(k): str(v) for k, v in case.items()}
                pod = ""
                cid = "rucio"
                if 'USE_PODMAN' in os.environ and os.environ['USE_PODMAN'] == '1':
                    print("*** Starting with pod for", {**case, "IMAGE": image}, file=sys.stderr, flush=True)
                    stdout = run('podman', 'pod', 'create', return_stdout=True, check=True)
                    pod = stdout.decode().strip()
                    if not pod:
                        raise RuntimeError("Could not determine pod id after " + ' '.join(args))
                    os.environ['POD'] = pod
                else:
                    print("*** Starting", {**case, "IMAGE": image}, file=sys.stderr, flush=True)
                docker_env_args = list(itertools.chain(*map(lambda x: ('--env', f'{x[0]}={x[1]}'), case.items())))
                try:
                    pod_net_args = ('--pod', pod) if pod else ('--hostname', 'rucio')
                    # Running rucio container from given image
                    stdout = run('docker', 'run', '--detach', '--name', 'rucio', *pod_net_args,
                                 *docker_env_args, image, return_stdout=True, check=True)
                    cid = stdout.decode().strip()
                    if not cid:
                        raise RuntimeError("Could not determine container id after docker run")

                    # Running before_script.sh
                    run('./tools/test/before_script.sh', env={**os.environ, **case, "IMAGE": image})

                    # output registered hostnames
                    run('docker', 'exec', cid, 'cat', '/etc/hosts')

                    # Running install_script.sh
                    run('docker', 'exec', cid, './tools/test/install_script.sh')

                    # Running test.sh
                    run('docker', 'exec', cid, './tools/test/test.sh')
                finally:
                    print("*** Finalizing", {**case, "IMAGE": image}, file=sys.stderr, flush=True)

                    if cid:
                        run('docker', 'stop', cid, check=False)
                        run('docker', 'rm', '-v', cid, check=False)
                    if pod:
                        run('podman', 'pod', 'stop', '-t', '10', pod, check=False)
                        run('podman', 'pod', 'rm', '--force', pod, check=False)


if __name__ == "__main__":
    main()
