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

import io
import itertools
import subprocess
import sys
import typing
from typing import Tuple, Optional, Dict, List

DEFAULT_TIMEOUT = 10
DEFAULT_DB_TIMEOUT = 27


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


def env_args(caseenv):
    environment_args = list(itertools.chain(*map(lambda x: ('--env', f'{x[0]}={x[1]}'), caseenv.items())))
    environment_args.append('--env')
    environment_args.append('GITHUB_ACTIONS')
    return environment_args


class Container:
    def __init__(
        self,
        image: "str",
        *args,
        runtime_args: "Optional[List[str]]" = None,
        run_args: "Optional[List[str]]" = None,
        environment: "Optional[Dict[str, str]]" = None,
        stop_timeout: int = DEFAULT_TIMEOUT,
    ):
        if runtime_args is None:
            runtime_args = []
        self.runtime_args = runtime_args
        if run_args is None:
            run_args = []
        if environment is None:
            environment = {}
        self.stop_timeout = stop_timeout
        self.args = ['docker', *runtime_args, 'run', '--detach', *run_args, *(env_args(environment)), image, *args]
        self.cid = None

    def __enter__(self):
        stdout = run(*self.args, return_stdout=True)
        self.cid = stdout.decode().strip()
        if not self.cid:
            raise RuntimeError("Could not determine container id after starting the container")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        run('docker', *self.runtime_args, 'stop', f'--time={self.stop_timeout}', self.cid, check=False)
        run('docker', *self.runtime_args, 'rm', '--force', '--volumes', self.cid, check=False)

    def wait(self):
        run('docker', *self.runtime_args, 'wait', self.cid, check=False)


class CumulativeContextManager:
    def __init__(self, *context_managers):
        self.context_managers = context_managers

    def __enter__(self):
        for mgr in self.context_managers:
            mgr.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for mgr in self.context_managers:
            mgr.__exit__(exc_type, exc_val, exc_tb)


class OracleDB(Container):
    def __init__(
        self,
        runtime_args: "Optional[Tuple[str]]" = None,
        run_args: "Optional[Tuple[str]]" = None,
        environment: "Optional[Dict[str, str]]" = None,
        stop_timeout: int = DEFAULT_DB_TIMEOUT,
    ):
        if run_args is None:
            run_args = tuple()
        run_args = ("--no-healthcheck",) + run_args
        if environment is None:
            environment = dict()
        environment['processes'] = "1000"
        environment["sessions"] = "1105"
        environment["transactions"] = "1215"
        environment["ORACLE_ALLOW_REMOTE"] = "true"
        environment["ORACLE_PASSWORD"] = "oracle"
        environment["ORACLE_DISABLE_ASYNCH_IO"] = "true"
        super(OracleDB, self).__init__(
            "docker.io/gvenzl/oracle-xe:18.4.0",
            runtime_args=runtime_args,
            run_args=run_args,
            environment=environment,
            stop_timeout=stop_timeout,
        )


class MySQL5(Container):
    def __init__(
        self,
        runtime_args: "Optional[Tuple[str]]" = None,
        run_args: "Optional[Tuple[str]]" = None,
        environment: "Optional[Dict[str, str]]" = None,
        stop_timeout: int = DEFAULT_DB_TIMEOUT,
    ):
        if environment is None:
            environment = dict()
        environment["MYSQL_ROOT_PASSWORD"] = "secret"
        environment["MYSQL_ROOT_HOST"] = "%"
        super(MySQL5, self).__init__(
            "docker.io/mysql/mysql-server:5.7",
            runtime_args=runtime_args,
            run_args=run_args,
            environment=environment,
            stop_timeout=stop_timeout,
        )


class MySQL8(Container):
    def __init__(
        self,
        runtime_args: "Optional[Tuple[str]]" = None,
        run_args: "Optional[Tuple[str]]" = None,
        environment: "Optional[Dict[str, str]]" = None,
        stop_timeout: int = DEFAULT_DB_TIMEOUT,
    ):
        if environment is None:
            environment = dict()
        environment["MYSQL_ROOT_PASSWORD"] = "secret"
        environment["MYSQL_ROOT_HOST"] = "%"
        super(MySQL8, self).__init__(
            "docker.io/mysql/mysql-server:8.0",
            "--default-authentication-plugin=mysql_native_password",
            "--character-set-server=latin1",
            runtime_args=runtime_args,
            run_args=run_args,
            environment=environment,
            stop_timeout=stop_timeout,
        )


class Postgres14(Container):
    def __init__(
        self,
        runtime_args: "Optional[Tuple[str]]" = None,
        run_args: "Optional[Tuple[str]]" = None,
        environment: "Optional[Dict[str, str]]" = None,
        stop_timeout: int = DEFAULT_DB_TIMEOUT,
    ):
        if environment is None:
            environment = dict()
        environment["POSTGRES_PASSWORD"] = "secret"
        super(Postgres14, self).__init__(
            "docker.io/postgres:14",
            "-c", "max_connections=300",
            runtime_args=runtime_args,
            run_args=run_args,
            environment=environment,
            stop_timeout=stop_timeout,
        )


class ActiveMQ(Container):
    def __init__(
        self,
        runtime_args: "Optional[Tuple[str]]" = None,
        run_args: "Optional[Tuple[str]]" = None,
        environment: "Optional[Dict[str, str]]" = None,
        stop_timeout: int = DEFAULT_DB_TIMEOUT,
    ):
        super(ActiveMQ, self).__init__(
            "docker.io/webcenter/activemq:latest",
            runtime_args=runtime_args,
            run_args=run_args,
            environment=environment,
            stop_timeout=stop_timeout,
        )


class InfluxDB(Container):
    def __init__(
        self,
        runtime_args: "Optional[Tuple[str]]" = None,
        run_args: "Optional[Tuple[str]]" = None,
        environment: "Optional[Dict[str, str]]" = None,
        stop_timeout: int = DEFAULT_DB_TIMEOUT,
    ):
        if environment is None:
            environment = dict()
        environment["DOCKER_INFLUXDB_INIT_MODE"] = "setup"
        environment["DOCKER_INFLUXDB_INIT_USERNAME"] = "myusername"
        environment["DOCKER_INFLUXDB_INIT_PASSWORD"] = "passwordpasswordpassword"
        environment["DOCKER_INFLUXDB_INIT_ORG"] = "rucio"
        environment["DOCKER_INFLUXDB_INIT_BUCKET"] = "rucio"
        environment["DOCKER_INFLUXDB_INIT_ADMIN_TOKEN"] = "mytoken"
        super(InfluxDB, self).__init__(
            "docker.io/influxdb:latest",
            runtime_args=runtime_args,
            run_args=run_args,
            environment=environment,
            stop_timeout=stop_timeout,
        )


class Elasticsearch(Container):
    def __init__(
        self,
        runtime_args: "Optional[Tuple[str]]" = None,
        run_args: "Optional[Tuple[str]]" = None,
        environment: "Optional[Dict[str, str]]" = None,
        stop_timeout: int = DEFAULT_DB_TIMEOUT,
    ):
        if environment is None:
            environment = dict()
        environment["discovery.type"] = "single-node"
        super(Elasticsearch, self).__init__(
            "docker.elastic.co/elasticsearch/elasticsearch:6.4.2",
            runtime_args=runtime_args,
            run_args=run_args,
            environment=environment,
            stop_timeout=stop_timeout,
        )


rdbms_container: Dict[str, typing.Any] = {
    "oracle": OracleDB,
    "mysql5": MySQL5,
    "mysql8": MySQL8,
    "postgres14": Postgres14,
    "sqlite": None,
}
services = {
    'default': [ActiveMQ],
    'influxdb_elastic': [ActiveMQ, InfluxDB, Elasticsearch],
}
service_hostnames = ['activemq', 'influxdb', 'elasticsearch'] + list(rdbms_container.keys())
