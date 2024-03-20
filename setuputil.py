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

import subprocess
import sys

from pkg_resources import parse_requirements, safe_name

clients_requirements_table = {
    'install_requires': [
        'requests',
        'urllib3',
        'dogpile.cache',
        'tabulate',
        'jsonschema',
        'dataclasses',
    ],
    'ssh': ['paramiko'],
    'kerberos': [
        'kerberos',
        'pykerberos',
        'requests-kerberos',
    ],
    'swift': ['python-swiftclient'],
    'argcomplete': ['argcomplete'],
    'sftp': ['paramiko'],
    'dumper': [
        'python-magic',
    ],
}

dev_requirements = [
    'pytest',
    'pytest-xdist',
    'pyflakes',
    'flake8',
    'pylint',
    'isort',
    'virtualenv',
    'xmltodict',
    'pytz',
    'pycodestyle',
    'pydoc-markdown',
    'docspec_python',
    'sh',
    'PyYAML',
]

server_requirements_table = {
    'install_requires': clients_requirements_table['install_requires'] + [
        'argcomplete',
        'boto',
        'python-magic',
        'paramiko',
        'boto3',
        'sqlalchemy',
        'alembic',
        'pymemcache',
        'python-dateutil',
        'stomp.py',
        'statsd',
        'geoip2',
        'google-auth',
        'redis',
        'flask',
        'oic',
        'prometheus_client',
    ],
    'oracle': ['cx_oracle'],
    'mongo': ['pymongo'],
    'postgresql': ['psycopg2-binary'],
    'mysql': ['PyMySQL'],
    'kerberos': [
        'kerberos',
        'pykerberos',
        'requests-kerberos',
    ],
    'globus': [
        'PyYAML',
        'globus-sdk',
    ],
    'saml': ['python3-saml'],
    'dev': dev_requirements
}


def run_shell_command(cmd):
    """
    Run a shell command in path and return output"

    :param cmd: the shell command.
    :return: Output of the shell command.
    """
    output = subprocess.Popen(["/bin/sh", "-c", cmd], stdout=subprocess.PIPE)
    stdout = output.communicate()[0].strip()
    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors='replace')
    return stdout


def get_rucio_version():
    python_executable = "'" + sys.executable + "'"
    ver = run_shell_command(
        "PYTHONPATH=lib " + python_executable + " -c "
        '"from rucio import version; print(version.version_string())"'
    )
    if not ver:
        raise RuntimeError("Could not fetch Rucio version")
    return ver


def _build_requirements_table_by_key(requirements_table):
    extras_require = {}
    req_table_by_key = {}
    for group in requirements_table.keys():
        if group != 'install_requires' and group not in extras_require:
            extras_require[group] = []
        for key in map(str.lower, map(safe_name, requirements_table[group])):
            if key in req_table_by_key:
                req_table_by_key[key].append(group)
            else:
                req_table_by_key[key] = [group]
    return req_table_by_key, extras_require


def match_define_requirements(requirements_table):
    install_requires = []
    req_table_by_key, extras_require = _build_requirements_table_by_key(requirements_table)

    with open('requirements.txt', 'r') as fhandle:
        for req in parse_requirements(fhandle.readlines()):
            if req.key in req_table_by_key:
                for group in req_table_by_key[req.key]:
                    print("requirement found", group, req, file=sys.stderr)
                    if group == 'install_requires':
                        install_requires.append(str(req))
                    else:
                        extras_require[group].append(str(req))
            else:
                print("requirement unused", req, "(from " + req.key + ")", file=sys.stderr)
        sys.stderr.flush()

    for extra, deps in extras_require.items():
        if not deps:
            raise RuntimeError('Empty extra: {}'.format(extra))

    return install_requires, extras_require


def list_all_requirements(requirements_table):
    req_table_by_key, _ = _build_requirements_table_by_key(requirements_table)
    with open('requirements.txt', 'r') as fhandle:
        for req in parse_requirements(fhandle.readlines()):
            if req.key in req_table_by_key:
                print(str(req))
