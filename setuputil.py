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
from typing import Union

clients_requirements_table = {
    'install_requires': [
        'requests',
        'urllib3',
        'dogpile-cache',
        'tabulate',
        'jsonschema',
        'dataclasses',
    ],
    'extras_require': {
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
        'stomp-py',
        'statsd',
        'geoip2',
        'google-auth',
        'redis',
        'flask',
        'oic',
        'prometheus_client',
    ],
    'extras_require': {
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
}


def run_shell_command(cmd: str) -> Union[str, bytearray, memoryview]:
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


def get_rucio_version() -> str:
    python_executable = "'" + sys.executable + "'"
    ver = run_shell_command(
        "PYTHONPATH=lib " + python_executable + " -c "
        '"from rucio import version; print(version.version_string())"'
    )
    if not ver:
        raise RuntimeError("Could not fetch Rucio version")
    return str(ver)
