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
        'click',
        'requests',
        'urllib3',
        'dogpile-cache',
        'packaging',
        'tabulate',
        'jsonschema',
        'rich',
        'typing_extensions'
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
    'pytest-cov',
    'pyflakes',
    'pylint',
    'isort',
    'xmltodict',
    'pytz',
    'pycodestyle',
    'pydoc-markdown',
    'docspec_python',
    'sh',
    'PyYAML',
]

server_requirements_table = {
    'install_requires': [
        'requests<=2.32.5',
        'urllib3<=1.26.19',
        'dogpile-cache<=1.2.2',
        'packaging<=25.0',
        'tabulate<=0.9.0',
        'jsonschema<=4.25.1',
        'rich<=14.2.0',
        'typing_extensions<=4.15.0',
        'argcomplete<=3.6.3',
        'boto',  # no upper limit is set in .in or .txt req files
        'python-magic<=0.4.27',
        'paramiko<=4.0.0',
        'boto3<=1.40.64',
        'sqlalchemy<=2.0.44',
        'alembic<=1.16.5',
        'pymemcache<=4.0.0',
        'python-dateutil<=2.9.0.post0',
        'stomp-py<=8.2.0',
        'statsd<=4.0.1',
        'geoip2<=5.1.0',
        'google-auth<=2.42.1',
        'redis<=7.0.1',
        'flask<=3.1.2',
        'oic<=1.7.0',
        'prometheus_client<=0.23.1',
    ],
    'extras_require': {
        'oracle': ['oracledb<=3.4.0'],
        'mongo': ['pymongo<=4.15.3'],
        'elastic': ['elasticsearch<=8.15.1'],
        'postgresql': [
            'psycopg<=3.2.12',
            'psycopg-binary<=3.2.12',
            'psycopg-pool<=3.2.12',
        ],
        'mysql': ['PyMySQL<=1.1.1'],
        'kerberos': [
            'kerberos<=1.3.1',
            'pykerberos<=1.2.4',
            'requests-kerberos<=0.15.0',
        ],
        'globus': [
            'PyYAML<=6.0.3',
            'globus-sdk<=4.1.0',
        ],
        'saml': ['python3-saml<=1.16.0'],
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
