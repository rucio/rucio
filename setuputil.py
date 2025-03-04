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
import os
import subprocess
import sys
from typing import TYPE_CHECKING, Union

from pkg_resources import Requirement, parse_requirements

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

clients_requirements_table = {
    'install_requires': [
        'requests',
        'urllib3',
        'dogpile-cache',
        'packaging',
        'tabulate',
        'jsonschema',
        'dataclasses',
        'rich',
        'typing_extensions'
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
    'pytest-cov',
    'pyflakes',
    'flake8',
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
    'oracle': ['cx_oracle'],
    'mongo': ['pymongo'],
    'elastic': ['elasticsearch'],
    'postgresql': ['psycopg[binary,pool]'],
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


def extract_requirement_with_extras(req_str: str) -> tuple[str, set[str]]:
    """
    Extracts the base-requirement specification (along with its extras) from a full-requirement specification string.

    :param req_str: The full requirement specification (e.g., 'psycopg[binary,pool]').
    :returns: Tuple of (base-requirement specification, set of its extras).
    :raises ValueError: If the input string is invalid and cannot be parsed.
    """
    if not req_str or not isinstance(req_str, str):
        raise ValueError("Input must be a non-empty string representing a requirement.")

    try:
        req = Requirement.parse(req_str)
        return req.key, set(req.extras)
    except Exception as e:
        raise ValueError(f"Invalid dependency string '{req_str}': {e}")


def build_requirements_table_by_key(
        requirements_table: "Mapping[str, Iterable[str]]"
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """
    Build lookup tables for requirements while preserving extras information.

    :param requirements_table: A mapping where:
        - Keys are feature groups (e.g., 'ssh', 'kerberos') or 'install_requires'.
        - Values are iterables of full requirement specifications, potentially including extras (e.g., 'psycopg[pool]').

    :returns: A tuple containing two dictionaries:
        - base_req_to_group: Maps base requirements (e.g., 'psycopg') to a list of feature groups associated with it.
        - extras_require: Maps feature groups to their respective lists of requirement specifications .
    """
    base_req_to_group: dict[str, list[str]] = {}
    extras_require: dict[str, list[str]] = {}

    for feature_group, requirements in requirements_table.items():
        if feature_group != 'install_requires':
            extras_require[feature_group] = []

        for req in requirements:
            base_req, base_req_extras = extract_requirement_with_extras(req)

            # Handle first the identified base requirement
            base_req_to_group.setdefault(base_req, []).append(feature_group)

            # Handle also possible extras as separate base requirements
            for extra_req in base_req_extras:
                base_req_to_group.setdefault(extra_req, []).append(feature_group)

    # Deduplicate lists to handle potential input redundancy or overlaps across groups
    base_req_to_group = {key: list(set(groups)) for key, groups in base_req_to_group.items()}
    extras_require = {key: list(set(reqs)) for key, reqs in extras_require.items()}

    return base_req_to_group, extras_require


def match_define_requirements(
        app_type: str,
        requirements_table: "Mapping[str, Iterable[str]]"
) -> tuple[list[str], dict[str, list[str]]]:
    """
    Prepare and return the 'install_requires' and 'extras_require' objects for setuptools.setup().

    :param app_type: The application type, which determines the requirements file to use (e.g., 'server', 'client').
    :param requirements_table: A mapping where:
        - Keys are feature groups (e.g., 'postgresql', 'oracle', or 'install_requires').
        - Values are iterables of full requirement specifications.

    :returns: A tuple containing:
        - install_requires: A list of requirements (e.g., ['requests==2.32.3', 'urllib3==1.26.19']).
        - extras_require: A dictionary mapping feature groups to their respective lists of requirements
          (e.g., {'postgresql': ['psycopg[binary]==3.2.3'], 'oracle': ['cx_oracle==8.3.0']}).

    :raises RuntimeError: If any `extras_require` feature group is empty or a requirements file is missing.
    :raises ValueError: If the `requirements_table` is invalid.
    """

    install_requires: list[str] = []

    # Build base requirement mappings and initial extras_require
    base_req_to_group, extras_require = build_requirements_table_by_key(requirements_table)

    # Construct the filename for the pip-compiled requirements file
    req_file_name = f"requirements/requirements.{app_type}.txt"
    if not os.path.exists(req_file_name):
        raise RuntimeError(f"Requirements file '{req_file_name}' not found.")

    # Read and parse the requirements file
    with open(req_file_name, 'r') as fhandle:
        for req in parse_requirements(fhandle.readlines()):
            if req.key in base_req_to_group:
                for feature_group in base_req_to_group[req.key]:
                    print("requirement found", feature_group, req, file=sys.stderr)
                    if feature_group == 'install_requires':
                        install_requires.append(str(req))
                    else:
                        extras_require[feature_group].append(str(req))

            else:
                print("requirement unused", req, "(from " + req.key + ")", file=sys.stderr)
        sys.stderr.flush()

    # Validate that all feature groups have at least one dependency
    for feature_group, deps in extras_require.items():
        if not deps:
            raise RuntimeError(f"Empty feature group '{feature_group}' found in extras_require.")

    return install_requires, extras_require


def list_all_requirements(app_type: str, requirements_table: "Mapping[str, Iterable[str]]") -> None:
    req_table_by_key, _ = build_requirements_table_by_key(requirements_table)
    req_file_name = "requirements/requirements.{}.txt".format(app_type)

    with open(req_file_name, 'r') as fhandle:
        for req in parse_requirements(fhandle.readlines()):
            if req.key in req_table_by_key:
                print(str(req))
