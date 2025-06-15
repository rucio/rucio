#!/usr/bin/env python
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

import argparse
import os

# from setup_rucio_clients
PACKAGES = [
    'rucio',
    'rucio.client',
    'rucio.common',
    'rucio.common.schema',
    'rucio.rse.protocols',
    'rucio.rse',
    # 'rucio.tests'  do not include tests
]  # type: list[str]


def package_directories(packages):
    """Convert package names into directory paths under 'lib/'."""
    return ['lib/' + p.replace('.', '/') for p in packages]


def get_excluded_dirs():
    """Find directories to exclude for Ruff, excluding __pycache__ and test files."""
    include_dirs = set(package_directories(PACKAGES))
    exclude_dirs = []

    for root, dirs, files in os.walk('lib/'):
        if '__pycache__' in root or root == 'lib/' or root in include_dirs:
            continue
        exclude_dirs.append(root)

    return exclude_dirs


def main():
    parser = argparse.ArgumentParser(description='Returns ignore-strings for Ruff')
    parser.add_argument('-r', '--ruff', dest='ruff', action='store_true',
                        help='Build a list for Ruff with the --extend-exclude flag')
    script_args = parser.parse_args()

    if script_args.ruff:
        exclude_dirs = get_excluded_dirs()
        if exclude_dirs:
            print(f'--extend-exclude="{",".join(exclude_dirs)}" lib/')
        else:
            print('lib/')


if __name__ == '__main__':
    main()
