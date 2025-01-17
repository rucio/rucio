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
    'rucio.core.common',
    'rucio.core.common.schema',
    'rucio.rse.protocols',
    'rucio.rse',
    # 'rucio.tests'  do not include tests
]  # type: list[str]


def package_directories(packages):
    for directory in map(lambda p: './' + p.replace('.', '/'), packages):
        yield directory


def main():
    parser = argparse.ArgumentParser(description='Returns ignore-strings for client files')
    parser.add_argument('-l', '--pylint', dest='pylint', action='store_true',
                        help='build a list for pylint with the --ignore flag')
    parser.add_argument('-f', '--flake8', dest='flake8', action='store_true',
                        help='build a list for flake8 tool')
    script_args = parser.parse_args()

    if script_args.flake8:
        print(' '.join(map(lambda d: d + '/*.py', package_directories(PACKAGES))))
    elif script_args.pylint:
        ignore_dirs = []
        include_dirs = set(package_directories(PACKAGES))

        for root, dirs, files in os.walk('./'):
            if '__pycache__' not in root and root != './' and root not in include_dirs:
                ignore_dirs.append(root)

        if ignore_dirs:
            print('--ignore=' + ','.join(ignore_dirs), './')
        else:
            print('.')


if __name__ == '__main__':
    main()
