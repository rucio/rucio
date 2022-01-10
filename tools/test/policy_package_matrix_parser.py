#!/usr/bin/env python3
# Copyright 2021-2022 CERN
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
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021

import sys
import traceback
import json
import argparse
from pathlib import Path
import yaml


def build_config(input_conf):
    build_matrix: list = None
    try:
        build_matrix = [
            {
                "POLICY": policy_package,
                "DIST": dist,
                "RDBMS": rdbms,
                "PYTHON": python_ver,
                "IMAGE_IDENTIFIER": f"votest-{image_identifier}",
            }
            for policy_package in input_conf
            for dist in input_conf[policy_package]['dists']
            for rdbms in input_conf[policy_package]['rdbms']
            for image_identifier in input_conf[policy_package]['image_identifier']
            for python_ver in input_conf[policy_package]['python']
        ]
    except KeyError as e:
        print(f"Key not found for policy package. Check YAML schema. Details: {e}")
        sys.exit(1)
    return json.dumps(build_matrix)


def load_config_file(policy_package_matrix_file):
    input_conf: list = None
    with open(policy_package_matrix_file, 'r') as stream:
        try: 
            input_conf = yaml.safe_load(stream)
        except yaml.parser.ParserError:
            traceback.print_exc()
            print("Error parsing matrix for policy packages. Invalid YAML syntax")
            sys.exit(1)
    return input_conf


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process policy package build matrix')
    parser.add_argument('--file',
                        metavar="file",
                        type=lambda p: Path(p).absolute(),
                        default=Path(Path(__file__).parent.parent.parent / "etc" / "docker" / "test" / "matrix_policy_package_tests.yml").absolute(),
                        help='the path to matric_policy_package_tests.yml',
                        )
    parser.add_argument('--vo', type=str, default='all', required=False)
    output_type = parser.add_mutually_exclusive_group(required=False)
    output_type.add_argument('-i', required=False,
                             action='store_true',
                             help="return the policy package installation command for given vo."
                             )
    output_type.add_argument('-c', required=False,
                             action='store_true',
                             help="return the rucio config section for the given vo.")
    output_type.add_argument('-t', required=False,
                             action='store_true',
                             help="return the tests that will be run for the given vo.")

    args = parser.parse_args()

    file = args.file
    vo = args.vo
    input_conf = load_config_file(file)
    if vo != 'all':
        if args.i:
            print("print installation command for vo")
        elif args.c:
            print("config overrides for vo")
        elif args.t:
            print("tests for vo")
    else:
        if args.i:
            print("Please specify a single vo using the --vo option. The -i flag requires a single VO to be specified.")
            sys.exit(1)
        elif args.c:
            print("Please specify a single vo using the --vo option. The -c flag requires a single VO to be specified.")
            sys.exit(1)
        elif args.t:
            print("Please specify a single vo using the --vo option. The -t flag requires a single VO to be specified.")
            sys.exit(1)
        else:
            print(build_config(input_conf))
