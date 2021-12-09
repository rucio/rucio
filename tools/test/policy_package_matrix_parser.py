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
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021

import yaml
import traceback
import sys
import json


def readobj(policy_package: dict) -> dict:
    """
    parse individual objects from matrix_policy_package_tests.yaml
    """

def main():
    input_conf: list = None
    build_matrix: list = None

    try:
        input_conf = dict(yaml.safe_load(sys.stdin))
    except yaml.parser.ParserError as ex:
        traceback.print_exc()
        print(f"Error parsing matrix for policy packages. Invalid YAML syntax")
    else:
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

        print(json.dumps(build_matrix), file=sys.stdout)


if __name__ == "__main__":
    main()
