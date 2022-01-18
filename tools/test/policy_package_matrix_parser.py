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
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021-2022

import sys
import traceback
import json
import argparse
import logging
import functools
from pathlib import Path
import yaml


logger = logging.getLogger(__name__)


def validate(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if 'data' not in kwargs:
            logger.error(f"Please specify a kwarg data for {func.__name__}")
            sys.exit(1)
        if 'vo' not in kwargs:
            logger.error(f"Please specify a kwarg vo for {func.__name__}")
        if 'section' not in kwargs:
            logger.error(f"Please specify a kwarg section for {func.__name__}")
        data = kwargs['data']
        vo = kwargs['vo']
        section = kwargs['section']
        if vo not in data:
            logger.error(f"{vo} is not defined in the matrix configuration file.")
            sys.exit(1)
        if section not in data[vo]:
            logger.error(f"No {section} found for installing policy packages for vo {vo}")
            sys.exit(1)
        output = func(*args, **kwargs)
        return output
    return wrapper


@validate
def get_config(data: dict, vo: str, section: str):
    return data[vo][section]


def get_installation_cmd(data: dict, vo: str):
    installation_cmd = get_config(data=data, vo=vo, section="installation_cmd")
    if installation_cmd == '':
        logger.warning(f"No Installation command specified for {vo}")
        sys.exit(1)
    return installation_cmd


def get_config_overrides(data: dict, vo: str, rucio_cfg: Path):
    config_overrides = get_config(data=data, vo=vo, section="config_overrides")
    if rucio_cfg is None:
        logger.warning("Config overrides will not take effect as path to rucio.cfg has not been specified")
        return config_overrides
    with open(rucio_cfg, 'r') as rucio:
        pass


def build_config(input_conf):
    build_matrix: list = None
    try:
        build_matrix = [
            {
                "POLICY": policy_package,
                "DIST": dist,
                "RDBMS": rdbms,
                "PYTHON": python_ver,
                "SUITE": "votest",
                "IMAGE_IDENTIFIER": f"votest-{image_identifier}",
            }
            for policy_package in input_conf
            for dist in input_conf[policy_package]['dists']
            for rdbms in input_conf[policy_package]['rdbms']
            for image_identifier in input_conf[policy_package]['image_identifier']
            for python_ver in input_conf[policy_package]['python']
        ]
    except KeyError as e:
        logger.warning(f"Key not found for policy package. Check YAML schema. Details: {e}")
        sys.exit(1)
    return json.dumps(build_matrix)


def load_config_file(policy_package_matrix_file):
    input_conf: list = None
    with open(policy_package_matrix_file, 'r') as stream:
        try:
            input_conf = yaml.safe_load(stream)
        except yaml.parser.ParserError:
            traceback.print_exc()
            logger.warning("Error parsing matrix for policy packages. Invalid YAML syntax")
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
    parser.add_argument('--rucio-cfg',
                        metavar="rucio",
                        type=lambda p: Path(p).absolute(),
                        default=Path(Path(__file__).parent.parent.parent / "etc" / "rucio.cfg").absolute(),
                        help='the path to matric_policy_package_tests.yml',
                        )
    parser.add_argument('--vo', type=str, default='all', required=False)
    parser.add_argument('-v', action='store_true',
                        required=False,
                        help="Verbose mode to show logged errors")
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
    if args.v:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
    file = args.file
    vo = args.vo
    input_conf = load_config_file(file)
    if vo != 'all':
        if args.i:
            print(get_installation_cmd(input_conf, vo))
        elif args.c:
            rucio_cfg = args.rucio_cfg
            if rucio_cfg is None:
                logger.warning(f"Please specify path to rucio.cfg in order to apply the configration changes.")
            print(get_config_overrides(input_conf, vo, rucio_cfg))
        elif args.t:
            print("tests for vo")
    else:
        if args.i:
            logger.warning("Please specify a single vo using the --vo option. The -i flag requires a single VO to be specified.")
            sys.exit(1)
        elif args.c:
            logger.warning("Please specify a single vo using the --vo option. The -c flag requires a single VO to be specified.")
            sys.exit(1)
        elif args.t:
            logger.warning("Please specify a single vo using the --vo option. The -t flag requires a single VO to be specified.")
            sys.exit(1)
        else:
            print(build_config(input_conf))
