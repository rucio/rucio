#!/usr/bin/env python3
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
import configparser
import functools
import glob
import itertools
import json
import logging
import sys
import traceback
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


def validate(func):
    """
    A decorator to validate vo-specific sections contained in matrix_policy_package_tests.yaml
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if 'data' not in kwargs:
            logger.error("Please specify a kwarg data for %s", func.__name__)
            sys.exit(1)
        if 'vo' not in kwargs:
            logger.error("Please specify a kwarg vo for %s", func.__name__)
        if 'section' not in kwargs:
            logger.error("Please specify a kwarg section for %s", func.__name__)
        data = kwargs['data']
        vo = kwargs['vo']
        section = kwargs['section']
        if vo not in data:
            logger.error("%s is not defined in the matrix configuration file.", vo,)
            sys.exit(1)
        if section not in data[vo]:
            logger.error("No {section} found for installing policy packages for vo %s", vo,)
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
        logger.warning("No Installation command specified for %s", vo)
        sys.exit(1)
    return installation_cmd


def persist_config_overrides(data: dict, vo: str, rucio_cfg: Path):
    config_overrides = get_config(data=data, vo=vo, section="config_overrides")
    if len(config_overrides) == 0:
        logger.warning("No config overrides specified for policy %s. Rucio Configuration will not be modified.", vo)
        sys.exit(1)

    if not rucio_cfg.is_file():
        logger.warning("Rucio Configuration File not found at %s. Please use --rucio-cfg option to specify a valid path.", rucio_cfg)
        sys.exit(1)
    rucio_config = configparser.ConfigParser()
    rucio_config.read(rucio_cfg)

    policy_section = rucio_config['policy']
    policy_section.clear()

    for key, val in config_overrides.items():
        policy_section[key] = val
    with open(rucio_cfg, 'w') as rucio:
        logger.warning("Overriding policy section in %s", rucio_cfg)
        rucio_config.write(rucio)
    return config_overrides


def combine_paths(all_paths):
    """Flatten a sequence of iterables into a single iterator."""
    return itertools.chain.from_iterable(all_paths)


def collect_tests(data: dict, vo: str):
    keyword_path_mapping = {
        Path("rucio_tests"): Path("tests/"),
        Path("rucio_root"): Path("/opt/rucio"),
    }
    substitute_keywords = functools.partial(functools.reduce, lambda path, part: path / keyword_path_mapping[part] if part in keyword_path_mapping.keys() else path / part)
    resolve_path_keywords = functools.partial(map, lambda path: substitute_keywords([keyword_path_mapping[Path("rucio_root")]] + [Path(x) for x in Path(path).parts]))
    resolve_paths = functools.partial(map, lambda path: glob.glob(f"{path}/test_*.py") if path.is_dir() else [str(path)])
    filter_paths = functools.partial(filter, lambda path: Path(path).is_file())
    tests = get_config(data=data, vo=vo, section="tests")
    allowed_paths = set(filter_paths(combine_paths(resolve_paths(resolve_path_keywords(tests.get('allow', []))))))
    excluded_paths = set(filter_paths(combine_paths(resolve_paths(resolve_path_keywords(tests.get('deny', []))))))
    tests_to_run = allowed_paths - excluded_paths
    return " ".join(tests_to_run)


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
        logger.warning("Key not found for policy package. Check YAML schema. Details: %s", e)
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
    parser = argparse.ArgumentParser(description='Utils for extracting information from policy package build matrix')
    parser.add_argument('--file',
                        metavar="file",
                        type=lambda p: Path(p).absolute(),
                        default=Path(Path(__file__).parent.parent.parent / "etc" / "docker" / "test" / "matrix_policy_package_tests.yml").absolute(),
                        help='the path to matrix_policy_package_tests.yml',
                        )
    parser.add_argument('--rucio-cfg',
                        metavar="rucio",
                        type=lambda p: Path(p).absolute(),
                        default=Path(Path(__file__).parent.parent.parent / "etc" / "rucio.cfg").absolute(),
                        help='the path to rucio.cfg',
                        )
    parser.add_argument('--vo', type=str, default='all', required=False)
    parser.add_argument('--verbose', '-v', action='store_true',
                        required=False,
                        help="Verbose mode to show logged errors")
    output_type = parser.add_mutually_exclusive_group(required=False)
    output_type.add_argument('--installation-command', '-i', required=False,
                             action='store_true',
                             help="return the policy package installation command for given vo."
                             )
    output_type.add_argument('--vo-config', '-c', required=False,
                             action='store_true',
                             help="return the rucio config section for the given vo.")
    output_type.add_argument('--tests', '-t', required=False,
                             action='store_true',
                             help="return the tests that will be run for the given vo.")

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
    file = args.file
    vo = args.vo
    input_conf = load_config_file(file)
    if vo != 'all':
        if args.installation_command:
            print(get_installation_cmd(input_conf, vo))
        elif args.vo_config:
            rucio_cfg = args.rucio_cfg
            print(persist_config_overrides(input_conf, vo, rucio_cfg))
        elif args.tests:
            print(collect_tests(input_conf, vo))
    else:
        if args.installation_command:
            logger.warning("Please specify a single vo using the --vo option. The -i flag requires a single VO to be specified.")
            sys.exit(1)
        elif args.vo_config:
            logger.warning("Please specify a single vo using the --vo option. The -c flag requires a single VO to be specified.")
            sys.exit(1)
        elif args.tests:
            logger.warning("Please specify a single vo using the --vo option. The -t flag requires a single VO to be specified.")
            sys.exit(1)
        else:
            print(build_config(input_conf))
