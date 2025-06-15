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
import os
import shutil
import signal
import sys

# make sure the following imports work
sys.path.append(os.path.abspath(os.path.dirname(__file__)))  # noqa: E402
import build_images  # noqa: E402
from matrix_parser import parse_matrix  # noqa: E402
from run_tests import run_tests  # noqa: E402


def shutdown(signum, frame):
    print("Caught", signal.Signals(signum).name + ". Stopping..", file=sys.stderr)
    sys.exit(1)


def check_container_runtime():
    if 'USE_PODMAN' not in os.environ or os.environ['USE_PODMAN'] == "":
        docker_executable = shutil.which("docker")
        podman_executable = shutil.which("podman")
        if docker_executable and podman_executable:
            with open(docker_executable, 'br') as fhandle:
                if podman_executable.encode() in fhandle.read():
                    os.environ['USE_PODMAN'] = "1"
        elif docker_executable:
            os.environ['USE_PODMAN'] = "0"
        elif podman_executable:
            os.environ['USE_PODMAN'] = "1"
        else:
            print("No compatible container executable (podman/docker) found! Exiting..", file=sys.stderr)
            sys.exit(1)


def parse_arguments(default_matrix_file):
    parser = argparse.ArgumentParser(description='Run the full autotest pipeline.')
    parser.add_argument('test_matrix_file', metavar='test matrix file', type=str, nargs='?',
                        default=default_matrix_file, help='path to the test matrix')
    parser.add_argument('--build', dest='build', action='store_true',
                        help='build images, instead of only downloading')
    parser.add_argument('-f', '--filter', dest='filter_tests', type=str, action='append',
                        help='filter tests')
    parser.add_argument('-d', '--dist', dest='dist', type=str, help='select distribution')
    parser.add_argument('--py', '--python', dest='python', type=str, help='select Python version')
    parser.add_argument('-s', '--suite', dest='suite', type=str, help='select test suite')
    parser.add_argument('--db', '--database', dest='database', type=str, help='select RDBMS')
    return parser.parse_args()


def parse_and_filter_matrix(args):
    with open(args.test_matrix_file, 'r') as fhandle:
        test_matrix = parse_matrix(fhandle)

    if not test_matrix:
        print("Matrix could not be determined", file=sys.stderr)
        sys.exit(1)

    def argument_filter(case):
        if args.dist:
            if case['DIST'] != args.dist:
                return False
        if args.python:
            if case['PYTHON'] != args.python:
                return False
        if args.suite:
            if case['SUITE'] != args.suite:
                return False
        if args.database:
            if case['RDBMS'] != args.database:
                return False
        return True

    test_matrix = list(filter(argument_filter, test_matrix))

    if len(test_matrix) == 0:
        print("No more test cases after filtering. Exiting..", file=sys.stderr)
        sys.exit(0)

    return test_matrix


def main():
    check_container_runtime()

    project_dir = os.path.abspath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "../.."))
    print("Detected project directory", project_dir, file=sys.stderr)

    default_matrix_file = os.path.join(project_dir, "etc/docker/test/matrix.yml")
    args = parse_arguments(default_matrix_file)
    print("Using test matrix from file", args.test_matrix_file, file=sys.stderr)

    test_matrix = parse_and_filter_matrix(args)

    if len(test_matrix) == 1 and 'PARALLEL_AUTOTESTS' not in os.environ:
        print("One test case remaining after filtering. Switching to serial run", file=sys.stderr)
        os.environ['PARALLEL_AUTOTESTS'] = "0"
    elif 'PARALLEL_AUTOTESTS' not in os.environ or (os.environ['PARALLEL_AUTOTESTS'] not in ['false', '0']):
        print("Tests will run in parallel", file=sys.stderr)
        os.environ['PARALLEL_AUTOTESTS'] = "1"

    build_args = [os.path.join(project_dir, "etc/docker/test")]
    if not args.build:
        build_args.insert(0, "--download-only")
    images = build_images.build_main(test_matrix, build_args)

    if not images:
        print("Images could not be built", file=sys.stderr)

    run_tests(test_matrix, images, args.filter_tests)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    main()
