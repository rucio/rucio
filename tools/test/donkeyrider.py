#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
import shutil
import signal
import sys

stop = False


def shutdown(signum, frame):
    global stop
    stop = True
    print("Caught", signal.Signals(signum).name + ". Stopping..", file=sys.stderr)
    sys.exit(1)


def main():
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

    if 'PARALLEL_AUTOTESTS' not in os.environ or (os.environ['PARALLEL_AUTOTESTS'] not in ['false', '0']):
        print("Tests will run in parallel", file=sys.stderr)
        os.environ['PARALLEL_AUTOTESTS'] = "1"

    project_dir = os.path.abspath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "../.."))
    print("Detected project directory", project_dir, file=sys.stderr)

    if len(sys.argv) > 1:
        matrix_file = sys.argv[1]
    else:
        matrix_file = os.path.join(project_dir, "etc/docker/test/matrix.yml")
    print("Using test matrix from file", matrix_file, file=sys.stderr)

    # make sure the following imports work
    sys.path.append(os.path.abspath(os.path.dirname(__file__)))

    # matrix parsing

    from matrix_parser import parse_matrix

    with open(matrix_file, 'r') as fhandle:
        test_matrix = parse_matrix(fhandle)

    if not test_matrix:
        print("Matrix could not be determined", file=sys.stderr)
        sys.exit(1)

    # image building

    from build_images import build_main

    images = build_main(test_matrix, ["--download-only", os.path.join(project_dir, "etc/docker/test")])

    if not images:
        print("Images could not be built", file=sys.stderr)

    # test running

    from run_tests import run_tests

    run_tests(test_matrix, images)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    main()
