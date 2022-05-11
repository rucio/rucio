#!/bin/bash
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

set -euo pipefail
IFS=$'\n\t'

USE_PODMAN=${USE_PODMAN-}
if [ -z "$USE_PODMAN" ]; then
    if [ -x /usr/bin/podman -a ! -x /usr/bin/docker ] || grep -q /usr/bin/podman /usr/bin/docker; then
        echo "Detected podman environment"
        export USE_PODMAN=1
    fi
fi

PARALLEL_AUTOTESTS=${PARALLEL_AUTOTESTS-}
if [ "x$PARALLEL_AUTOTESTS" != "xfalse" -a "x$PARALLEL_AUTOTESTS" != "x0" ]; then
    echo "Tests will run in parallel"
    export PARALLEL_AUTOTESTS=1
fi

# fetch project directory relatively to this file
PROJECT_DIR="$(dirname $0)/.."
MATRIX_FILE=${1:-"$PROJECT_DIR/etc/docker/test/matrix.yml"}

MATRIX=`"$PROJECT_DIR/tools/test/matrix_parser.py" < $MATRIX_FILE`
if [ -z "$MATRIX" ]; then
    echo "Matrix could not be determined"
    exit 1
fi

IMAGES=`echo $MATRIX | nice "$PROJECT_DIR/tools/test/build_images.py" "$PROJECT_DIR/etc/docker/test"`
if [ -z "$IMAGES" ]; then
    echo "Images could not be built"
    exit 1
fi

RUN_TESTS_JSON="{\"matrix\": $MATRIX, \"images\": $IMAGES}"
echo "$RUN_TESTS_JSON"
echo "$RUN_TESTS_JSON" | nice "$PROJECT_DIR/tools/test/run_tests.py"
