#!/bin/bash
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

set -euo pipefail
IFS=$'\n\t'

# change directory to main repository directory
cd `dirname $0`/..

BASE_BRANCH=master INCLUDE_UNSTAGED=true INCLUDE_STAGED=true ./tools/test/create_changelist.sh
MATRIX=`./tools/test/matrix_parser.py < ./etc/docker/test/matrix.yml`
if [[ -z "$MATRIX" ]]; then
    echo "Matrix could not be determined"
    exit 1
fi
IMAGES=`echo $MATRIX | ./tools/test/build_images.py ./etc/docker/test`
if [[ -z "$IMAGES" ]]; then
    echo "Images could not be built"
    exit 1
fi

echo "{\"matrix\": $MATRIX, \"images\": $IMAGES}" | ./tools/test/run_tests.py
