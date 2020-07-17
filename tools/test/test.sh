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

set -eo pipefail

function srchome() {
    export RUCIO_HOME=/usr/local/src/rucio
    cd $RUCIO_HOME
}

if [[ $SUITE == "syntax" ]]; then
    srchome
    tools/test/check_syntax.sh
fi

if [[ $SUITE == "python3" ]]; then
    srchome
    tools/test/check_python_3.sh
fi

if [[ $SUITE == "client" ]]; then
    srchome
    nosetests -v lib/rucio/tests/test_clients.py
    nosetests -v lib/rucio/tests/test_bin_rucio.py
    nosetests -v lib/rucio/tests/test_module_import.py
fi

if [[ $SUITE == "all" ]]; then
    tools/run_tests_docker.sh
fi

if [[ $SUITE == "multi_vo" ]]; then
    tools/run_multi_vo_tests_docker.sh
fi
