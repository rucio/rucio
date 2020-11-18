#!/bin/bash
# Copyright 2020 CERN
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

if [ "$SUITE" == "syntax" ]; then
    srchome
    tools/test/check_syntax.sh
    tools/test/sphinx_build.sh

elif [[ "$SUITE" =~ ^client.* ]]; then
    if [ "$SUITE" == "client" ]; then
        tools/run_tests_docker.sh -i
    fi

    srchome
    TEST_FILES="lib/rucio/tests/test_clients.py lib/rucio/tests/test_bin_rucio.py lib/rucio/tests/test_module_import.py"

    if [ "$SUITE" == "client" ]; then
        python -bb -m pytest -vvvrxs $TEST_FILES
    elif [ "$SUITE" == "client_syntax" ]; then
        CLIENT_BIN_FILES="bin/rucio bin/rucio-admin"
        export SYNTAX_PYLINT_ARGS="$(tools/test/ignoretool.py --pylint)"
        export SYNTAX_PYLINT_BIN_ARGS="$CLIENT_BIN_FILES"
        export SYNTAX_FLAKE_ARGS="$(tools/test/ignoretool.py --flake8) $CLIENT_BIN_FILES $TEST_FILES"
        tools/test/check_syntax.sh
    fi

elif [ "$SUITE" == "all" ]; then
    tools/run_tests_docker.sh

elif [ "$SUITE" == "multi_vo" ]; then
    tools/run_multi_vo_tests_docker.sh
fi
