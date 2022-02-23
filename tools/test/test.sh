#!/bin/bash
# Copyright 2020-2021 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

set -eo pipefail

function srchome() {
    export RUCIO_HOME=/usr/local/src/rucio
    cd $RUCIO_HOME
}

if [ "$SUITE" == "syntax" ]; then
    srchome
    tools/test/check_syntax.sh

elif [ "$SUITE" == "docs" ]; then
    srchome
    export RUCIO_CLIENT_API_OUTPUT="rucio_client_api.md"
    export RUCIO_REST_API_OUTPUT="rucio_rest_api.md"
    tools/generate_doc.py
    test -s $RUCIO_CLIENT_API_OUTPUT
    test -s $RUCIO_REST_API_OUTPUT

    export REST_API_DOC_FILENAME="api_doc.yaml"
    tools/generate_rest_api_doc.py > $REST_API_DOC_FILENAME
    tools/test/check_rest_api_documentation.sh $REST_API_DOC_FILENAME


elif [[ "$SUITE" =~ ^client.* ]]; then
    if [ "$SUITE" == "client" ]; then
        tools/run_tests_docker.sh -i
    fi

    srchome
    if [ "$SUITE" == "client" ]; then
        tools/pytest.sh -v --tb=short test_clients.py test_bin_rucio.py test_module_import.py
    elif [ "$SUITE" == "client_syntax" ]; then
        CLIENT_BIN_FILES="bin/rucio bin/rucio-admin"
        export SYNTAX_PYLINT_ARGS="$(tools/test/ignoretool.py --pylint)"
        export SYNTAX_PYLINT_BIN_ARGS="$CLIENT_BIN_FILES"
        export SYNTAX_FLAKE_ARGS="$(tools/test/ignoretool.py --flake8) $CLIENT_BIN_FILES lib/rucio/tests/test_clients.py lib/rucio/tests/test_bin_rucio.py lib/rucio/tests/test_module_import.py"
        tools/test/check_syntax.sh
    fi

elif [ "$SUITE" == "all" ]; then
    tools/run_tests_docker.sh

elif [ "$SUITE" == "multi_vo" ]; then
    tools/run_multi_vo_tests_docker.sh
fi
