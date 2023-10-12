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

set -eo pipefail

echo "* Using $(command -v python) $(python --version 2>&1) and $(command -v pip) $(pip --version 2>&1)"

SOURCE_PATH=/usr/local/src/rucio
CFG_PATH=/usr/local/src/rucio/etc/docker/test/extra/
if [ -z "$RUCIO_HOME" ]; then
    RUCIO_HOME=/opt/rucio
fi

function srchome() {
    export RUCIO_HOME="$SOURCE_PATH"
    cd $SOURCE_PATH
}

function wait_for_database() {
    echo 'Waiting for database to be ready'
    if ! python3 -c "from rucio.db.sqla.session import wait_for_database; wait_for_database()"
    then
        echo 'Cannot access database'
        exit 1
    fi
}

if [ "$SUITE" == "client" ]; then
    tools/run_tests.sh -i

    cp "$SOURCE_PATH"/etc/docker/test/extra/rucio_client.cfg "$SOURCE_PATH"/etc/rucio.cfg
    srchome
    tools/pytest.sh -v --tb=short tests/test_clients.py tests/test_bin_rucio.py tests/test_module_import.py

elif [ "$SUITE" == "client_syntax" ]; then
    srchome
    CLIENT_BIN_FILES="bin/rucio bin/rucio-admin"
    SYNTAX_PYLINT_ARGS="$(tools/test/ignoretool.py --pylint)"
    SYNTAX_FLAKE_ARGS="$(tools/test/ignoretool.py --flake8) $CLIENT_BIN_FILES tests/test_clients.py tests/test_bin_rucio.py tests/test_module_import.py"
    export SYNTAX_PYLINT_ARGS
    export SYNTAX_PYLINT_BIN_ARGS="$CLIENT_BIN_FILES"
    export SYNTAX_FLAKE_ARGS
    tools/test/check_syntax.sh

elif [ "$SUITE" == "syntax" ]; then
    srchome
    tools/test/check_syntax.sh

elif [ "$SUITE" == "docs" ]; then
    python3 $SOURCE_PATH/tools/merge_rucio_configs.py --use-env \
        -s "$CFG_PATH"/rucio_autotests_common.cfg "$CFG_PATH"/rucio_sqlite.cfg \
        -d "$SOURCE_PATH"/etc/rucio.cfg
    srchome
    export RUCIO_CLIENT_API_OUTPUT="rucio_client_api.md"
    export RUCIO_REST_API_OUTPUT="rucio_rest_api.md"
    tools/generate_doc.py
    test -s $RUCIO_CLIENT_API_OUTPUT
    test -s $RUCIO_REST_API_OUTPUT

    export REST_API_DOC_FILENAME="api_doc.yaml"
    tools/generate_rest_api_doc.py > $REST_API_DOC_FILENAME
    tools/test/check_rest_api_documentation.sh $REST_API_DOC_FILENAME

elif [ "$SUITE" == "votest" ]; then
    VOTEST_HELPER=$RUCIO_HOME/tools/test/votest_helper.py
    VOTEST_CONFIG_FILE=$RUCIO_HOME/etc/docker/test/matrix_policy_package_tests.yml
    echo "VOTEST: Overriding policy section in rucio.cfg"
    python $VOTEST_HELPER --vo "$POLICY" --vo-config --file $VOTEST_CONFIG_FILE
    echo "VOTEST: Restarting httpd to load config"
    httpd -k restart

    TESTS=$(python $VOTEST_HELPER --vo "$POLICY" --tests --file $VOTEST_CONFIG_FILE)
    export TESTS
    tools/run_tests.sh -p

elif [ "$SUITE" == "multi_vo" ]; then
    VO1_HOME="$RUCIO_HOME"
    mkdir -p "$VO1_HOME/etc"
    python3 $SOURCE_PATH/tools/merge_rucio_configs.py --use-env \
        -s "$CFG_PATH"/rucio_autotests_common.cfg "$CFG_PATH"/rucio_multi_vo_tst_postgres14.cfg \
        -d "$VO1_HOME"/etc/rucio.cfg
    httpd -k restart

    VO2_HOME="$RUCIO_HOME/../ts2"
    mkdir -p "$VO2_HOME/etc"
    python3 $SOURCE_PATH/tools/merge_rucio_configs.py --use-env \
        -s "$CFG_PATH"/rucio_autotests_common.cfg "$CFG_PATH"/rucio_multi_vo_ts2_postgres14.cfg \
        -d "$VO2_HOME"/etc/rucio.cfg

    wait_for_database

    tools/run_multi_vo_tests_docker.sh

elif [ "$SUITE" == "remote_dbs" ] || [ "$SUITE" == "sqlite" ]; then
    wait_for_database

    if [ -n "$TESTS" ]; then
        tools/run_tests.sh -p
    else
        tools/run_tests.sh
    fi
fi
