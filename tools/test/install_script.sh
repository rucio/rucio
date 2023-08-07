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

if [ "$SUITE" == "client" -o "$SUITE" == "client_syntax" ]; then
    cd /usr/local/src/rucio
    cp etc/docker/test/extra/rucio_client.cfg etc/rucio.cfg

elif [ "$SUITE" == "syntax" -o "$SUITE" == "docs" ]; then
    cd /usr/local/src/rucio
    cp etc/docker/test/extra/rucio_syntax.cfg etc/rucio.cfg

elif [ "$SUITE" == "votest" ]; then
    RUCIO_HOME=/opt/rucio
    VOTEST_HELPER=$RUCIO_HOME/tools/test/votest_helper.py
    VOTEST_CONFIG_FILE=$RUCIO_HOME/etc/docker/test/matrix_policy_package_tests.yml
    echo "VOTEST: Overriding policy section in rucio.cfg"
    python $VOTEST_HELPER --vo $POLICY --vo-config --file $VOTEST_CONFIG_FILE
    echo "VOTEST: Restarting httpd to load config"
    httpd -k restart
fi
