#!/bin/bash
# Copyright 2018-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

set -eo pipefail

echo "* Running tests with $(python --version) and $(pip --version)"

if [[ $SUITE == "client" ]]; then
    cd /usr/local/src/rucio
    pip install -r etc/pip-requires
    pip install setuptools_scm
    pip install -r etc/pip-requires-test
    python setup_rucio_client.py install
    cp etc/docker/test/extra/rucio_client.cfg etc/rucio.cfg

    # initialize tests
    tools/run_tests_docker.sh -i

elif [[ $SUITE == "syntax" ]]; then
    cd /usr/local/src/rucio
    pip install setuptools_scm google_compute_engine
    cp etc/docker/test/extra/rucio_syntax.cfg etc/rucio.cfg

elif [[ $SUITE == "python3" ]]; then
    cd /usr/local/src/rucio
    pip install -r etc/pip-requires-test
fi
