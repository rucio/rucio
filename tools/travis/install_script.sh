#!/bin/bash
# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Thomas Beermann, <thomas.beermann@cern.ch> 2019>
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019

if [[ $SUITE == "client" ]]; then

 if [[ "$TRAVIS_PYTHON_VERSION" !=  "2.6" ]]; then pip install -r tools/pip-requires; fi
    pip install setuptools_scm
    pip install -r tools/pip-requires-test
    python setup_rucio_client.py install
    cp etc/docker/travis/rucio_client.cfg etc/rucio.cfg
    cp etc/docker/travis/Dockerfile Dockerfile
    docker build -t rucio/rucio .

elif [[ $SUITE == "syntax" ]]; then
    pip install setuptools_scm
    pip install google_compute_engine
    pip install .[dev]
    cp etc/docker/travis/rucio_syntax.cfg etc/rucio.cfg
    cp etc/docker/travis/google-cloud-storage-test.json etc/google-cloud-storage-test.json

elif [[ $SUITE == "all" ]]; then
    echo $TRAVIS_PYTHON_VERSION
    cp etc/docker/travis/Dockerfile Dockerfile
    docker build -t rucio/rucio --build-arg python=$TRAVIS_PYTHON_VERSION .
    if [[ $RDBMS == "oracle" ]]; then
        git clone https://github.com/wnameless/docker-oracle-xe-11g.git
        cd docker-oracle-xe-11g/
        docker build -t rucio/oraclexe .
        cd ..
    fi

elif [[ $SUITE == 'python3' ]]; then 
    pip install -r tools/pip-requires-test

fi
