#!/bin/bash
# Copyright 2018-2019 CERN for the benefit of the ATLAS collaboration.
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

# Force compile against OpenSSL, otherwise Travis will try to use GnuTLS
# which is not installed by default.
export PYCURL_SSL_LIBRARY=openssl

if [[ $SUITE == "client" ]]; then

    if [[ "$TRAVIS_PYTHON_VERSION" !=  "2.6" ]]; then
	pip install -r etc/pip-requires;
    fi
    sudo apt-get update
    sudo apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
    pip install setuptools_scm
    pip install -r etc/pip-requires-test
    pip install .[saml]
    python setup_rucio_client.py install
    cp etc/docker/travis/rucio_client.cfg etc/rucio.cfg
    cp etc/docker/travis/Dockerfile Dockerfile
    docker build -t rucio/rucio .

elif [[ $SUITE == "syntax" ]]; then
    sudo apt-get update
    sudo apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
    pip install setuptools_scm
    pip install google_compute_engine
    pip install .[dev,saml]
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
    sudo apt-get update
    sudo apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
    pip install -r etc/pip-requires-test
    pip install .[saml]
fi
