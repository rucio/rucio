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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

echo '==============================='
echo 'Running flake8                 '
echo '==============================='

flake8 --ignore=E501,E722,W503 --exclude="*.cfg" bin/* lib/ tools/*.py

if [ $? -ne 0 ]; then
    exit 1
fi


echo '==============================='
echo 'Running pylint                 '
echo '==============================='

pylint --rcfile=pylintrc --errors-only --ignore=lib/rucio/tests lib/rucio/ bin/*

if [ $? -ne 0 ]; then
    echo "PYLINT FAILED"
    exit 1
else
    echo "PYLINT PASSED"
fi


if [ -n "$SYNTAX_REPORT" -a "$SYNTAX_REPORT" -eq "1" ]; then
    echo '==============================='
    echo 'Pylint report                  '
    echo '==============================='

    pylint --rcfile=pylintrc --reports y --exit-zero lib/rucio/ bin/*
fi


echo '==============================='
echo 'Running Sphinx                 '
echo '==============================='

RUCIO_HOME=/usr/local/src/rucio sphinx-build -avT doc/source/ doc/build/html

if [ $? -ne 0 ]; then
    exit 1
fi
