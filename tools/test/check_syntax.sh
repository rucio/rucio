#!/bin/bash
# Copyright 2018-2020 CERN
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

if [ -z "$SYNTAX_FLAKE_ARGS" ]; then
    SYNTAX_FLAKE_ARGS="--exclude=\"*.cfg\" bin/* lib/ tools/*.py"
fi

if [ -z "$SYNTAX_PYLINT_ARGS" ]; then
    SYNTAX_PYLINT_ARGS="--ignore=lib/rucio/tests,lib/rucio/tests/mock lib/rucio/"
fi

if [ -z "$SYNTAX_PYLINT_BIN_ARGS" ]; then
    SYNTAX_PYLINT_BIN_ARGS="bin/*"
fi


echo '==============================='
echo 'Running flake8                 '
echo '==============================='

flake8 --ignore=E501,E722,W503 $SYNTAX_FLAKE_ARGS

if [ $? -ne 0 ]; then
    exit 1
fi


echo '==============================='
echo 'Running pylint                 '
echo '==============================='

pylint --rcfile=pylintrc --errors-only $SYNTAX_PYLINT_ARGS

if [ $? -ne 0 ]; then
    echo "PYLINT on $SYNTAX_PYLINT_ARGS FAILED"
    exit 1
else
    echo "PYLINT on $SYNTAX_PYLINT_ARGS PASSED"
fi

# disable no-name-in-module since bin/rucio clashes with lib/rucio
PYTHONPATH=lib pylint --rcfile=pylintrc --errors-only --disable no-name-in-module $SYNTAX_PYLINT_BIN_ARGS

if [ $? -ne 0 ]; then
    echo "PYLINT on $SYNTAX_PYLINT_BIN_ARGS FAILED"
    exit 1
else
    echo "PYLINT on $SYNTAX_PYLINT_BIN_ARGS PASSED"
fi


if [[ "$SYNTAX_REPORT" && "$SYNTAX_REPORT" == "1" ]]; then
    echo '==============================='
    echo 'Pylint report                  '
    echo '==============================='

    pylint --rcfile=pylintrc --reports y --exit-zero $SYNTAX_PYLINT_ARGS
fi
