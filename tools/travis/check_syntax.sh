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

echo '==============================='
echo 'Running flake8                 '
echo '==============================='

flake8 --ignore=E501,E722 --exclude="*.cfg" bin/* lib/ tools/*.py tools/probes/common/*

if [ $? -ne 0 ]; then
    exit 1
fi

echo '==============================='
echo 'Running pylint                 '
echo '==============================='

pylint --rcfile=pylintrc `cat changed_files.txt` > pylint.out

if [ $(($? & 3)) -ne 0 ]; then
    echo "PYLINT FAILED"
    cat pylint.out
    exit 1
else
    echo "PYLINT PASSED"
    tail -n 3 pylint.out
fi

# 2to3 --no-diffs lib/rucio  2>&1 |grep 'RefactoringTool: Refactored'|wc

echo '==============================='
echo 'Running Sphinx                 '
echo '==============================='

RUCIO_HOME=/home/travis/build/rucio/rucio sphinx-build -avT doc/source/ doc/build/html

if [ $? -ne 0 ]; then
    exit 1
fi
