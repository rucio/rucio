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

if [ -z "$SYNTAX_RUFF_ARGS" ]; then
    SYNTAX_RUFF_ARGS="bin/ lib/ tools/*.py"
fi

echo '==============================='
echo 'Running Ruff                   '
echo '==============================='

ruff check --extend-ignore=E501,E722 $SYNTAX_RUFF_ARGS

if [ $? -ne 0 ]; then
    echo "Ruff checks failed"
    exit 1
else
    echo "Ruff checks passed"
fi

if [[ "$SYNTAX_REPORT" && "$SYNTAX_REPORT" == "1" ]]; then
    echo '==============================='
    echo 'Ruff Full Report               '
    echo '==============================='

    ruff check --output-format=full $SYNTAX_RUFF_ARGS
fi