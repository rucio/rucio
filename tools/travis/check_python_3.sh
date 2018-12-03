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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018

echo '==============================='
echo 'Running pylint                 '
echo '==============================='

for filename in $(cat changed_files.txt);
do
    if grep -q "PY3K COMPATIBLE" $filename; then
        echo "Check if file" $filename "is Python3 compatible"
        pylint --py3k -d no-absolute-import -d round-builtin $filename 
        if [ $? -ne 0 ]; then
            echo "PYLINT FAILED"
            cat pylint.out
            exit 1
        fi
    fi
done
echo "PYLINT PASSED"
