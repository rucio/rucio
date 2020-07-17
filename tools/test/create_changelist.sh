#!/bin/bash
# Copyright 2020 CERN for the benefit of the ATLAS collaboration.
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

set -eo pipefail
IFS=$'\n\t'

if [[ -z "$BASE_BRANCH" ]]; then
    echo "BASE_BRANCH environment variable needs to be set"
    exit 1
fi

appendChanges() {
    $* | grep -E 'bin/|\.py$' | grep -v '^A' | grep -v 'conf.py' | cut -f 2 | paste -sd " " - >> changed_files.txt.new || true
}

# change directory to main repository directory
cd `dirname $0`/../..

rm -f changed_files.txt
touch changed_files.txt.new
appendChanges git diff --name-status HEAD $(git merge-base HEAD $BASE_BRANCH)

if [[ "$INCLUDE_STAGED" == "true" ]]; then
    appendChanges git diff --name-status --staged
fi

if [[ "$INCLUDE_UNSTAGED" == "true" ]]; then
    appendChanges git diff --name-status
fi

# merge newlines, trim outside spaces
tr '\n' ' ' < changed_files.txt.new | xargs echo -n > changed_files.txt
rm changed_files.txt.new
