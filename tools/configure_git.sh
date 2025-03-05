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

# Check if the upstream remote already exists
if git remote get-url upstream &>/dev/null; then
    echo "Remote 'upstream' already exists. Skipping addition."
else
    echo "Adding remote 'upstream'..."
    git remote add upstream https://github.com/rucio/rucio.git
fi

# Set up the prepare-commit-msg hook
if [ -f .git/hooks/prepare-commit-msg ]; then
    echo "Git hook 'prepare-commit-msg' already exists. Skipping copy."
else
    echo "Setting up Git hook..."
    cp tools/prepare-commit-msg .git/hooks/prepare-commit-msg
    chmod +x .git/hooks/prepare-commit-msg
    echo "Git hook installed successfully."
fi
