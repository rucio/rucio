#!/bin/bash
# Copyright 2021-2022 CERN
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
# - Mayank Sharma <mayank.sharma@cern.ch>, 2020-2021

set -eo pipefail

if [[ -z "POLICY_PACKAGE_INSTALL_CMD" ]]; then 
    # No policy package install cmd specified
    continue
else
    echo "Installing policy package via command: $POLICY_PACKAGE_INSTALL_CMD"
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO sh -c "${POLICY_PACKAGE_INSTALL_CMD}"
fi

if [[ -z "POLICY_PACKAGE_PYTHONPATH" ]]; then
    # No modifications to pythonpath requested
else
    docker $CONTAINER_RUNTIME_ARGS exec $CON_RUCIO sh -c "${POLICY_PACKAGE_INSTALL_CMD}"
