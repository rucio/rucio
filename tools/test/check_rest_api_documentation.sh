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

set -eo pipefail


command_exists() {
    # check if command exists and fail otherwise
    command -v "$1" >/dev/null 2>&1 || {
	echo "$1 is required, but it's not installed. Abort."
	exit 1
    }
}


if [ "$#" -ne 1 ]; then
    echo "Usage: check_rest_api_documentation.sh FILE"
    exit 1
fi

command_exists "node"
command_exists "npx"

npx @redocly/openapi-cli lint $1
