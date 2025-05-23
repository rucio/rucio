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

set -e

TMP_FILE_NAME=python_config_documentation_report.txt
python3 tools/generate_configuration_setting.py --count > $TMP_FILE_NAME
DOCSTRING_COUNT=$(cat < $TMP_FILE_NAME)

echo "Configuration Annotation Coverage: $DOCSTRING_COUNT"

rm $TMP_FILE_NAME
