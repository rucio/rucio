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

# Script to count the number of missing python type annotations in the project.

set -e


source $(dirname "$0")/count_missing_type_annotations_utils.sh


TMP_FILE_NAME=python_type_annotations_report.txt
create_missing_python_type_annotations_report $TMP_FILE_NAME
NUMBER_MISSING_TYPE_ANNOTATIONS=$(wc -l < $TMP_FILE_NAME)

echo "Number of missing annotations: $NUMBER_MISSING_TYPE_ANNOTATIONS"

rm $TMP_FILE_NAME
