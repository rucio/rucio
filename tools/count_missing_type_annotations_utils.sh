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

# Script with all tools to count the missing python type annotations in the
# project. Installs all necessary python packages temporarily if needed. To use
# it run: `source count_missing_annotations_utils.sh`.

set -e


ensure_install() {
    # Checks if a python package is installed via pip. It installs the package,
    # and removes it after the script run automatically.
    #
    # All debug output is redirected to the stderr stream, to not interfere with
    # other output.
    #
    # :param $1: The name of the pip package.
    if [[ ! $(pip list) =~ $1 ]]
    then
        >&2 echo "Pip package $1 not installed! Installing it now..."
        >&2 pip install --user $1

        >&2 echo "The package will automatically be uninstalled."
        trap ">&2 pip uninstall --yes $1" EXIT
    fi
}


create_missing_python_type_annotations_report() {
    # Created a report of the missing python annotations.
    #
    # This does not include tests, tools, database and bin files.
    # :param $1: The name of the output file.

    flake8 . \
        --ignore=ANN101 \
        --exclude tools,rucio-core/src/rucio/core/db,rucio-client/src/rucio/client,rucio-core/src/rucio/core/common,rucio-core/src/rucio/core/rse,rucio-cli/src/rucio/cli \
        --output-file $1 \
        --select ANN || true
}


ensure_install "flake8"
ensure_install "flake8-annotations"
