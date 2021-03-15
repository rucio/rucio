#!/usr/bin/env bash
# Copyright 2021 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

set -euo pipefail
IFS=$'\n\t'

RUCIO_LIB="$(dirname "$0")/../lib"
cd "$RUCIO_LIB/rucio/tests"
if [ ${#@} -eq 0 ]; then
  # no extra arguments
  echo "Running pytest in lib/rucio/tests"
  ARGS=(".")
else
  echo "Running pytest with extra arguments: $@"
  ARGS=($@)
fi
export PYTHONPATH="$RUCIO_LIB"

NO_XDIST="${NO_XDIST:-False}"
if [ "${RDBMS:-}" == "sqlite" ]; then
  # no parallel tests on sqlite, because of random "sqlite3.OperationalError: database is locked"
  NO_XDIST="True"
fi

if [ "$NO_XDIST" == "False" ]; then
  NO_XDIST="$(python -c 'import xdist; print(False)' ||:)"
fi

if [ "$NO_XDIST" == "False" ]; then
  # do not run xdist below Python 3.6
  NO_XDIST="$(python -c 'import sys; print(sys.version_info < (3, 6))' ||:)"
fi

XDIST_ARGS=("")
if [ "$NO_XDIST" == "False" ]; then
  if [ "${GITHUB_ACTIONS:-false}" == "true" ]; then
    # run on 4 processes instead of 2 on GitHub Actions
    PROCESS_COUNT="4"
  else
    PROCESS_COUNT="auto"
  fi
  XDIST_ARGS=("-p" "xdist" "-p" "ruciopytest.plugin" "--dist=rucio" "--numprocesses=$PROCESS_COUNT")
  echo "Running pytest with pytest-xdist: ${XDIST_ARGS[@]}"
fi

exec python -bb -m pytest -r fExX ${XDIST_ARGS[@]} ${ARGS[@]}
