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

set -euo pipefail
IFS=$'\n\t'

RUCIO_DIR="$(dirname "$0")/../"
cd "$RUCIO_DIR"
if [[ ${#@} -eq 0 ]]; then
  # no extra arguments
  echo "Running pytest in tests"
  ARGS=(".")
else
  echo "Running pytest with extra arguments: $@"
  ARGS=($@)
fi

export PYTEST_DISABLE_PLUGIN_AUTOLOAD="True"

RUN_XDIST="${RUN_XDIST:-True}"
if [[ "${RDBMS:-}" == "sqlite" ]]; then
  # no parallel tests on sqlite, because of random "sqlite3.OperationalError: database is locked"
  echo "Disabling parallel testing for sqlite"
  RUN_XDIST="False"
elif [[ "${RDBMS:-}" =~ mysql.* ]]; then
  # no parallel tests on mysql, because of random "pymysql.err.OperationalError:
  # (1213, 'Deadlock found when trying to get lock; try restarting transaction')"
  echo "Disabling parallel testing for mysql"
  RUN_XDIST="False"
elif [[ "${RDBMS:-}" == "oracle" ]]; then
  # no parallel tests on oracle, because of potential database deadlock errors.
  echo "Disabling parallel testing for oracle"
  RUN_XDIST="False"
fi

if [[ "$RUN_XDIST" == "True" ]] && ! python -c 'import xdist' &>/dev/null 2>&1; then
    echo "xdist is not installed, disabling parallel testing"
    RUN_XDIST="False"
fi

XDIST_ARGS=()
if [[ "$RUN_XDIST" == "True" ]]; then
  if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
    # run on 3 processes instead of 2 on GitHub Actions
    PROCESS_COUNT="3"
  else
    PROCESS_COUNT="auto"
  fi
  XDIST_ARGS=("-p" "xdist" "--numprocesses=$PROCESS_COUNT")
  echo "Running pytest with pytest-xdist: " "${XDIST_ARGS[@]}"
fi

exec python -bb -m pytest -r fExX --log-level=DEBUG ${XDIST_ARGS[@]+"${XDIST_ARGS[@]}"} ${ARGS[@]}
