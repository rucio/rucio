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

# NOTE: Keep this file Bash-3 compatible (macOS /bin/bash). Avoid declare -g, mapfile, etc.

declare -a TEST_COMMANDS
declare -a TEST_DESCRIPTIONS
TEST_COMMANDS=()
TEST_DESCRIPTIONS=()

# Track caller selections with conservative defaults.
SELECTED_TEST=""
PYTEST_FILTER=""
REUSE_AUTOTEST_IMAGES=false

# bootstrap_tests::configure <selected_test> <pytest_filter> <reuse_flag>
# ----------------------------------------------
# Store CLI selections for later helpers.
#
function bootstrap_tests::configure() {
  local selected_test="${1:-}"
  local pytest_filter="${2:-}"
  local reuse_images="${3:-false}"

  SELECTED_TEST="$selected_test"
  PYTEST_FILTER="$pytest_filter"
  if [[ "$reuse_images" == "true" ]]; then
    REUSE_AUTOTEST_IMAGES=true
  else
    REUSE_AUTOTEST_IMAGES=false
  fi
}

# bootstrap_tests::gather
# ----------------------------------------------
# Collect the available test commands and descriptions.
#
function bootstrap_tests::gather() {
  TEST_COMMANDS=()
  TEST_DESCRIPTIONS=()

  if [[ -z "${RUCIO_REPO_ROOT:-}" ]]; then
    RUCIO_REPO_ROOT="$(bootstrap_common::repo_root)"
  fi

  local compose_cmd
  compose_cmd="$(bootstrap_docker::compose_cmd_string)"

  # 1) Default local test suite
  TEST_COMMANDS+=("$compose_cmd --project-name dev exec rucio tools/run_tests.sh")
  TEST_DESCRIPTIONS+=("run local test suite (tools/run_tests.sh)")

  # 2) Matrix entries from YAML via Python helper
  local matrix_yml
  matrix_yml="$RUCIO_REPO_ROOT/etc/docker/test/matrix.yml"

  local parser_path=""
  if [[ -f "$RUCIO_REPO_ROOT/tools/test/matrix_parser.py" ]]; then
    parser_path="$RUCIO_REPO_ROOT/tools/test/matrix_parser.py"
  elif [[ -f "$RUCIO_REPO_ROOT/tools/matrix_parser.py" ]]; then
    parser_path="$RUCIO_REPO_ROOT/tools/matrix_parser.py"
  elif [[ -f "$RUCIO_REPO_ROOT/matrix_parser.py" ]]; then
    parser_path="$RUCIO_REPO_ROOT/matrix_parser.py"
  fi

  if [[ -n "$parser_path" && -f "$matrix_yml" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
      bootstrap_common::warn "python3 not found; skipping autotest matrix discovery"
      return
    fi
    if ! command -v jq >/dev/null 2>&1; then
      bootstrap_common::warn "jq not found; skipping autotest matrix discovery"
      return
    fi
    local matrix_json
    if matrix_json=$(python3 "$parser_path" < "$matrix_yml" 2>/dev/null); then
      local matrix_cases=()
      while IFS= read -r line; do
        matrix_cases+=("$line")
      done < <(echo "$matrix_json" | jq -c '(. // []) | .[]?')

      if ((${#matrix_cases[@]} > 0)); then
        local case dist py suite db services desc cmd
        for case in "${matrix_cases[@]}"; do
          dist=$(echo "$case"    | jq -r '.DIST')
          py=$(echo   "$case"    | jq -r '.PYTHON')
          suite=$(echo "$case"   | jq -r '.SUITE')
          db=$(echo    "$case"   | jq -r '.RDBMS // empty')
          services=$(echo "$case"| jq -r '[.SERVICES] | flatten | join(",")')

          desc="autotest: ${suite} (dist ${dist}, py ${py}"
          [[ -n "$db" ]] && desc+=", db ${db}"
          [[ -n "$services" ]] && desc+=", services ${services}"
          desc+=")"

          cmd="$RUCIO_REPO_ROOT/tools/run_autotests.sh --build -d ${dist} --py ${py} --suite ${suite}"
          if [[ "${REUSE_AUTOTEST_IMAGES:-false}" == true ]]; then
            cmd="RUCIO_AUTOTEST_REUSE_IMAGES=1 $cmd"
          fi
          [[ -n "$db" ]] && cmd+=" --db ${db}"

          TEST_COMMANDS+=("$cmd")
          TEST_DESCRIPTIONS+=("$desc")
        done
      else
        bootstrap_common::warn "Autotest matrix is empty"
      fi
    else
      bootstrap_common::warn "Unable to parse autotest matrix with $parser_path"
    fi
  else
    if [[ ! -f "$matrix_yml" ]]; then
      bootstrap_common::warn "Autotest matrix not found: $matrix_yml"
    else
      bootstrap_common::warn "matrix_parser.py not found"
    fi
  fi
}

# bootstrap_tests::print_available
# ----------------------------------------------
# Print a numbered list of discovered tests.
#
function bootstrap_tests::print_available() {
  echo
  echo "Available tests:"
  local idx=1
  local desc
  for desc in "${TEST_DESCRIPTIONS[@]}"; do
    printf "  %2d) %s\n" "$idx" "$desc"
    idx=$((idx+1))
  done
  echo "Run with '$0 --test <number>' or '$0 -t <number>' to execute one automatically."
}

# bootstrap_tests::run_selected
# ----------------------------------------------
# Run the requested test, applying optional filters and reuse flags.
#
function bootstrap_tests::run_selected() {
  if [[ -z "${SELECTED_TEST:-}" ]]; then
    return
  fi

  if ! [[ "${SELECTED_TEST:-}" =~ ^[0-9]+$ ]] || (( SELECTED_TEST < 1 || SELECTED_TEST > ${#TEST_COMMANDS[@]} )); then
    bootstrap_common::error "Invalid test number '${SELECTED_TEST:-}'"
    return 1
  fi

  cd "$RUCIO_REPO_ROOT"
  bootstrap_common::info "Running test #${SELECTED_TEST:-}: ${TEST_DESCRIPTIONS[SELECTED_TEST-1]}"
  local cmd filter_escaped
  cmd="${TEST_COMMANDS[SELECTED_TEST-1]}"
  if [[ -n "${PYTEST_FILTER:-}" ]]; then
    filter_escaped=$(printf '%q' "${PYTEST_FILTER:-}")
    if [[ "${SELECTED_TEST:-}" == "1" ]]; then
      cmd="$(bootstrap_docker::compose_cmd_string) --project-name dev exec -e TESTS=$filter_escaped rucio tools/run_tests.sh -p"
    else
      cmd+=" --filter $filter_escaped"
    fi
  fi
  eval "$cmd"
}
