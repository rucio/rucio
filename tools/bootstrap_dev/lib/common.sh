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

: "${SCRIPT_DIR:?}"  # Provided by bootstrap_dev.sh
: "${BOOTSTRAP_ROOT:?}"
: "${BOOTSTRAP_REPO_ROOT:?}"

DEMO_BRANCH="${DEMO_BRANCH:-demo-env}"
UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"

# bootstrap_common::repo_root
# ----------------------------------------------
# Return the repository root determined by bootstrap_dev.sh.
#
function bootstrap_common::repo_root() {
  echo "$BOOTSTRAP_REPO_ROOT"
}

# bootstrap_common::demo_branch
# ----------------------------------------------
# Name of the branch used for temporary checkouts.
#
function bootstrap_common::demo_branch() {
  echo "$DEMO_BRANCH"
}

# bootstrap_common::upstream_remote
# ----------------------------------------------
# Return the expected remote for the upstream Rucio repository.
#
function bootstrap_common::upstream_remote() {
  echo "$UPSTREAM_REMOTE"
}

# bootstrap_common::info <message>
# ----------------------------------------------
# Print an informational message with a consistent prefix.
#
function bootstrap_common::info() {
  echo ">>> $*"
}

# bootstrap_common::warn <message>
# ----------------------------------------------
# Print a warning to STDERR with a shared prefix.
#
function bootstrap_common::warn() {
  echo "WARNING: $*" >&2
}

# bootstrap_common::error <message>
# ----------------------------------------------
# Print an error to STDERR with a shared prefix.
#
function bootstrap_common::error() {
  echo "ERROR: $*" >&2
}

# bootstrap_common::to_lowercase <string...>
# ----------------------------------------------
# Convert the provided argument list to lowercase.
#
function bootstrap_common::to_lowercase() {
  local input="${1-}"
  if (( $# > 1 )); then
    shift
    input="$input $*"
  fi
  printf '%s' "$input" | tr '[:upper:]' '[:lower:]'
}

# bootstrap_common::require_command <binary> [message]
# ----------------------------------------------
# Exit with an error if the command is missing.
#
function bootstrap_common::require_command() {
  local cmd="$1"
  local message="${2:-}"  # Optional custom message
  if ! command -v "$cmd" >/dev/null 2>&1; then
    if [[ -n "$message" ]]; then
      bootstrap_common::error "$message"
    else
      bootstrap_common::error "Required command '$cmd' is not available."
    fi
    exit 1
  fi
}
