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

# Lightweight configuration helpers for bootstrap_dev.sh and its CLI parser.

# bootstrap_config::init <config_var> <profiles_var>
# ----------------------------------------------
# Set up default values for the script configuration.
#
function bootstrap_config::init() {
  local config_name="$1"
  local profiles_name="$2"

  bootstrap_config::set "$config_name" release ""
  bootstrap_config::set "$config_name" use_master "false"
  bootstrap_config::set "$config_name" use_latest "false"
  bootstrap_config::set "$config_name" any_profile_arg "false"
  bootstrap_config::set "$config_name" expose_ports "false"
  bootstrap_config::set "$config_name" selected_test ""
  bootstrap_config::set "$config_name" pytest_filter ""
  bootstrap_config::set "$config_name" reuse_autotest_images "false"
  bootstrap_config::set "$config_name" skip_pull_for_profiles "false"
  bootstrap_config::set "$config_name" assume_yes "false"
  bootstrap_config::set "$config_name" profile_count "0"
  bootstrap_config::set "$config_name" dry_run_flag "0"

  bootstrap_config::set_profiles "$config_name" "$profiles_name"
}

# bootstrap_config::set <config_var> <key> <value>
# ----------------------------------------------
# Store a single configuration value.
#
function bootstrap_config::set() {
  local config_name="$1"
  local key="$2"
  local value="$3"
  printf -v "${config_name}_${key}" '%s' "$value"
}

# bootstrap_config::get <config_var> <key>
# ----------------------------------------------
# Fetch a stored configuration value.
#
function bootstrap_config::get() {
  local config_name="$1"
  local key="$2"
  local var_name="${config_name}_${key}"
  local value=""
  eval "value=\${$var_name-}"
  printf '%s' "$value"
}

# bootstrap_config::set_profiles <config_var> <profiles_var> [values...]
# ----------------------------------------------
# Replace the stored profile list and keep the count in sync.
#
function bootstrap_config::set_profiles() {
  local config_name="$1"
  local profiles_name="$2"
  shift 2

  eval "$profiles_name=()"
  if [[ $# -eq 0 ]]; then
    bootstrap_config::set "$config_name" profile_count "0"
    return
  fi

  local count=0
  local value
  for value in "$@"; do
    printf -v "${profiles_name}[$count]" '%s' "$value"
    count=$((count + 1))
  done

  bootstrap_config::set "$config_name" profile_count "$count"
}

# bootstrap_config::copy_profiles <source_var> <target_var>
# ----------------------------------------------
# Copy a stored profile list into another array variable.
#
function bootstrap_config::copy_profiles() {
  local profiles_name="$1"
  local target_name="$2"

  eval "$target_name=()"

  local length
  length="$(bootstrap_config::profile_count "$profiles_name")"
  if [[ -z "$length" ]]; then
    length=0
  fi

  local idx
  local value
  for ((idx = 0; idx < length; idx++)); do
    eval "value=\${${profiles_name}[$idx]}"
    printf -v "${target_name}[$idx]" '%s' "$value"
  done
}

# bootstrap_config::profile_count <profiles_var>
# ----------------------------------------------
# Return the number of stored profiles.
#
function bootstrap_config::profile_count() {
  local profiles_name="$1"
  local length
  eval "length=\${#${profiles_name}[@]}"
  if [[ -z "$length" ]]; then
    length=0
  fi
  echo "$length"
}
