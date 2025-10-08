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

# shellcheck disable=SC2034
BOOTSTRAP_DEV_TESTS_LOADED=1

# bootstrap_dev_tests::run <config_var> <profiles_var>
# ----------------------------------------------
# Handle the optional test workflow after bootstrapping.
#
function bootstrap_dev_tests::run() {
  local cfg_name="$1"
  local profiles_name="$2"

  local project_name="$(bootstrap_config::get "$cfg_name" project_name)"
  if [[ -z "$project_name" ]]; then
    project_name="dev"
  fi
  local use_master="$(bootstrap_config::get "$cfg_name" use_master)"
  local any_profile_arg="$(bootstrap_config::get "$cfg_name" any_profile_arg)"
  local selected_test="$(bootstrap_config::get "$cfg_name" selected_test)"
  local pytest_filter="$(bootstrap_config::get "$cfg_name" pytest_filter)"
  local reuse_autotest_images="$(bootstrap_config::get "$cfg_name" reuse_autotest_images)"
  local expose_ports="$(bootstrap_config::get "$cfg_name" expose_ports)"
  local rucio_tag="$(bootstrap_config::get "$cfg_name" rucio_tag)"
  local rucio_dev_prefix="$(bootstrap_config::get "$cfg_name" rucio_dev_prefix)"
  local repo_root="$(bootstrap_config::get "$cfg_name" repo_root)"
  local dry_run="$(bootstrap_config::get "$cfg_name" dry_run_flag)"

  # Normalise the helper library so the gathered test catalogue and execution
  # logic use the same view of the CLI selections.
  bootstrap_tests::configure "$selected_test" "$pytest_filter" "$reuse_autotest_images"
  bootstrap_tests::gather

  if [[ "$dry_run" != "0" ]]; then
    return
  fi

  if [[ "$use_master" == "true" && "$any_profile_arg" == "true" ]]; then
    echo
    echo ">>> Since '--master' is selected, let's ensure the container's environment has the most"
    echo ">>> recent dev dependencies (we'll just upgrade packages; old ones won't be removed)."
    echo ">>> Requirements considered: /rucio_source/requirements/requirements.dev.txt"

    bootstrap_docker::compose --project-name "$project_name" exec rucio python3 -m pip install --no-cache-dir --upgrade pip
    bootstrap_docker::compose --project-name "$project_name" exec rucio \
      python3 -m pip install --no-cache-dir --upgrade -r /rucio_source/requirements/requirements.dev.txt

    echo ">>> Done installing/upgrading dev requirements for master!"
  fi

  if [[ -z "$selected_test" ]]; then
    return
  fi

  echo ">>> WARNING: Running tests will remove the 'dev_vol-ruciodb-data' volume."
  bootstrap_docker::stop_dev_containers "$project_name"
  bootstrap_docker::remove_rucio_db_volume
  if [[ "$selected_test" != "1" ]]; then
    trap bootstrap_docker::remove_autotest_volumes EXIT
  fi

  export RUCIO_TAG="$rucio_tag"
  export RUCIO_DEV_PREFIX="$rucio_dev_prefix"

  if [[ "$selected_test" == "1" ]]; then
    echo ">>> Ensuring 'rucio' service is running for test #1..."

    local -a compose_files=(--file docker-compose.yml)
    if [[ "$expose_ports" == "true" ]]; then
      compose_files+=(--file docker-compose.ports.yml)
    fi

    (
      cd "$repo_root/etc/docker/dev" && \
      bootstrap_docker::compose --project-name "$project_name" "${compose_files[@]}" up -d
    )
  fi

  bootstrap_tests::run_selected
}
