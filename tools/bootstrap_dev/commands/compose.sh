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
BOOTSTRAP_DEV_COMPOSE_LOADED=1

# bootstrap_dev_compose::run <config_var> <profiles_var>
# ----------------------------------------------
# Start the requested Docker Compose services using the parsed options.
#
function bootstrap_dev_compose::run() {
  local cfg_name="$1"
  local profiles_name="$2"

  local repo_root="$(bootstrap_config::get "$cfg_name" repo_root)"
  local project_name="$(bootstrap_config::get "$cfg_name" project_name)"
  if [[ -z "$project_name" ]]; then
    project_name="dev"
  fi
  local profile_count="$(bootstrap_config::get "$cfg_name" profile_count)"
  if [[ -z "$profile_count" ]]; then
    profile_count="$(bootstrap_config::profile_count "$profiles_name")"
  fi
  local expose_ports="$(bootstrap_config::get "$cfg_name" expose_ports)"
  local rucio_tag="$(bootstrap_config::get "$cfg_name" rucio_tag)"
  local rucio_dev_prefix="$(bootstrap_config::get "$cfg_name" rucio_dev_prefix)"
  local skip_pull_for_profiles="$(bootstrap_config::get "$cfg_name" skip_pull_for_profiles)"
  local dry_run="$(bootstrap_config::get "$cfg_name" dry_run_flag)"

  local -a profiles=()
  bootstrap_config::copy_profiles "$profiles_name" profiles

  local compose_cmd
  compose_cmd="$(bootstrap_docker::compose_cmd_string)"
  if [[ -z "$compose_cmd" ]]; then
    echo "ERROR: No docker compose command detected."
    exit 1
  fi

  echo ">>> Using Docker images with RUCIO_TAG=\"$rucio_tag\" and RUCIO_DEV_PREFIX=\"$rucio_dev_prefix\""

  export RUCIO_TAG="$rucio_tag"
  export RUCIO_DEV_PREFIX="$rucio_dev_prefix"

  if (( profile_count > 0 )); then
    export DEV_PROFILES=$(IFS=,; echo "${profiles[*]}")
  else
    export DEV_PROFILES=""
  fi

  pushd "$repo_root/etc/docker/dev" >/dev/null

  local -a profile_args=()
  if (( profile_count > 0 )); then
    for prof in "${profiles[@]}"; do
      profile_args+=( --profile "$prof" )
    done
  fi

  if [[ "$dry_run" != "0" ]]; then
    echo ">>> [dry-run] Would stop previous containers for project '$project_name'."
  else
    bootstrap_docker::stop_dev_containers "$project_name"
  fi

  local -a compose_files=(--file docker-compose.yml)
  if [[ "$expose_ports" == "true" ]]; then
    compose_files+=(--file docker-compose.ports.yml)
  fi

  local -a up_extra_args=()
  if [[ "$skip_pull_for_profiles" == "true" ]] && bootstrap_docker::is_compose_v2; then
    up_extra_args+=(--pull never)
  fi

  local up_extra_pretty=""
  if (( ${#up_extra_args[@]} > 0 )); then
    up_extra_pretty=" ${up_extra_args[*]}"
  fi

  if (( profile_count == 0 )); then
    echo ">>> Starting only unprofiled/base containers (no named profiles)."
    if [[ "$skip_pull_for_profiles" != "true" ]]; then
      if [[ "$dry_run" != "0" ]]; then
        echo ">>> [dry-run] Would execute: $compose_cmd ${compose_files[*]} pull"
      else
        bootstrap_docker::compose "${compose_files[@]}" pull || true
      fi
    else
      echo ">>> Cache-use enabled: skipping 'docker compose pull' (using locally cached images)."
    fi
    if [[ "$dry_run" != "0" ]]; then
      echo ">>> [dry-run] Would execute: $compose_cmd --project-name $project_name ${compose_files[*]} up -d$up_extra_pretty"
    else
      local -a up_cmd=(--project-name "$project_name" "${compose_files[@]}" up -d)
      if (( ${#up_extra_args[@]} > 0 )); then
        up_cmd+=("${up_extra_args[@]}")
      fi
      bootstrap_docker::compose "${up_cmd[@]}"
    fi
  else
    echo ">>> Starting unprofiled/base + named profiles: ${profiles[*]}"
    if [[ "$skip_pull_for_profiles" != "true" ]]; then
      if [[ "$dry_run" != "0" ]]; then
        echo ">>> [dry-run] Would execute: $compose_cmd ${compose_files[*]} ${profile_args[*]} pull"
      else
        bootstrap_docker::compose "${compose_files[@]}" "${profile_args[@]}" pull || true
      fi
    else
      echo ">>> Cache-use enabled: skipping 'docker compose pull' (using locally cached images)."
    fi

    if [[ "$dry_run" != "0" ]]; then
      echo ">>> [dry-run] Would execute: $compose_cmd --project-name $project_name ${compose_files[*]} ${profile_args[*]} up -d$up_extra_pretty"
    else
      local -a up_cmd=(--project-name "$project_name" "${compose_files[@]}" "${profile_args[@]}" up -d)
      if (( ${#up_extra_args[@]} > 0 )); then
        up_cmd+=("${up_extra_args[@]}")
      fi
      bootstrap_docker::compose "${up_cmd[@]}"
    fi
  fi

  popd >/dev/null
}
