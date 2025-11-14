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
BOOTSTRAP_DEV_CHECKOUT_LOADED=1

# bootstrap_dev_checkout::run <config_var>
# ----------------------------------------------
# Apply the selected checkout strategy to the local repository.
#
function bootstrap_dev_checkout::run() {
  local cfg_name="$1"

  local repo_root="$(bootstrap_config::get "$cfg_name" repo_root)"
  local remote_name="$(bootstrap_config::get "$cfg_name" upstream_remote)"
  local demo_branch="$(bootstrap_config::get "$cfg_name" demo_branch)"
  local use_master="$(bootstrap_config::get "$cfg_name" use_master)"
  local use_latest="$(bootstrap_config::get "$cfg_name" use_latest)"
  local specified_release="$(bootstrap_config::get "$cfg_name" specified_release)"
  if [[ -z "$specified_release" ]]; then
    specified_release="$(bootstrap_config::get "$cfg_name" release)"
  fi
  local assume_yes="$(bootstrap_config::get "$cfg_name" assume_yes)"
  local dry_run="$(bootstrap_config::get "$cfg_name" dry_run_flag)"

  local rucio_tag=""
  local rucio_dev_prefix=""
  local matching_tag=""

  if [[ "$use_latest" == "true" ]]; then
    if [[ "$dry_run" != "0" ]]; then
      echo ">>> [dry-run] Skipping Docker Hub 'latest' digest lookup."
    else
      echo ">>> Looking up release tag that matches Docker Hub's 'latest' digest..."
      matching_tag="$(bootstrap_git::find_release_tag_for_latest_digest || true)"
      if [[ -n "$matching_tag" ]]; then
        echo ">>> Found matching semver release tag for 'latest': $matching_tag"
      else
        echo "WARNING: Could not find a release tag matching the Docker Hub 'latest' digest."
        echo "WARNING: Using local code without changing branches."
      fi
    fi
  fi

  if [[ "$dry_run" != "0" ]]; then
    echo ">>> [dry-run] Skipping upstream remote verification."
  else
    bootstrap_git::ensure_upstream_exists "$repo_root" "$remote_name" "$assume_yes" "$dry_run"
  fi

  if [[ "$use_master" != "true" && "$use_latest" != "true" && -n "$specified_release" ]]; then
    :
  elif [[ "$use_master" != "true" && "$use_latest" != "true" && -z "$specified_release" ]]; then
    bootstrap_config::set "$cfg_name" rucio_tag "$rucio_tag"
    bootstrap_config::set "$cfg_name" rucio_dev_prefix "$rucio_dev_prefix"
    return
  fi

  if [[ "$dry_run" != "0" ]]; then
    echo
    echo "WARNING: You are about to forcibly reset the local '$demo_branch' branch."
    echo "Any uncommitted changes (or even local commits) on that branch will be overwritten."
    echo ">>> [dry-run] Would fetch from '$remote_name' and reset '$demo_branch'."
    if [[ -n "$specified_release" ]]; then
      rucio_tag="$specified_release"
      rucio_dev_prefix="release-"
    elif [[ -n "$matching_tag" ]]; then
      local git_tag="$matching_tag"
      local dev_prefix=""
      if [[ "$matching_tag" == release-* ]]; then
        git_tag="${matching_tag#release-}"
        dev_prefix="release-"
      fi
      rucio_tag="$git_tag"
      rucio_dev_prefix="$dev_prefix"
    fi
    bootstrap_config::set "$cfg_name" rucio_tag "$rucio_tag"
    bootstrap_config::set "$cfg_name" rucio_dev_prefix "$rucio_dev_prefix"
    return
  fi

  echo
  echo "WARNING: You are about to forcibly reset the local '$demo_branch' branch."
  echo "Any uncommitted changes (or even local commits) on that branch will be overwritten."

  if [[ "$assume_yes" == "true" ]]; then
    echo ">>> --yes supplied: proceeding without additional confirmation."
  else
    echo -n "Are you sure you want to proceed? [y/N]: "
    read -r user_in
    user_in="$(bootstrap_common::to_lowercase "$user_in")"
    if [[ "$user_in" != "y" && "$user_in" != "yes" ]]; then
      echo "Aborting."
      exit 0
    fi
  fi

  pushd "$repo_root" >/dev/null

  echo ">>> Fetching from '$remote_name' (all tags + branches)..."
  git fetch "$remote_name" --tags

  if [[ "$use_master" == "true" ]]; then
    echo ">>> Force-reset local '$demo_branch' to '$remote_name/master'."
    git checkout -B "$demo_branch" "$remote_name/master"
  elif [[ -n "$specified_release" ]]; then
    echo ">>> Force-reset local '$demo_branch' to tag '$specified_release'."
    bootstrap_git::ensure_tag_fetched "$repo_root" "$remote_name" "$specified_release" "$dry_run"
    git checkout -B "$demo_branch" "refs/tags/$specified_release"
    rucio_tag="$specified_release"
    rucio_dev_prefix="release-"
  elif [[ "$use_latest" == "true" ]]; then
    if [[ -n "$matching_tag" ]]; then
      local git_tag="$matching_tag"
      local dev_prefix=""
      if [[ "$matching_tag" == release-* ]]; then
        git_tag="${matching_tag#release-}"
        dev_prefix="release-"
      fi

      bootstrap_git::ensure_tag_fetched "$repo_root" "$remote_name" "$git_tag" "$dry_run"
      git checkout -B "$demo_branch" "refs/tags/$git_tag"
      rucio_tag="$git_tag"
      rucio_dev_prefix="$dev_prefix"
    fi
  fi

  popd >/dev/null

  bootstrap_config::set "$cfg_name" rucio_tag "$rucio_tag"
  bootstrap_config::set "$cfg_name" rucio_dev_prefix "$rucio_dev_prefix"
}
