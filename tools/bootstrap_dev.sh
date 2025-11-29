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
#
# ---------------------------------------------------------------------------
# bootstrap_dev.sh
#
# Utility script for setting up a local Rucio development environment.
# It can check out a release or master, bring up Docker Compose services,
# and optionally run a selected test suite.
#
# Requirements: a local clone of Rucio plus git, docker, docker-compose (or
# Docker Compose v2), curl, and jq available in PATH.
#
set -euo pipefail

DRY_RUN_ENVIRONMENT="${BOOTSTRAP_DEV_DRY_RUN:-${BOOTSTRAP_DEV_TEST_MODE:-0}}"
SKIP_RUNTIME_DEP_CHECKS=false
if [[ "$DRY_RUN_ENVIRONMENT" != "0" ]]; then
  SKIP_RUNTIME_DEP_CHECKS=true
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_ROOT="$SCRIPT_DIR/bootstrap_dev"
BOOTSTRAP_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMMANDS_DIR="$BOOTSTRAP_ROOT/commands"

source "$BOOTSTRAP_ROOT/lib/common.sh"
source "$BOOTSTRAP_ROOT/lib/docker.sh"
source "$BOOTSTRAP_ROOT/lib/git.sh"
source "$BOOTSTRAP_ROOT/lib/tests.sh"
source "$BOOTSTRAP_ROOT/lib/config.sh"
source "$BOOTSTRAP_ROOT/lib/cli.sh"

source "$COMMANDS_DIR/checkout.sh"
source "$COMMANDS_DIR/compose.sh"
source "$COMMANDS_DIR/tests.sh"

#
# bootstrap_dev::log_selections <config_var> <profiles_var>
# ----------------------------------------------
# Summarise parsed CLI options before any action is taken.
#
function bootstrap_dev::log_selections() {
  local cfg_name="$1"
  local profiles_name="$2"

  local use_master="$(bootstrap_config::get "$cfg_name" use_master)"
  local use_latest="$(bootstrap_config::get "$cfg_name" use_latest)"
  local specified_release="$(bootstrap_config::get "$cfg_name" release)"
  local any_profile="$(bootstrap_config::get "$cfg_name" any_profile_arg)"
  local expose_ports="$(bootstrap_config::get "$cfg_name" expose_ports)"
  local selected_test="$(bootstrap_config::get "$cfg_name" selected_test)"
  local pytest_filter="$(bootstrap_config::get "$cfg_name" pytest_filter)"
  local reuse_autotest="$(bootstrap_config::get "$cfg_name" reuse_autotest_images)"
  local skip_pull="$(bootstrap_config::get "$cfg_name" skip_pull_for_profiles)"
  local dry_run_flag="$(bootstrap_config::get "$cfg_name" dry_run_flag)"
  local profile_count="$(bootstrap_config::profile_count "$profiles_name")"
  local -a selected_profiles=()
  bootstrap_config::copy_profiles "$profiles_name" selected_profiles

  echo ">>> Logging user input selections..."
  if [[ "$use_master" == "true" ]]; then
    echo "Checkout -m/--master"
  fi
  if [[ "$use_latest" == "true" ]]; then
    echo "Checkout -l/--latest"
  fi
  if [[ -n "$specified_release" ]]; then
    echo "Checkout -r/--release $specified_release"
  fi

  if [[ "$any_profile" == "true" ]]; then
    if (( profile_count > 0 )); then
      echo "Deploy unprofiled services + named profiles: ${selected_profiles[*]}"
    else
      echo "Deploy only unprofiled/base services (no named profiles)."
    fi
  else
    echo "No profiles specified."
  fi

  if [[ "$expose_ports" == "true" ]]; then
    echo "Local port mappings enabled (docker-compose.ports.yml will be used)."
  else
    echo "No local port mappings requested."
  fi

  if [[ -n "$selected_test" ]]; then
    echo "Test selection: #$selected_test"
    if [[ -n "$pytest_filter" ]]; then
      echo "Pytest filter: $pytest_filter"
    fi
  else
    echo "No tests selected."
  fi

  if [[ "$reuse_autotest" == "true" && -n "$selected_test" ]]; then
    echo "Cache-use: autotests will reuse cached images (RUCIO_AUTOTEST_REUSE_IMAGES=1)."
  fi
  if [[ "$skip_pull" == "true" && "$any_profile" == "true" ]]; then
    echo "Cache-use: profiles will skip 'docker compose pull' and use locally cached images."
    if bootstrap_docker::is_compose_v2; then
      echo "Compose v2 detected: will also add '--pull never' to 'docker compose up'."
    fi
  fi
  if [[ "$dry_run_flag" != "0" ]]; then
    echo "Dry-run mode enabled: git and Docker commands will be logged only."
  fi
}

#
# bootstrap_dev::print_help_reference <script_name>
# ----------------------------------------------
# Emit the canonical help text for the script.
#
function bootstrap_dev::print_help_reference() {
  local script_name="$1"
  cat <<USAGE
Usage: $script_name [options]

Checkout options (mutually exclusive):
  -r, --release <TAG>   Force local '$(bootstrap_common::demo_branch)' branch to the upstream release tag <TAG>, e.g. 37.4.0.
  -l, --latest          Force local '$(bootstrap_common::demo_branch)' to the semver release that matches the Docker Hub 'latest' digest.
  -m, --master          Force local '$(bootstrap_common::demo_branch)' to the upstream master branch.

Docker options:
  -p, --profile [NAME]  If NAME is omitted, spin up only unprofiled/base services.
                        If NAME is provided, spin up that profile plus unprofiled services.
                        You can specify multiple profiles by repeating this option.
  -x, --expose-ports    Include docker-compose.ports.yml so that containers have published ports.

Other:
  -t, --test <N>        Run test number N after bootstrap. Cannot be used with -p/--profile.
  -f, --filter <PYTEST> Limit tests executed when combined with --test/-t.
  -c, --cache-use       Reuse cached images for tests and/or profiles (skip pulls/builds).
  -y, --yes             Assume "yes" for destructive prompts.
  -h, --help            Show this message and exit.

Notes:
  1) Checkout flags (-r, -l, -m) operate on the demo branch (default '$(bootstrap_common::demo_branch)') and forcibly
     overwrite any local changes on that branch.
  2) Without checkout flags the script leaves your working copy untouched.
  3) Docker Compose runs only when at least one --profile/-p argument is provided.
  4) --expose-ports merges docker-compose.ports.yml so containers expose services on 127.0.0.1.
  5) Running tests is destructive: the dev database volume is removed to ensure a clean state.
USAGE
}

bootstrap_common::require_command git "Git is not installed or not in PATH."
if [[ "$SKIP_RUNTIME_DEP_CHECKS" == "false" ]]; then
  bootstrap_common::require_command docker "Docker is not installed or not in PATH."
  bootstrap_docker::ensure_daemon_running
  compose_cmd="$(bootstrap_docker::detect_compose_command)"
else
  compose_cmd="${COMPOSE_CMD:-docker compose}"
fi
bootstrap_docker::set_compose_command "$compose_cmd"

bootstrap_common::require_command curl "'curl' not found."
bootstrap_common::require_command jq "'jq' not found."

declare -a BOOTSTRAP_PROFILES
bootstrap_cli::parse BOOTSTRAP_CONFIG BOOTSTRAP_PROFILES "$@"

bootstrap_config::set BOOTSTRAP_CONFIG repo_root "$BOOTSTRAP_REPO_ROOT"
bootstrap_config::set BOOTSTRAP_CONFIG demo_branch "$(bootstrap_common::demo_branch)"
bootstrap_config::set BOOTSTRAP_CONFIG upstream_remote "$(bootstrap_common::upstream_remote)"
bootstrap_config::set BOOTSTRAP_CONFIG project_name "dev"
bootstrap_config::set BOOTSTRAP_CONFIG specified_release "$(bootstrap_config::get BOOTSTRAP_CONFIG release)"

use_master="$(bootstrap_config::get BOOTSTRAP_CONFIG use_master)"
use_latest="$(bootstrap_config::get BOOTSTRAP_CONFIG use_latest)"
specified_release="$(bootstrap_config::get BOOTSTRAP_CONFIG release)"
any_profile="$(bootstrap_config::get BOOTSTRAP_CONFIG any_profile_arg)"
expose_ports="$(bootstrap_config::get BOOTSTRAP_CONFIG expose_ports)"
selected_test="$(bootstrap_config::get BOOTSTRAP_CONFIG selected_test)"
pytest_filter="$(bootstrap_config::get BOOTSTRAP_CONFIG pytest_filter)"
reuse_autotest="$(bootstrap_config::get BOOTSTRAP_CONFIG reuse_autotest_images)"
skip_pull="$(bootstrap_config::get BOOTSTRAP_CONFIG skip_pull_for_profiles)"
dry_run_flag="$(bootstrap_config::get BOOTSTRAP_CONFIG dry_run_flag)"

bootstrap_dev::log_selections BOOTSTRAP_CONFIG BOOTSTRAP_PROFILES

echo

cd "$BOOTSTRAP_REPO_ROOT"

bootstrap_dev_checkout::run BOOTSTRAP_CONFIG

if [[ "$any_profile" == "true" ]]; then
  bootstrap_dev_compose::run BOOTSTRAP_CONFIG BOOTSTRAP_PROFILES
  if [[ "$dry_run_flag" == "0" ]]; then
    cat <<SUMMARY
-----------------------------------------------------------------------
Rucio dev environment started.

 If you used one of -r/-l/-m, your local branch '$(bootstrap_common::demo_branch)' now points
 to that code. Any existing changes on '$(bootstrap_common::demo_branch)' were overwritten.

 Next steps:
   - Check containers:                              docker ps
   - Attach to a container:                         docker exec -it dev-rucio-1 /bin/bash
   - Tail the HTTPD error log:                      docker exec -it dev-rucio-1 tail -f /var/log/rucio/httpd_error_log
   - Run a complete testing:                        docker exec -it dev-rucio-1 tools/run_tests.sh
   - Only prepare the Database for testing:         docker exec -it dev-rucio-1 tools/run_tests.sh -i
   - Get the rucio version with curl:               docker exec -it dev-rucio-1 curl -k https://rucio:443/ping
   - Stop a container:                              docker stop dev-rucio-1
   - Shut down (stop/remove) all Rucio containers:  docker-compose --project-name dev down

-------------------------------------------------------------------
 IMPORTANT:
   1) You can also manually spin up the 'latest' dev environment using Docker Compose directly.
      Example using docker:
        docker-compose --file path_to/etc/docker/dev/docker-compose.yml up
      ..or using podman:
        podman-compose --file path_to/etc/docker/dev/docker-compose.yml up -d

   2) Additionally, you can specify custom parameters, such as a Docker repository, a specific Rucio
      release tag (in such cases, RUCIO_DEV_PREFIX=release- is required), or extra profiles.
      Example using docker:
        DOCKER_REPO=my_repo RUCIO_TAG=37.4.0 RUCIO_DEV_PREFIX=release- docker-compose --project-name dev --file path_to/etc/docker/dev/docker-compose.yml --profile storage --profile monitoring up
      ..or using podman:
        RUCIO_TAG=37.4.0 RUCIO_DEV_PREFIX=release- podman-compose --file path_to/etc/docker/dev/docker-compose.yml --profile storage up -d

   3) Switching local branches while containers are running:
      If you change or check out a different branch locally, the bind-mounted code inside
      the container will be replaced on-the-fly. This can cause unpredictable behavior or
      partial/inconsistent code loading. For best results, tear down the containers before
      switching branches, then start them again on the new branch.
-------------------------------------------------------------------
SUMMARY
  fi
else
  echo ">>> Since no '-p/--profile' specified, skipping Docker Compose."
  if [[ -z "$selected_test" ]]; then
    echo ">>> Done."
  else
    echo ">>> Test option detected; required services (if any) will be started automatically."
  fi
fi

bootstrap_dev_tests::run BOOTSTRAP_CONFIG BOOTSTRAP_PROFILES
bootstrap_tests::print_available
