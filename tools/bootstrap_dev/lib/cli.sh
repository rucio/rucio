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

# bootstrap_cli::usage
# ----------------------------------------------
# Show help text and the list of known tests.
#
function bootstrap_cli::usage() {
  bootstrap_dev::print_help_reference "$0"

  bootstrap_tests::configure "" "" false
  bootstrap_tests::gather
  bootstrap_tests::print_available
}

# bootstrap_cli::parse <config_var> <profiles_var> -- <args...>
# ----------------------------------------------
# Parse CLI arguments and write the outcome into the config store.
#
function bootstrap_cli::parse() {
  local config_name="$1"
  local profiles_name="$2"
  shift 2

  bootstrap_config::init "$config_name" "$profiles_name"

  local specified_release=""
  local use_master="false"
  local use_latest="false"
  local any_profile_arg="false"
  local expose_ports="false"
  local selected_test=""
  local pytest_filter=""
  local reuse_autotest_images="false"
  local skip_pull_for_profiles="false"
  local assume_yes="false"
  local -a parsed_profiles
  parsed_profiles=()

  if [[ "${RUCIO_AUTOTEST_REUSE_IMAGES:-}" == "1" ]]; then
    reuse_autotest_images="true"
  fi

  if [[ "${RUCIO_DEV_SKIP_PULL:-}" == "1" ]]; then
    skip_pull_for_profiles="true"
  fi

  local dry_run_flag
  dry_run_flag="${BOOTSTRAP_DEV_DRY_RUN:-${BOOTSTRAP_DEV_TEST_MODE:-0}}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--release)
        if [[ "$use_master" == "true" || "$use_latest" == "true" || -n "$specified_release" ]]; then
          bootstrap_common::error "Only one of --release, --latest, or --master may be specified."
          exit 1
        fi
        if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
          bootstrap_common::error "Option '$1' requires a release tag (e.g. '37.4.0')."
          exit 1
        fi
        specified_release="$2"
        shift 2
        ;;
      -l|--latest)
        if [[ "$use_master" == "true" || "$use_latest" == "true" || -n "$specified_release" ]]; then
          bootstrap_common::error "Only one of --release, --latest, or --master may be specified."
          exit 1
        fi
        use_latest="true"
        shift
        ;;
      -m|--master)
        if [[ "$use_master" == "true" || "$use_latest" == "true" || -n "$specified_release" ]]; then
          bootstrap_common::error "Only one of --release, --latest, or --master may be specified."
          exit 1
        fi
        use_master="true"
        shift
        ;;
      -p|--profile)
        any_profile_arg="true"
        if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
          shift
        else
          parsed_profiles+=("$2")
          shift 2
        fi
        ;;
      -x|--expose-ports)
        expose_ports="true"
        shift
        ;;
      -c|--cache-use)
        reuse_autotest_images="true"
        skip_pull_for_profiles="true"
        shift
        ;;
      -y|--yes)
        assume_yes="true"
        shift
        ;;
      -t|--test)
        if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
          bootstrap_common::error "Option '$1' requires a test number."
          exit 1
        fi
        selected_test="$2"
        shift 2
        ;;
      -f|--filter)
        if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
          bootstrap_common::error "Option '$1' requires a pytest filter string."
          exit 1
        fi
        pytest_filter="$2"
        shift 2
        ;;
      -h|--help)
        bootstrap_cli::usage
        exit 0
        ;;
      --)
        shift
        break
        ;;
      *)
        bootstrap_common::error "Unknown option: $1"
        echo
        bootstrap_cli::usage
        exit 1
        ;;
    esac
  done

  if [[ $# -gt 0 ]]; then
    bootstrap_common::error "Unexpected extra arguments: $*"
    echo
    bootstrap_cli::usage
    exit 1
  fi

  if [[ -n "$selected_test" && "$any_profile_arg" == "true" ]]; then
    bootstrap_common::error "The -t/--test option cannot be combined with -p/--profile."
    exit 1
  fi

  if [[ -n "$pytest_filter" && -z "$selected_test" ]]; then
    bootstrap_common::error "--filter can only be used together with --test/-t."
    exit 1
  fi

  if { [[ "$reuse_autotest_images" == "true" ]] || [[ "$skip_pull_for_profiles" == "true" ]] ; } \
     && [[ -z "$selected_test" ]] && [[ "$any_profile_arg" == "false" ]]; then
    bootstrap_common::error "--cache-use/-c must be used together with either --test/-t or --profile/-p."
    exit 1
  fi

  bootstrap_config::set "$config_name" release "$specified_release"
  bootstrap_config::set "$config_name" use_master "$use_master"
  bootstrap_config::set "$config_name" use_latest "$use_latest"
  bootstrap_config::set "$config_name" any_profile_arg "$any_profile_arg"
  bootstrap_config::set "$config_name" expose_ports "$expose_ports"
  bootstrap_config::set "$config_name" selected_test "$selected_test"
  bootstrap_config::set "$config_name" pytest_filter "$pytest_filter"
  bootstrap_config::set "$config_name" reuse_autotest_images "$reuse_autotest_images"
  bootstrap_config::set "$config_name" skip_pull_for_profiles "$skip_pull_for_profiles"
  bootstrap_config::set "$config_name" assume_yes "$assume_yes"
  bootstrap_config::set "$config_name" dry_run_flag "$dry_run_flag"
  if [[ ${#parsed_profiles[@]} -gt 0 ]]; then
    bootstrap_config::set_profiles "$config_name" "$profiles_name" "${parsed_profiles[@]}"
  else
    bootstrap_config::set_profiles "$config_name" "$profiles_name"
  fi
}
