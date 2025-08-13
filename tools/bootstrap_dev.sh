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
# ----------------------------------------------------------------------------
#
# bootstrap_dev.sh
#
#  A convenience script for testers/devs to set up (bootstrap) a local Rucio environment. It can:
#   - Checkout a specific Rucio release or master branch into an ephemeral "demo-env" branch (force-overwriting it).
#   - Start the Rucio services via Docker Compose, controlled via profiles.
#   - Run one of the available tests after the bootstrap step.
#
#  What this script does:
#    1. (Optional) Checks out a specific Rucio version in your local Git repo using:
#         -r, --release <X>  => a specific Rucio release tag (e.g. 36.5.0)
#         -l, --latest       => the tag matching Docker Hub's 'latest' digest (if found)
#         -m, --master       => the latest master branch from upstream
#       If none of these are used, no checkout is performed (the local repo remains untouched).
#
#    2. (Optional) Spins up the dev environment **only if** one or more -p, --profile <NAME> arguments are provided.
#       - If `-p` or `--profile` is used WITHOUT a specified <NAME> (e.g. `-p`), we spin up *only* the unprofiled/base services.
#       - If any `-p someProfile` / `--profile anotherProfile` are given, we spin up the unprofiled services **plus** those named profiles.
#         Examples:
#           -p
#           -p storage
#           -p monitoring
#           -p storage -p monitoring
#
#    3. (Optional) Runs a selected test after bootstrapping via:
#         -t, --test <N>
#       This option must NOT be combined with -p/--profile, as the tests will manage
#       Docker Compose on their own depending on what they need. Combine with
#       -f, --filter <PYTEST_FILTER> to run only specific tests within the suite.
#
#    4. (Optional) Enables local port mappings (127.0.0.1:<port>:<container_port>) via:
#         -x, --expose-ports
#       This will include the additional docker-compose.ports.yml file so that the containers
#       expose their ports on localhost. If omitted, the containers run without published ports.
#
#  Prerequisites:
#   - You have cloned your Rucio fork locally.
#   - Docker, docker-compose (or Docker Compose v2), curl, and jq are installed/running.
#
# Usage:
#   ./tools/bootstrap_dev.sh [--release <TAG> | --latest | --master]
#                            [--profile [<NAME>] ...]
#                            [--test <N>] [--filter <PYTEST_FILTER>]
#                            [--expose-ports]
#                            [--help]
#   (You can also use the short forms: -r <TAG>, -l, -m, -p <NAME>, -t <N>, -f <PYTEST_FILTER>, -x)
#
# Examples:
#   1) Check out a specific release (37.4.0) and start the dev environment including the "storage" profile:
#        ./tools/bootstrap_dev.sh --release 37.4.0 --profile storage
#     or the short form:
#        ./tools/bootstrap_dev.sh -r 37.4.0 -p storage
#
#   2) Check out master and run the dev environment (with local port mappings), including the "storage" and "monitoring" profiles:
#        ./tools/bootstrap_dev.sh --master --profile storage --profile monitoring --expose-ports
#     or:
#        ./tools/bootstrap_dev.sh -m -p storage -p monitoring -x
#
#   3) Check out the tag that matches Docker Hub 'latest' and start the dev environment including the "storage" profile:
#        ./tools/bootstrap_dev.sh --latest --profile storage
#     or:
#        ./tools/bootstrap_dev.sh -l -p storage
#
#   4) Check out master only:
#        ./tools/bootstrap_dev.sh --master
#     or:
#        ./tools/bootstrap_dev.sh -m
#
#   5) Start the dev environment using the local code (no fork/checkout changes) with the basic Docker Compose profile:
#        ./tools/bootstrap_dev.sh --profile
#     or:
#        ./tools/bootstrap_dev.sh -p
#
#   6) Run the default local test suite after bootstrapping:
#        ./tools/bootstrap_dev.sh --test 1
#     or:
#        ./tools/bootstrap_dev.sh -t 1
#
#   7) Run a single pytest within "multi_vo (dist alma9, py 3.9, db postgres14) test suite using a filter:
#        ./tools/bootstrap_dev.sh --test 9 --filter tests/test_scope.py::test_scope_duplicate
#     or:
#        ./tools/bootstrap_dev.sh -t 9 -f tests/test_scope.py::test_scope_duplicate
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
#                          CONFIGURATION / CONSTANTS
# ---------------------------------------------------------------------------
DEMO_BRANCH="demo-env"        # The ephemeral local branch we will force-reset if needed
UPSTREAM_REMOTE="upstream"    # The name of the remote pointing to https://github.com/rucio/rucio
SELECTED_TEST=""              # Optional test number to run after bootstrap
TEST_COMMANDS=()              # Commands for available tests
TEST_DESCRIPTIONS=()          # Human readable descriptions for tests

# ---------------------------------------------------------------------------
#                             HELPER: Print usage
# ---------------------------------------------------------------------------
function usage() {
  cat <<EOF
Usage: $0 [options]

Checkout options (mutually exclusive):
  -r, --release <TAG>   Force local '$DEMO_BRANCH' branch to the upstream release tag <TAG>, e.g. 37.4.0.
  -l, --latest          Force local '$DEMO_BRANCH' to the semver release that matches the Docker Hub 'latest' digest.
  -m, --master          Force local '$DEMO_BRANCH' to the upstream master branch.

Docker options:
  -p, --profile [NAME]  If NAME is omitted, spin up only unprofiled/base services
                        (like 'docker-compose up -d' with no profiles).
                        If NAME is provided, spin up that profile plus unprofiled services.
                        You can specify multiple profiles by repeating this option.
  -x, --expose-ports    Include docker-compose.ports.yml so that containers have published ports.

Other:
  -t, --test <N>        Run test number N after bootstrap. Cannot be used with
                        -p/--profile, as tests handle Docker Compose themselves.
  -f, --filter <PYTEST_FILTER>
                        When running tests with -t/--test, limit execution to
                        tests matching the given pytest filter.
  -h, --help            Show this message and exit.

Notes:
  1) If you provide any of the checkout flags (-r, -l, -m), the script creates or overwrites the
     local '$DEMO_BRANCH' branch (any uncommitted changes on '$DEMO_BRANCH' will be destroyed).
  2) If you do NOT provide any checkout flags (-r, -l, -m), the script does
     NOT modify branches or tags at all (your local code remains intact).
  3) Docker Compose runs only if you specify at least one -p/--profile argument.
  4) This script will ensure a remote named '$UPSTREAM_REMOTE' pointing to the official
     Rucio repository. If it's absent or incorrect, the script will fix it automatically.
  5) If you specify -x or --expose-ports, the additional 'docker-compose.ports.yml' is used
     so that each service's port is published on 127.0.0.1.
  6) The -t/--test option cannot be combined with -p/--profile. When a test is
     selected, this script will start any required services automatically.
  7) Running tests is destructive: any existing 'dev_vol-ruciodb-data' volume and
     containers using it will be removed to guarantee a clean database.
  8) The -f/--filter option can be used with -t/--test to pass any pytest-style
     filter such as 'tests/file.py::TestClass::test_method' to run a subset of tests.

Examples:
  $0 --release 37.4.0 --profile storage
  $0 --master --profile storage --profile monitoring --expose-ports
  $0 --latest --profile storage
  $0 --master
  $0 --profile
  $0 --test 9 --filter tests/test_scope.py::test_scope_duplicate
EOF

gather_tests
print_available_tests
}

# ---------------------------------------------------------------------------
#     HELPER: Ensure '$UPSTREAM_REMOTE' points to official Rucio
# ---------------------------------------------------------------------------
function ensure_upstream_exists() {
  local ssh_url="git@github.com:rucio/rucio.git"
  local https_url="https://github.com/rucio/rucio.git"

  # Check if the remote $UPSTREAM_REMOTE exists
  if git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
    local current_url
    current_url="$(git remote get-url "$UPSTREAM_REMOTE")"

    # It should also match the official Rucio repo
    if [[ "$current_url" == "$ssh_url" || "$current_url" == "$https_url" ]]; then
      echo ">>> '$UPSTREAM_REMOTE' remote already points to the official Rucio repo: $current_url"
      return  # Nothing else to do
    fi

    # Otherwise, it exists but points somewhere else
    echo "WARNING: '$UPSTREAM_REMOTE' found but points to:"
    echo "         $current_url"
    echo "         Official Rucio addresses are:"
    echo "             SSH:   $ssh_url"
    echo "             HTTPS: $https_url"
    echo
    read -r -p "Do you want to OVERWRITE '$UPSTREAM_REMOTE' with the official Rucio repo? [y/N]: " confirm
    case "${confirm,,}" in
      y|yes)
        # Prompt which protocol to use
        while true; do
          echo
          echo "Which protocol do you want to use?"
          echo "  [1] SSH   ($ssh_url)"
          echo "  [2] HTTPS ($https_url)"
          read -r -p "Please enter 1 or 2: " choice
          case "$choice" in
            1)
              echo ">>> Setting '$UPSTREAM_REMOTE' to SSH: $ssh_url"
              git remote set-url "$UPSTREAM_REMOTE" "$ssh_url"
              break
              ;;
            2)
              echo ">>> Setting '$UPSTREAM_REMOTE' to HTTPS: $https_url"
              git remote set-url "$UPSTREAM_REMOTE" "$https_url"
              break
              ;;
            *)
              echo "Invalid choice. Please try again."
              ;;
          esac
        done
        ;;
      *)
        echo "INFO: Leaving '$UPSTREAM_REMOTE' as-is. (Might cause errors later.)"
        ;;
    esac

  else
    # The remote doesn't exist at all
    echo ">>> No '$UPSTREAM_REMOTE' remote found. Let's add it now."
    while true; do
      echo
      echo "Which protocol do you want to use?"
      echo "  [1] SSH   ($ssh_url)"
      echo "  [2] HTTPS ($https_url)"
      read -r -p "Please enter 1 or 2: " choice
      case "$choice" in
        1)
          echo ">>> Adding '$UPSTREAM_REMOTE' as SSH: $ssh_url"
          git remote add "$UPSTREAM_REMOTE" "$ssh_url"
          break
          ;;
        2)
          echo ">>> Adding '$UPSTREAM_REMOTE' as HTTPS: $https_url"
          git remote add "$UPSTREAM_REMOTE" "$https_url"
          break
          ;;
        *)
          echo "Invalid choice. Please try again."
          ;;
      esac
    done
  fi
}

# ---------------------------------------------------------------------------
#  HELPER: Ensure a given tag exists locally; if not, fetch it from upstream
# ---------------------------------------------------------------------------
function ensure_tag_fetched() {
  local tag="$1"
  if ! git rev-parse "refs/tags/$tag" >/dev/null 2>&1; then
    echo "    Tag '$tag' not found locally, attempting to fetch from '$UPSTREAM_REMOTE'..."
    git fetch "$UPSTREAM_REMOTE" "refs/tags/$tag:refs/tags/$tag" || {
      echo "ERROR: Could not fetch tag '$tag' from upstream!"
      exit 1
    }
  fi
}

# ---------------------------------------------------------------------------
#    HELPER: Find a release tag that matches Docker Hub’s 'latest' digest
# ---------------------------------------------------------------------------
function find_release_tag_for_latest_digest() {
  # Query the Docker Hub API to discover which semantic version tag shares the
  # same image digest as the "latest" tag. The endpoint is paginated, so loop
  # over pages until both the digest and matching tag are found.
  local REPO="rucio/rucio-dev"                      # Repository to query
  local PAGE_SIZE="100"                             # Fetch up to 100 tags per page
  local URL="https://hub.docker.com/v2/repositories/$REPO/tags/?page_size=$PAGE_SIZE"
  local arch_to_match="amd64"                       # Architecture to compare digests for

  local LATEST_DIGEST=""
  local MATCHING_TAG=""

  # Continue looping while the API provides a "next" page to follow.
  while [[ -n "$URL" && "$URL" != "null" ]]; do
    local RESPONSE
    # Retrieve the current page. "-f" makes curl fail on HTTP errors to handle them explicitly.
    RESPONSE="$(curl -fsSL "$URL")" || {
      echo "ERROR: Unable to fetch $URL"
      return 1
    }

    # Extract the list of tags from the JSON response.
    # Each element will be processed individually by jq in the sections below.
    local TAGS_ON_PAGE
    TAGS_ON_PAGE="$(echo "$RESPONSE" | jq -c '.results[]')"

    # 1) Discover the digest referenced by the "latest" tag if we haven't done so yet.
    #    The jq expression filters for the latest tag, then selects the image matching
    #    our target architecture and extracts its digest.
    if [[ -z "$LATEST_DIGEST" ]]; then
      LATEST_DIGEST="$(
        echo "$TAGS_ON_PAGE" \
          | jq -r --arg arch "$arch_to_match" '
              select(.name == "latest")
              | .images[]
              | select(.architecture == $arch)
              | .digest
            ' \
          | head -1
      )"
    fi

    # 2) Once we know the digest of "latest", search the remaining tags for a
    #    semantic version (or release-) tag that points to the same digest.
    if [[ -n "$LATEST_DIGEST" && -z "$MATCHING_TAG" ]]; then
      MATCHING_TAG="$(
        echo "$TAGS_ON_PAGE" \
          | jq -r --arg arch "$arch_to_match" --arg digest "$LATEST_DIGEST" '
              select(.name != "latest")
              | select(.images[] | select(.architecture == $arch and .digest == $digest))
              | .name
            ' \
          | grep -E '^(release-)?[0-9]+\.[0-9]+\.[0-9]+' \
          | head -1
      )"
    fi

    # 3) If both values are populated, we've found what we were after. Abort the pagination.
    if [[ -n "$LATEST_DIGEST" && -n "$MATCHING_TAG" ]]; then
      break
    fi

    # Use the "next" field from the API response to continue to the next page, if any.
    URL="$(echo "$RESPONSE" | jq -r '.next')"
  done

  echo "$MATCHING_TAG"
}

# ---------------------------------------------------------------------------
#            HELPER: Collect and display available test commands
# ---------------------------------------------------------------------------
function gather_tests() {

  # Reset the arrays that hold test metadata for each invocation of this function.
  # Each index in TEST_COMMANDS corresponds to the same index in TEST_DESCRIPTIONS.
  TEST_COMMANDS=()
  TEST_DESCRIPTIONS=()

  # Determine the repository root if not already provided by the caller.
  # This allows the script to be executed from anywhere within the repository tree.
  if [[ -z "${RUCIO_REPO_ROOT:-}" ]]; then
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    RUCIO_REPO_ROOT="$(cd "$script_dir/.." && pwd)"
  fi

  # Add the default option which simply runs the local test suite.
  TEST_COMMANDS+=("$COMPOSE_CMD --project-name dev exec rucio tools/run_tests.sh")
  TEST_DESCRIPTIONS+=("run local test suite (tools/run_tests.sh)")

  # The autotest matrix contains additional cases defined in a YAML file.
  # We convert it to JSON using a helper Python script and then iterate over each
  # case to build commands and human readable descriptions.
  local matrix_json
  if matrix_json=$(python3 "$RUCIO_REPO_ROOT/tools/test/matrix_parser.py" < "$RUCIO_REPO_ROOT/etc/docker/test/matrix.yml" 2>/dev/null); then
    # Use 'mapfile' if available to read the JSON array into Bash; fall back to
    # a manual read loop otherwise for broader compatibility.
    if command -v mapfile >/dev/null 2>&1; then
      mapfile -t matrix_cases < <(echo "$matrix_json" | jq -c '(. // []) | .[]?')
    else
      matrix_cases=()
      while IFS= read -r line; do
        matrix_cases+=("$line")
      done < <(echo "$matrix_json" | jq -c '(. // []) | .[]?')
    fi

    if ((${#matrix_cases[@]} > 0)); then
      for case in "${matrix_cases[@]}"; do
        local dist py suite db services desc cmd
        # Extract various parameters for this test case.
        # Optional values such as RDBMS or extra services may be empty.
        dist=$(echo "$case" | jq -r '.DIST')
        py=$(echo "$case" | jq -r '.PYTHON')
        suite=$(echo "$case" | jq -r '.SUITE')
        db=$(echo "$case" | jq -r '.RDBMS // empty')
        services=$(echo "$case" | jq -r '[.SERVICES] | flatten | join(",")')

        # Build a human-readable description and the command to run for this entry in the matrix.
        desc="autotest: ${suite} (dist ${dist}, py ${py}"
        if [[ -n "$db" ]]; then
          desc+=", db ${db}"
        fi
        if [[ -n "$services" ]]; then
          desc+=", services ${services}"
        fi
        desc+=")"

        cmd="$RUCIO_REPO_ROOT/tools/run_autotests.sh --build -d ${dist} --py ${py} --suite ${suite}"
        if [[ -n "$db" ]]; then
          cmd+=" --db ${db}"
        fi
        TEST_COMMANDS+=("$cmd")
        TEST_DESCRIPTIONS+=("$desc")
      done
    else
      echo "WARNING: Autotest matrix is empty" >&2
    fi
  else
    echo "WARNING: Unable to parse autotest matrix" >&2
  fi
}

function print_available_tests() {
  echo
  echo "Available tests:"
  local idx=1
  for desc in "${TEST_DESCRIPTIONS[@]}"; do
    printf "  %2d) %s\n" "$idx" "$desc"
    idx=$((idx+1))
  done
  echo "Run with '$0 --test <number>' or '$0 -t <number>' to execute one automatically."
}

# ---------------------------------------------------------------------------
#                HELPER: Remove dev database volume and container
# ---------------------------------------------------------------------------
function remove_rucio_db_volume() {
  local volume="dev_vol-ruciodb-data"

  # Remove any containers that still reference the volume. Docker refuses to delete a volume
  # that is in use, so we force-remove such containers to guarantee a clean slate for upcoming
  # tests. Normally this case should never occur because containers should be already stopped.
  local containers
  containers=$(docker ps -aq --filter "volume=$volume" 2>/dev/null || true)
  if [[ -n "$containers" ]]; then
    echo ">>> Removing containers using volume '$volume'..."
    docker rm -f $containers >/dev/null 2>&1 || true
  fi

  # Remove the volume itself if it exists. This ensures each test run starts
  # with a brand new database without any leftover state from previous runs.
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    echo ">>> Removing existing database volume '$volume' to ensure a clean test database..."
    docker volume rm -f "$volume" >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
#                HELPER: Remove auto-generated autotest volumes
# ---------------------------------------------------------------------------
function remove_autotest_volumes() {
  local volumes
  # Volumes created by autotests get a random hex project prefix
  volumes=$(docker volume ls --format '{{.Name}}' | grep -E '^[0-9a-f]{16}_vol-' || true)
  if [[ -n "$volumes" ]]; then
    echo ">>> Removing autogenerated autotest volumes..."
    docker volume rm $volumes >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
#      HELPER: Stop any running containers from the 'dev' compose project
# ---------------------------------------------------------------------------
function stop_dev_containers() {
  local compose_dir="$RUCIO_REPO_ROOT/etc/docker/dev"
  if [[ -d "$compose_dir" ]]; then
    (
      cd "$compose_dir"
      echo ">>> Stopping any previous containers from 'dev' environment..."
      $COMPOSE_CMD --project-name dev --file docker-compose.yml \
        --profile default \
        --profile monitoring \
        --profile storage \
        --profile externalmetadata \
        --profile iam \
        --profile client \
        --profile postgres14 \
        --profile mysql8 \
        --profile oracle \
        down >/dev/null 2>&1 || true
    )
  fi


  # Some tests start containers with a random Docker Compose project name
  # while still assigning a fixed container_name like 'dev-graphite-1'. Such
  # containers won't be removed by the command above because their project
  # label differs. Explicitly remove any leftover containers matching the
  # 'dev-' prefix to avoid name conflicts on subsequent runs.
  local leftovers
  leftovers=$(docker ps -aq --filter 'name=^dev-' 2>/dev/null || true)
  if [[ -n "$leftovers" ]]; then
    echo ">>> Removing leftover 'dev' containers to avoid conflicts..."
    docker rm -f $leftovers >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
#                      CHECK BASIC DEPENDENCIES / ENV
# ---------------------------------------------------------------------------
# 1) Git
if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: Git is not installed or not in PATH."
  exit 1
fi

# 2) Docker
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed or not in PATH."
  exit 1
fi

# 3) Check Docker is running
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker doesn't seem to be running, or you lack privileges."
  exit 1
fi

# 4) Docker Compose (v1 or v2)
COMPOSE_CMD=""
if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
elif docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD="docker compose"
else
  echo "ERROR: Neither 'docker-compose' nor 'docker compose' is available."
  exit 1
fi

# 5) curl + jq for --latest
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: 'curl' not found."
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: 'jq' not found."
  exit 1
fi

# ---------------------------------------------------------------------------
#                              PARSE ARGUMENTS
# ---------------------------------------------------------------------------
SPECIFIED_RELEASE=""
USE_MASTER="false"
USE_LATEST="false"
PROFILES=()           # Named profiles
ANY_PROFILE_ARG=false # Will be set true if -p/--profile is used at all
EXPOSE_PORTS=false    # Track whether we want to expose ports

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--release)
      # Only one checkout option allowed
      if [[ "$USE_MASTER" == "true" || "$USE_LATEST" == "true" || -n "$SPECIFIED_RELEASE" ]]; then
        echo "ERROR: Only one of --release, --latest, or --master may be specified."
        exit 1
      fi
      # Ensure $2 is valid
      if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
        echo "ERROR: Option '$1' requires a release tag (e.g. '37.4.0')."
        exit 1
      fi
      SPECIFIED_RELEASE="$2"
      shift 2
      ;;
    -l|--latest)
      if [[ "$USE_MASTER" == "true" || "$USE_LATEST" == "true" || -n "$SPECIFIED_RELEASE" ]]; then
        echo "ERROR: Only one of --release, --latest, or --master may be specified."
        exit 1
      fi
      USE_LATEST="true"
      shift
      ;;
    -m|--master)
      if [[ "$USE_MASTER" == "true" || "$USE_LATEST" == "true" || -n "$SPECIFIED_RELEASE" ]]; then
        echo "ERROR: Only one of --release, --latest, or --master may be specified."
        exit 1
      fi
      USE_MASTER="true"
      shift
      ;;
    -p|--profile)
      ANY_PROFILE_ARG=true
      # Check if user provided a profile name or not
      if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
        # No name => user wants only base (unprofiled) services
        # We do NOT add anything to PROFILES[]; that signals "no named profiles"
        shift
      else
        # Next token is a profile name
        PROFILES+=("$2")
        shift 2
      fi
      ;;
    -x|--expose-ports)
      EXPOSE_PORTS=true
      shift
      ;;
    -t|--test)
      if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
        echo "ERROR: Option '$1' requires a test number."; exit 1
      fi
      SELECTED_TEST="$2"
      shift 2
      ;;
    -f|--filter)
      if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
        echo "ERROR: Option '$1' requires a test selection."; exit 1
      fi
      PYTEST_FILTER="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option '$1'"
      usage
      exit 1
      ;;
  esac
done

# Ensure there are no leftover arguments
if [[ "$#" -gt 0 ]]; then
  echo "ERROR: Unexpected extra arguments: $*"
  usage
  exit 1
fi

# Ensure filter is only used when a test is selected
if [[ -n "$PYTEST_FILTER" && -z "$SELECTED_TEST" ]]; then
  echo "ERROR: --filter/-f must be used together with --test/-t." >&2
  exit 1
fi

# Disallow combining tests with explicit profile selection
if [[ -n "$SELECTED_TEST" && $ANY_PROFILE_ARG == true ]]; then
  echo "ERROR: --test/-t cannot be used together with --profile/-p." >&2
  echo "       Selected tests start any required Docker Compose services automatically." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
#                              SELECTIONS LOGGING
# ---------------------------------------------------------------------------
echo ">>> Logging user input selections..."
if [[ "$USE_MASTER" == "true" ]]; then
  echo "Checkout -m/--master"
fi
if [[ "$USE_LATEST" == "true" ]]; then
  echo "Checkout -l/--latest"
fi
if [[ -n "$SPECIFIED_RELEASE" ]]; then
  echo "Checkout -r/--release $SPECIFIED_RELEASE"
fi

if $ANY_PROFILE_ARG; then
  if [[ "${#PROFILES[@]}" -gt 0 ]]; then
    echo "Deploy unprofiled services + named profiles: ${PROFILES[*]}"
  else
    echo "Deploy only unprofiled/base services (no named profiles)."
  fi
else
  echo "No profiles specified."
fi

if $EXPOSE_PORTS; then
  echo "Local port mappings enabled (docker-compose.ports.yml will be used)."
else
  echo "No local port mappings requested."
fi

if [[ -n "$SELECTED_TEST" ]]; then
  echo "Test selection: #$SELECTED_TEST"
  if [[ -n "$PYTEST_FILTER" ]]; then
    echo "Pytest filter: $PYTEST_FILTER"
  fi
else
  echo "No tests selected."
fi

# ---------------------------------------------------------------------------
#                        MOVE INTO THE RUCIO REPO ROOT
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
RUCIO_REPO_ROOT="$(pwd)"

# ---------------------------------------------------------------------------
#            ENSURE 'upstream' POINTS TO THE OFFICIAL RUCIO REPO
# ---------------------------------------------------------------------------
ensure_upstream_exists

# ---------------------------------------------------------------------------
#                            GIT CHECKOUT LOGIC
# ---------------------------------------------------------------------------

# We'll pass this to Docker Compose as RUCIO_TAG. If empty, that means :latest.
RUCIO_TAG=""

# By default, no prefix for rucio-dev images
RUCIO_DEV_PREFIX=""

# If user specified any destructive checkout option
if [[ "$USE_MASTER" == "true" || "$USE_LATEST" == "true" || -n "$SPECIFIED_RELEASE" ]]; then

  # Prompt user for destructive action confirmation
  echo
  echo "WARNING: You are about to forcibly reset the local '$DEMO_BRANCH' branch."
  echo "Any uncommitted changes (or even local commits) on that branch will be overwritten."
  echo -n "Are you sure you want to proceed? [y/N]: "
  read -r user_in
  # Convert to lowercase
  user_in=$(echo "$user_in" | tr '[:upper:]' '[:lower:]')
  if [[ "$user_in" != "y" && "$user_in" != "yes" ]]; then
    echo "Aborting."
    exit 0
  fi

  echo ">>> Fetching from '$UPSTREAM_REMOTE' (all tags + branches)..."
  git fetch "$UPSTREAM_REMOTE" --tags

  # --master
  if [[ "$USE_MASTER" == "true" ]]; then
    echo ">>> Force-reset local '$DEMO_BRANCH' to '$UPSTREAM_REMOTE/master'."
    git checkout -B "$DEMO_BRANCH" "$UPSTREAM_REMOTE/master"
    # RUCIO_TAG and RUCIO_DEV_PREFIX stay empty => "docker.io/.../rucio-dev:latest"

  # --release
  elif [[ -n "$SPECIFIED_RELEASE" ]]; then
    echo ">>> Force-reset local '$DEMO_BRANCH' to tag '$SPECIFIED_RELEASE'."
    ensure_tag_fetched "$SPECIFIED_RELEASE"
    git checkout -B "$DEMO_BRANCH" "refs/tags/$SPECIFIED_RELEASE"
    RUCIO_TAG="$SPECIFIED_RELEASE"

    # For rucio-dev images that use "release-<tag>" style
    RUCIO_DEV_PREFIX="release-"

  # --latest
  elif [[ "$USE_LATEST" == "true" ]]; then
    echo ">>> Looking up release tag that matches Docker Hub's 'latest' digest..."
    MATCHING_TAG="$(find_release_tag_for_latest_digest || true)"
    if [[ -n "$MATCHING_TAG" ]]; then
      echo ">>> Found matching semver release tag for 'latest': $MATCHING_TAG"

      # 1) Remove 'release-' prefix if present, so we can fetch from upstream
      GIT_TAG="$MATCHING_TAG"
      if [[ "$MATCHING_TAG" == release-* ]]; then
        GIT_TAG="${MATCHING_TAG#release-}"
      fi

      # 2) Ensure the actual Git tag is fetched locally
      ensure_tag_fetched "$GIT_TAG"

      # 3) Check out a local branch and set RUCIO_TAG
      git checkout -B "$DEMO_BRANCH" "refs/tags/$GIT_TAG"
      RUCIO_TAG="$GIT_TAG"
    else
      echo ">>> WARNING: Could not find a semver release tag that matches Docker Hub's 'latest' digest."
      echo "    1) The 'latest' image might be built from a commit that is not yet tagged."
      echo "    2) We will NOT checkout any tag. Your local code remains on the current branch."
      echo "    3) Docker images will still default to 'latest'."
    fi
  fi
else
  # No checkout flags => do nothing to local code
  # RUCIO_TAG remains "" => default to :latest
  :
fi

# ---------------------------------------------------------------------------
#                RUN DOCKER COMPOSE with the requested profiles
#       (First tear down any existing environment to ensure a clean start)
# ---------------------------------------------------------------------------
if $ANY_PROFILE_ARG; then
echo ">>> Using Docker images with RUCIO_TAG=\"$RUCIO_TAG\" and RUCIO_DEV_PREFIX=\"$RUCIO_DEV_PREFIX\""

# Make sure Docker Compose sees the RUCIO_TAG environment variable
export RUCIO_TAG="$RUCIO_TAG"
export RUCIO_DEV_PREFIX="$RUCIO_DEV_PREFIX"

cd "$RUCIO_REPO_ROOT/etc/docker/dev"

# Build an array of '--profile' arguments if the user gave them. Docker Compose
# expects a separate '--profile <name>' pair for each profile, so transform the
# simple list stored in PROFILES into the appropriate CLI arguments.
profile_args=()

if [ "${PROFILES+set}" = set ]; then
  for prof in "${PROFILES[@]}"; do
    profile_args+=( --profile "$prof" )
  done
fi

stop_dev_containers

# Build an array of compose files including always the docker-compose.yml and (optionally)
# also the docker-compose.ports.yml if EXPOSE_PORTS is true.
compose_files=(--file docker-compose.yml)
if $EXPOSE_PORTS; then
  # Include an additional compose file that exposes container ports on
  # localhost when the user requested --expose-ports.
  compose_files+=(--file docker-compose.ports.yml)
fi

# If we have no named profiles, that means the user specified `-p` with no name,
# so we do not pass --profile at all => only unprofiled containers will run.
if [[ "${#profile_args[@]}" -eq 0 ]]; then
  echo ">>> Starting only unprofiled/base containers (no named profiles)."
  $COMPOSE_CMD "${compose_files[@]}" pull || true
  # Bring them up
  $COMPOSE_CMD --project-name dev "${compose_files[@]}" up -d
else
  echo ">>> Starting unprofiled/base + named profiles: ${PROFILES[*]}"
  $COMPOSE_CMD "${compose_files[@]}" "${profile_args[@]}" pull || true
  # Bring them up with profiles + base
  $COMPOSE_CMD --project-name dev "${compose_files[@]}" "${profile_args[@]}" up -d
fi

# ------------------------------------------------------------------------------
# Perform a "pip install --upgrade -r" ONLY IF the user explicitly selected --master.
# For master, we want to ensure the container environment is up-to-date with dev reqs.
# ------------------------------------------------------------------------------
if [[ "$USE_MASTER" == "true" ]]; then
  echo
  echo ">>> Since '--master' is selected, let's ensure the container's environment has the most"
  echo ">>> recent dev dependencies (we'll just upgrade packages; old ones won't be removed)."
  echo ">>> Requirements considered: /rucio_source/requirements/requirements.dev.txt"

  # 1) Upgrade pip just in case
  $COMPOSE_CMD --project-name dev exec rucio python3 -m pip install --no-cache-dir --upgrade pip

  # 2) Now install/upgrade from dev requirements
  $COMPOSE_CMD --project-name dev exec rucio \
    python3 -m pip install --no-cache-dir --upgrade -r /rucio_source/requirements/requirements.dev.txt

  echo ">>> Done installing/upgrading dev requirements for master!"
fi

cat <<EOF

-----------------------------------------------------------------------
Rucio dev environment started.

 If you used one of -r/-l/-m, your local branch '$DEMO_BRANCH' now points
 to that code. Any existing changes on '$DEMO_BRANCH' were overwritten.

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
   1) You can also manually spin up the \`latest\` dev environment using Docker Compose directly.
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

   4) Running tests (-t/--test) is destructive. The script will remove the 'dev_vol-ruciodb-data'
      volume and any containers using it, wiping any data stored there.
-------------------------------------------------------------------
EOF
else
  echo
  echo ">>> Since no '-p/--profile' specified, skipping Docker Compose."
  if [[ -z "$SELECTED_TEST" ]]; then
    exit 0
  else
    echo ">>> Test option detected; required services (if any) will be started automatically."
  fi
fi

# Warn about destructive volume removal before running any test
if [[ -n "$SELECTED_TEST" ]]; then
  echo ">>> WARNING: Running tests will remove the 'dev_vol-ruciodb-data' volume."
  stop_dev_containers
  remove_rucio_db_volume
  if [[ "$SELECTED_TEST" != "1" ]]; then
    # Autotests spawn project-specific volumes with random names. Clean them up on exit.
    trap remove_autotest_volumes EXIT
  fi
fi

# If running the basic test suite (--test 1) without starting the dev
# environment explicitly, ensure the 'rucio' service is up so that
# `docker compose exec rucio` succeeds.
if [[ "$SELECTED_TEST" == "1" ]]; then
  echo ">>> Ensuring 'rucio' service is running for test #1..."

  # The first test executes commands inside the running "rucio" container.
  # Make sure the bare minimum service is available here.
  export RUCIO_TAG="$RUCIO_TAG"
  export RUCIO_DEV_PREFIX="$RUCIO_DEV_PREFIX"

  compose_files=(--file docker-compose.yml)
  if $EXPOSE_PORTS; then
    compose_files+=(--file docker-compose.ports.yml)
  fi

  (
    cd "$RUCIO_REPO_ROOT/etc/docker/dev" && \
    $COMPOSE_CMD --project-name dev "${compose_files[@]}" up -d
  )
fi

# Build the test ID mapping
gather_tests

if [[ -n "$SELECTED_TEST" ]]; then
  if ! [[ "$SELECTED_TEST" =~ ^[0-9]+$ ]] || (( SELECTED_TEST < 1 || SELECTED_TEST > ${#TEST_COMMANDS[@]} )); then
    echo "ERROR: Invalid test number '$SELECTED_TEST'" >&2
  else
    cd "$RUCIO_REPO_ROOT"
    echo ">>> Running test #$SELECTED_TEST: ${TEST_DESCRIPTIONS[SELECTED_TEST-1]}"
    cmd="${TEST_COMMANDS[SELECTED_TEST-1]}"
    if [[ -n "$PYTEST_FILTER" ]]; then
      filter_escaped=$(printf '%q' "$PYTEST_FILTER")
      if [[ "$SELECTED_TEST" == "1" ]]; then
        cmd="$COMPOSE_CMD --project-name dev exec -e TESTS=$filter_escaped rucio tools/run_tests.sh -p"
      else
        cmd+=" --filter $filter_escaped"
      fi
    fi
    eval "$cmd"
  fi
fi

print_available_tests
