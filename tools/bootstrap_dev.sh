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
#
#  What this script does:
#    1. (Optional) Checks out a specific Rucio version in your local Git repo using:
#         -r, --release <X>  => a specific Rucio release tag (e.g. 36.5.0)
#         -l, --latest       => the tag matching Docker Hub's 'latest' digest (if found)
#         -m, --master       => the latest master branch from upstream
#       If none of these are used, no checkout is performed (the local repo remains untouched).
#
#    2. (Optional) Spins up the dev environment **only if** one or more -p, --profile <NAME> arguments are provided.
#       If `-p` or `--profile` is used WITHOUT a specified <NAME> (e.g. `-p`), the script spins up the basic profile.
#       If any `-p someProfile` / `--profile anotherProfile` are also given, we spin up those named profiles too.
#         Examples:
#           -p
#           -p storage
#           -p monitoring
#           -p storage -p monitoring
#
#  Prerequisites:
#   - You have cloned your Rucio fork and added the 'upstream' remote, e.g.:
#        cd ~/dev
#        git clone git@github.com:<your_username>/rucio.git
#        cd rucio
#        git remote add upstream git@github.com:rucio/rucio.git
#        git fetch --all
#   - Docker, docker-compose (or Docker Compose v2), curl, and jq are installed/running.
#
# Usage:
#   ./tools/bootstrap_dev.sh [--release <TAG> | --latest | --master]
#                            [--profile [<NAME>] ...]
#                            [--help]
#   (You can also use the short forms: -r <TAG>, -l, -m, -p <NAME>)
#
# Examples:
#   1) Perform simple environment checks (keep local code as-is, do NOT run Docker Compose):
#        ./tools/bootstrap_dev.sh
#
#   2) Check out a specific release (36.5.0) and start the dev environment including the "storage" profile:
#        ./tools/bootstrap_dev.sh --release 36.5.0 --profile storage
#     or the short form:
#        ./tools/bootstrap_dev.sh -r 36.5.0 -p storage
#
#   3) Check out master and run the dev environment including the "storage" and "monitoring" profiles:
#        ./tools/bootstrap_dev.sh --master --profile storage --profile monitoring
#     or:
#        ./tools/bootstrap_dev.sh -m -p storage -p monitoring
#
#   4) Check out the tag that matches Docker Hub 'latest' and start the dev environment including the "storage" profile:
#        ./tools/bootstrap_dev.sh --latest --profile storage
#     or:
#        ./tools/bootstrap_dev.sh -l -p storage
#
#   5) Check out master only:
#        ./tools/bootstrap_dev.sh --master
#     or:
#        ./tools/bootstrap_dev.sh -m
#
#   6) Start the dev environment using the local code (no fork/checkout changes) with the basic Docker Compose profile:
#        ./tools/bootstrap_dev.sh --profile
#     or:
#        ./tools/bootstrap_dev.sh -p
#
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
#                          CONFIGURATION / CONSTANTS
# ---------------------------------------------------------------------------
DEMO_BRANCH="demo-env"        # The ephemeral local branch we will force-reset if needed
UPSTREAM_REMOTE="upstream"    # The name of the remote pointing to https://github.com/rucio/rucio

# ---------------------------------------------------------------------------
#                             HELPER: Print usage
# ---------------------------------------------------------------------------
function usage() {
  cat <<EOF
Usage: $0 [options]

Checkout options (mutually exclusive):
  -r, --release <TAG>   Force local '$DEMO_BRANCH' branch to the upstream release tag <TAG>, e.g. 36.5.0.
  -l, --latest          Force local '$DEMO_BRANCH' to the semver release that matches the Docker Hub 'latest' digest.
  -m, --master          Force local '$DEMO_BRANCH' to the upstream master branch.

Docker options:
  -p, --profile [NAME]  If NAME is omitted, spin up only unprofiled/base services
                        (like 'docker-compose up -d' with no profiles).
                        If NAME is provided, spin up that profile plus unprofiled services.
                        You can specify multiple profiles by repeating this option.

Other:
  -h, --help            Show this message and exit.

Notes:
  1) If you provide any of the checkout flags (-r, -l, -m), the script creates or overwrites the
     local '$DEMO_BRANCH' branch (any uncommitted changes on '$DEMO_BRANCH' will be destroyed).
  2) If you do NOT provide any checkout flags (-r, -l, -m), the script does
     NOT modify branches or tags at all (your local code remains intact).
  3) Docker Compose runs only if you specify at least one -p/--profile argument.
  4) This script expects a configured remote called '$UPSTREAM_REMOTE' pointing to https://github.com/rucio/rucio.git.

Examples:
  $0 --release 36.5.0 --profile storage
  $0 --master --profile storage --profile monitoring
  $0 --latest --profile storage
  $0 --master
  $0 --profile
EOF
}

# ---------------------------------------------------------------------------
#     HELPER: Check that we have an '$UPSTREAM_REMOTE' pointing to Rucio
# ---------------------------------------------------------------------------
function ensure_upstream_exists() {
  if ! git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
    echo "ERROR: No '$UPSTREAM_REMOTE' remote found. Please set up your fork properly, e.g.:"
    echo "       git remote add upstream git@github.com:rucio/rucio.git"
    echo "       git fetch --all"
    exit 1
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
  local REPO="rucio/rucio-dev"
  local PAGE_SIZE="100"
  local URL="https://hub.docker.com/v2/repositories/$REPO/tags/?page_size=$PAGE_SIZE"
  local arch_to_match="amd64"

  local LATEST_DIGEST=""
  local MATCHING_TAG=""

  while [[ -n "$URL" && "$URL" != "null" ]]; do
    local RESPONSE
    RESPONSE="$(curl -fsSL "$URL")" || {
      echo "ERROR: Unable to fetch $URL"
      return 1
    }

    local TAGS_ON_PAGE
    TAGS_ON_PAGE="$(echo "$RESPONSE" | jq -c '.results[]')"

    # 1) Find the 'latest' digest if not found yet
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

    # 2) If we have LATEST_DIGEST, see if we can find a semver release tag with the same digest
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

    # 3) If we have both, we can stop; no need to parse further pages
    if [[ -n "$LATEST_DIGEST" && -n "$MATCHING_TAG" ]]; then
      break
    fi

    # Move to the next page
    URL="$(echo "$RESPONSE" | jq -r '.next')"
  done

  echo "$MATCHING_TAG"
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
PROFILES=()
USE_DEFAULT_PROFILE="false"  # Will be set true if -p/--profile is given with no argument

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
        echo "ERROR: Option '$1' requires a release tag (e.g. '36.5.0')."
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
      # Check if user provided a profile name or not
      if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
        # No name => user wants the default (unprofiled) set only
        USE_DEFAULT_PROFILE="true"
        shift
      else
        # Next token is a profile name
        PROFILES+=("$2")
        shift 2
      fi
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
if [[ "${#PROFILES[@]}" -gt 0 || "$USE_DEFAULT_PROFILE" == "true" ]]; then
  if [[ "$USE_DEFAULT_PROFILE" == "true" && "${#PROFILES[@]}" -gt 0 ]]; then
    echo "Deploy default/unprofiled services AND named profiles: ${PROFILES[*]}"
  elif [[ "$USE_DEFAULT_PROFILE" == "true" && "${#PROFILES[@]}" -eq 0 ]]; then
    echo "Deploy only the default/unprofiled services."
  else
    echo "Deploy named profiles: ${PROFILES[*]}"
  fi
else
  echo "No profiles specified."
fi

# ---------------------------------------------------------------------------
#                        MOVE INTO THE RUCIO REPO ROOT
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
RUCIO_REPO_ROOT="$(pwd)"

# ---------------------------------------------------------------------------
#                            GIT CHECKOUT LOGIC
# ---------------------------------------------------------------------------

# We'll pass this to Docker Compose as RUCIO_TAG. If empty, that means :latest.
RUCIO_TAG=""

# If user specified any destructive checkout option
if [[ "$USE_MASTER" == "true" || "$USE_LATEST" == "true" || -n "$SPECIFIED_RELEASE" ]]; then
  ensure_upstream_exists

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
    # RUCIO_TAG stays empty => "docker.io/.../rucio-dev:latest" (which shall be updated later to master state)

  # --release
  elif [[ -n "$SPECIFIED_RELEASE" ]]; then
    echo ">>> Force-reset local '$DEMO_BRANCH' to tag '$SPECIFIED_RELEASE'."
    ensure_tag_fetched "$SPECIFIED_RELEASE"
    git checkout -B "$DEMO_BRANCH" "refs/tags/$SPECIFIED_RELEASE"
    RUCIO_TAG="$SPECIFIED_RELEASE"

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
#                   IF NO PROFILES SPECIFIED, WE STOP HERE
# ---------------------------------------------------------------------------
if [[ "${#PROFILES[@]}" -eq 0 && "$USE_DEFAULT_PROFILE" == "false" ]]; then
  echo
  echo ">>> No '-p/--profile' specified. Skipping Docker Compose."
  echo ">>> Done."
  exit 0
fi

# ---------------------------------------------------------------------------
#                RUN DOCKER COMPOSE with the requested profiles
#       (First tear down any existing environment to ensure a clean start)
# ---------------------------------------------------------------------------

echo ">>> Using Docker images with RUCIO_TAG=\"$RUCIO_TAG\""

cd "$RUCIO_REPO_ROOT/etc/docker/dev"

# Build an array of '--profile' arguments if the user gave them
profile_args=()
if [[ "${#PROFILES[@]}" -gt 0 ]]; then
  for prof in "${PROFILES[@]}"; do
    profile_args+=( --profile "$prof" )
  done
fi

echo ">>> Stopping any previous containers from 'dev' environment..."
RUCIO_TAG="$RUCIO_TAG" "$COMPOSE_CMD" --project-name dev --file docker-compose.yml \
  --profile default --profile monitoring --profile storage down || true

# - If user did `-p` only (no name), we have USE_DEFAULT_PROFILE=true and PROFILES is empty.
# - If user did named profiles only, PROFILES is non-empty and USE_DEFAULT_PROFILE=false.
# - If user did both blank & named profiles, PROFILES is non-empty and USE_DEFAULT_PROFILE=true.
if [[ "$USE_DEFAULT_PROFILE" == "true" && "${#PROFILES[@]}" -eq 0 ]]; then
  echo ">>> Starting only the default/unprofiled containers (no named profiles)."
  # Pull images first (no --profile)
  RUCIO_TAG="$RUCIO_TAG" "$COMPOSE_CMD" --file docker-compose.yml pull || true
  # Bring them up
  RUCIO_TAG="$RUCIO_TAG" "$COMPOSE_CMD" --project-name dev --file docker-compose.yml up -d
else
  # We either have named profiles, or default + named profiles
  if [[ "$USE_DEFAULT_PROFILE" == "true" && "${#PROFILES[@]}" -gt 0 ]]; then
    echo ">>> Starting default/unprofiled + named profiles: ${PROFILES[*]}"
  else
    echo ">>> Starting named profiles only: ${PROFILES[*]}"
  fi
  # Pull images first with profiles + base
  RUCIO_TAG="$RUCIO_TAG" "$COMPOSE_CMD" --file docker-compose.yml "${profile_args[@]}" pull || true
  # Bring them up with profiles + base
  RUCIO_TAG="$RUCIO_TAG" "$COMPOSE_CMD" --project-name dev --file docker-compose.yml "${profile_args[@]}" up -d
fi

# ------------------------------------------------------------------------------
# Perform a "pip install --upgrade -r" ONLY IF the user explicitly selected --master.
# For master, we want to ensure the container environment is up-to-date with dev reqs.
# ------------------------------------------------------------------------------
if [[ "$USE_MASTER" == "true" ]]; then
  echo
  echo ">>> Since '--master' was selected, let's ensure the container's environment has"
  echo ">>> the *latest* dev dependencies. We'll just upgrade packages; old ones won't be removed."
  echo ">>> Using /rucio_source/requirements/requirements.dev.txt, which is read-only mounted."

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
   1) You can also manually spin up the dev environment using Docker Compose directly. For example:
      docker-compose --project-name dev --file etc/docker/dev/docker-compose.yml up -d

   2) Additionally, you can specify custom parameters, such as a Docker repository, a specific Rucio release tag, or extra profiles. For example:
      DOCKER_REPO=my_repo RUCIO_TAG=36.5.0 docker-compose --project-name dev --file etc/docker/dev/docker-compose.yml --profile storage --profile monitoring up -d

   3) Switching local branches while containers are running:
      If you change or check out a different branch locally, the bind-mounted code inside the container will be replaced on-the-fly. This can cause unpredictable
      behavior or partial/inconsistent code loading. For best results, tear down the containers before switching branches, then start them again on the new branch.
-------------------------------------------------------------------
EOF
