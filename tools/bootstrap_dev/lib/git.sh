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

# ensure_upstream_exists <repo_root> <remote_name> <assume_yes> <dry_run>
# ---------------------------------------------------------------------
# Check that the upstream remote exists and targets the official repository.
# When requested, prompt (or default) to update it.
function bootstrap_git::ensure_upstream_exists() {
  local repo_root="${1:-$(bootstrap_common::repo_root)}"
  local remote_name="${2:-$(bootstrap_common::upstream_remote)}"
  local assume_yes="${3:-false}"
  local dry_run="${4:-0}"

  local ssh_url="git@github.com:rucio/rucio.git"
  local https_url="https://github.com/rucio/rucio.git"

  pushd "$repo_root" >/dev/null

  if git remote get-url "$remote_name" >/dev/null 2>&1; then
    local current_url
    current_url="$(git remote get-url "$remote_name")"

    if [[ "$current_url" == "$ssh_url" || "$current_url" == "$https_url" ]]; then
      bootstrap_common::info "'$remote_name' remote already points to the official Rucio repo: $current_url"
      popd >/dev/null
      return
    fi

    bootstrap_common::warn "'$remote_name' found but points to:"
    echo "         $current_url"
    echo "         Official Rucio addresses are:"
    echo "             SSH:   $ssh_url"
    echo "             HTTPS: $https_url"
    echo

    local confirmed="false"
    local protocol=""
    if [[ "$assume_yes" == "true" ]]; then
      confirmed="true"
      protocol="https"
      bootstrap_common::info "--yes supplied: defaulting to HTTPS for '$remote_name'."
    else
      read -r -p "Do you want to OVERWRITE '$remote_name' with the official Rucio repo? [y/N]: " confirm
      confirm="$(bootstrap_common::to_lowercase "$confirm")"
      case "$confirm" in
        y|yes)
          confirmed="true"
          ;;
        *)
          bootstrap_common::info "Leaving '$remote_name' as-is. (Might cause errors later.)"
          popd >/dev/null
          return
          ;;
      esac
    fi

    if [[ "$confirmed" == "true" ]]; then
      while true; do
        if [[ -z "$protocol" ]]; then
          echo
          echo "Which protocol do you want to use?"
          echo "  [1] SSH   ($ssh_url)"
          echo "  [2] HTTPS ($https_url)"
          read -r -p "Please enter 1 or 2: " choice
          case "$choice" in
            1)
              protocol="ssh"
              ;;
            2)
              protocol="https"
              ;;
            *)
              echo "Invalid choice. Please try again."
              continue
              ;;
          esac
        fi

        if [[ "$protocol" == "ssh" ]]; then
          bootstrap_common::info "Setting '$remote_name' to SSH: $ssh_url"
          if [[ "$dry_run" != "0" ]]; then
            bootstrap_common::info "[dry-run] git remote set-url '$remote_name' '$ssh_url'"
          else
            git remote set-url "$remote_name" "$ssh_url"
          fi
        else
          bootstrap_common::info "Setting '$remote_name' to HTTPS: $https_url"
          if [[ "$dry_run" != "0" ]]; then
            bootstrap_common::info "[dry-run] git remote set-url '$remote_name' '$https_url'"
          else
            git remote set-url "$remote_name" "$https_url"
          fi
        fi
        break
      done
    fi
  else
    bootstrap_common::info "No '$remote_name' remote found. Let's add it now."
    local protocol=""
    if [[ "$assume_yes" == "true" ]]; then
      protocol="https"
      bootstrap_common::info "--yes supplied: defaulting to HTTPS for new remote."
    fi

    while true; do
      if [[ -z "$protocol" ]]; then
        echo
        echo "Which protocol do you want to use?"
        echo "  [1] SSH   ($ssh_url)"
        echo "  [2] HTTPS ($https_url)"
        read -r -p "Please enter 1 or 2: " choice
        case "$choice" in
          1)
            protocol="ssh"
            ;;
          2)
            protocol="https"
            ;;
          *)
            echo "Invalid choice. Please try again."
            continue
            ;;
        esac
      fi

      if [[ "$protocol" == "ssh" ]]; then
        bootstrap_common::info "Adding '$remote_name' as SSH: $ssh_url"
        if [[ "$dry_run" != "0" ]]; then
          bootstrap_common::info "[dry-run] git remote add '$remote_name' '$ssh_url'"
        else
          git remote add "$remote_name" "$ssh_url"
        fi
      else
        bootstrap_common::info "Adding '$remote_name' as HTTPS: $https_url"
        if [[ "$dry_run" != "0" ]]; then
          bootstrap_common::info "[dry-run] git remote add '$remote_name' '$https_url'"
        else
          git remote add "$remote_name" "$https_url"
        fi
      fi
      break
    done
  fi

  popd >/dev/null
}

# ensure_tag_fetched <repo_root> <remote_name> <tag> <dry_run>
# ---------------------------------------------------------------------
# Ensure the requested release tag is present locally, fetching it if needed.
function bootstrap_git::ensure_tag_fetched() {
  local repo_root="${1:-$(bootstrap_common::repo_root)}"
  local remote_name="${2:-$(bootstrap_common::upstream_remote)}"
  local tag="$3"
  local dry_run="${4:-0}"

  pushd "$repo_root" >/dev/null
  if ! git rev-parse "refs/tags/$tag" >/dev/null 2>&1; then
    echo "    Tag '$tag' not found locally, attempting to fetch from '$remote_name'..."
    if [[ "$dry_run" != "0" ]]; then
      bootstrap_common::info "[dry-run] git fetch '$remote_name' 'refs/tags/$tag:refs/tags/$tag'"
    else
      git fetch "$remote_name" "refs/tags/$tag:refs/tags/$tag" || {
        bootstrap_common::error "Could not fetch tag '$tag' from upstream!"
        popd >/dev/null
        exit 1
      }
    fi
  fi
  popd >/dev/null
}

# bootstrap_git::find_release_tag_for_latest_digest
# ----------------------------------------------
# Look up the Docker Hub "latest" digest and return the matching release tag.
function bootstrap_git::find_release_tag_for_latest_digest() {
  local repo="rucio/rucio-dev"
  local page_size="100"
  local url="https://hub.docker.com/v2/repositories/$repo/tags/?page_size=$page_size"
  local arch_to_match="amd64"
  local latest_digest=""
  local matching_tag=""

  while [[ -n "$url" && "$url" != "null" ]]; do
    local response
    response="$(curl -fsSL "$url")" || {
      bootstrap_common::error "Unable to fetch $url"
      return 1
    }

    local tags_on_page
    tags_on_page="$(echo "$response" | jq -c '.results[]')"

    if [[ -z "$latest_digest" ]]; then
      latest_digest="$(
        echo "$tags_on_page" \
          | jq -r --arg arch "$arch_to_match" '
              select(.name == "latest")
              | .images[]
              | select(.architecture == $arch)
              | .digest
            ' \
          | head -1
      )"
    fi

    if [[ -n "$latest_digest" && -z "$matching_tag" ]]; then
      matching_tag="$(
        echo "$tags_on_page" \
          | jq -r --arg arch "$arch_to_match" --arg digest "$latest_digest" '
              select(.name != "latest")
              | select(.images[] | select(.architecture == $arch and .digest == $digest))
              | .name
            ' \
          | grep -E '^(release-)?[0-9]+\.[0-9]+\.[0-9]+' \
          | head -1
      )"
    fi

    if [[ -n "$latest_digest" && -n "$matching_tag" ]]; then
      break
    fi

    url="$(echo "$response" | jq -r '.next')"
  done

  echo "$matching_tag"
}
