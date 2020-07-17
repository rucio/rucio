#!/usr/bin/env python3
# Copyright 2020 CERN for the benefit of the ATLAS collaboration.
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
# Authors:
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import json
import os
import pathlib
import sys

import sh
from sh import git


def get_github_url():
    return os.environ.get('GITHUB_URL', default='https://github.com')


def add_or_set_git_remote(remote_name, remote_uri):
    if remote_name in str(git.remote()).splitlines(keepends=False):
        git.remote("set-url", remote_name, remote_uri)
    else:
        git.remote.add(remote_name, remote_uri)


def set_git_author_info(name: str, email: str):
    git.config("user.name", name)
    git.config("user.email", email)


def main():
    options = json.load(sys.stdin)

    github_remote_url = f"{get_github_url()}/{options['target_remote']}.git"
    if len(list(pathlib.Path('.').iterdir())) > 0:
        print("Found existing files in work directory", file=sys.stderr)
        assert pathlib.Path('.git').exists(), "if files are present in the work dir, it must be a git work tree"
        remote = "origin"
        if options["source_remote_name"] == remote:
            remote = remote + "2"
        add_or_set_git_remote(remote, github_remote_url)
        print(f"Fetching from {github_remote_url}", file=sys.stderr)
        git.fetch(remote)
        print(f"Checking out {options['target_branch']} from {remote}/{options['target_branch']}", file=sys.stderr)
        git.checkout("-B", options['target_branch'], f"{remote}/{options['target_branch']}")
        print(f"Cleaning work tree", file=sys.stderr)
        git.reset("--hard", "HEAD")
        git.clean("-fdx")
    else:
        print(f"Cloning {options['target_branch']} from {github_remote_url}", file=sys.stderr)
        git.clone("--branch", options['target_branch'], github_remote_url, ".")

    if options['target_remote'] != options['source_remote']:
        source_remote_name = options['source_remote_name']
        add_or_set_git_remote(source_remote_name, f"{get_github_url()}/{options['source_remote']}.git")
        print(f"Fetching from {get_github_url()}/{options['source_remote']}.git", file=sys.stderr)
        git.fetch(source_remote_name)

    set_git_author_info(f"GitHub Action {os.environ['GITHUB_ACTION']}", "action@localhost")

    try:
        git("cherry-pick", options['source_commits'])
        print(f"Source commits ({options['source_commits']}) were successfully cherry-picked "
              f"onto {options['target_remote']}:{options['target_branch']}", file=sys.stderr)
    except sh.ErrorReturnCode:
        print(f"Source commits ({options['source_commits']}) could not be cherry-picked "
              f"onto {options['target_remote']}:{options['target_branch']}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
