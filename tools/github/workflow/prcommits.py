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
import sys
import urllib.request

from util import req_json, get_next_link


def main():
    commits_url = sys.stdin.read().strip()

    def allcommits():
        next_link = commits_url
        while next_link:
            with urllib.request.urlopen(req_json(next_link)) as answer:
                commits = json.load(answer)
                shalist = map(lambda c: c["sha"], commits)
                next_link = get_next_link(answer)
            yield from shalist

    commit_list = list(allcommits())
    print(f"{commit_list[0]}^..{commit_list[-1]}")


if __name__ == "__main__":
    main()
