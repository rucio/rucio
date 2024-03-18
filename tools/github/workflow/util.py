#!/usr/bin/env python3
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

import json
import sys
import urllib.request


def req_json(url):
    req = urllib.request.Request(url)
    req.add_header('Accept', 'application/json')
    print(f"Requesting {req.full_url} next..", file=sys.stderr)
    return req


def get_next_link(answer):
    info = answer.info()
    if "Link" in info:
        for link in info["Link"].split(","):
            parts = list(map(str.strip, link.split(";")))
            if 'rel="next"' in parts:
                return parts[0][1:-1]
    return False


def all_branches(branches_url: str):
    while branches_url:
        with urllib.request.urlopen(req_json(branches_url)) as answer:
            branches = json.load(answer)
            branches = map(lambda b: b["name"], branches)
            branches_url = get_next_link(answer)
        yield from branches
