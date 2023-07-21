#!/usr/bin/env python3
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

import itertools
import json
import sys

from util import all_branches


def branches_to_add() -> list[str]:
    add_branches = []
    idx = 0
    while True:
        try:
            if idx + 1 >= len(sys.argv):
                break

            idx = sys.argv.index('--add', idx + 1) + 1
            if idx >= len(sys.argv):
                print("--add was used without argument", file=sys.stderr)
                sys.exit(2)
            add_branches.append(sys.argv[idx])
        except ValueError:
            break
    return add_branches


def main():
    # input: https://api.github.com/repos/rucio/rucio/branches{/branch}
    branches_url = sys.stdin.read().strip().rstrip("{/branch}")

    branches = itertools.chain(
        branches_to_add(),
        filter(lambda b: b.startswith("release"), all_branches(branches_url)),
    )

    if '--all' in sys.argv:
        branches = list(branches)
        if not branches:
            print("Could not find any branches", file=sys.stderr)
            sys.exit(2)

        if '--json' in sys.argv:
            print(json.dumps(branches))
        else:
            print('\n'.join(branches))
    else:
        latest = max(branches, default=None)
        if latest is None:
            print("Could not find any branches", file=sys.stderr)
            sys.exit(2)

        print(latest)


if __name__ == "__main__":
    main()
