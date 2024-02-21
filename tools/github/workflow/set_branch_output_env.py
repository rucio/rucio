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

from os import environ as env


def set_output(name: str, value: str) -> None:
    with open(env['GITHUB_OUTPUT'], 'a') as fh:
        print(f'{name}={value}', file=fh)


def main():
    set_output("branch", str((env.get("GITHUB_BASE_REF", None) if env.get("GITHUB_BASE_REF", None) else env.get("GITHUB_REF", "master"))))


if __name__ == "__main__":
    main()
