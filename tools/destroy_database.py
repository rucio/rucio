#!/usr/bin/env python
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

import os.path
import sys

base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

import argparse  # noqa: E402

from rucio.core.db.sqla.util import destroy_database, drop_everything  # noqa: E402

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--drop-everything", action="store_true", default=False, help='Drop all tables+constraints')
    args = parser.parse_args()
    if args.drop_everything:
        drop_everything()
    else:
        destroy_database()
