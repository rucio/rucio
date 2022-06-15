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

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

from argparse import ArgumentParser  # noqa: E402

from rucio.db.sqla.util import build_database, destroy_database, drop_everything, create_root_account, create_base_vo  # noqa: E402

if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('-d', '--drop-everything', action="store_true", default=False, help='Drop all tables and constraints')
    args = parser.parse_args()

    if args.drop_everything:
        drop_everything()
    else:
        destroy_database()

    build_database()
    create_base_vo()
    create_root_account()
