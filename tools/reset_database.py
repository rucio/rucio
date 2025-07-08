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

"""
Reset, purge and/or (re)create a Rucio test database.

Behavior
------------------------+-----------------------+---------------------------+
 Flag(s)                |  What happens         |  Subsequent actions       |
------------------------+-----------------------+---------------------------+
 (no flag)              | drop_orm_tables()     | build_database() +        |
                        |                       | create_base_vo() +        |
                        |                       | create_root_account()     |
------------------------+-----------------------+---------------------------+
 -b / --purge-build     | purge_db()            | build_database() +        |
                        |                       | create_base_vo() +        |
                        |                       | create_root_account()     |
------------------------+-----------------------+---------------------------+
 -p / --purge           | purge_db()            | nothing else..            |
                        |                       | the script ends           |
------------------------+-----------------------+---------------------------+
"""

import os.path
import sys
from argparse import ArgumentParser

# Ensure package imports work when executed from any cwd
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

from rucio.db.sqla.util import (  # noqa: E402
    build_database,  # noqa: E402
    create_base_vo,  # noqa: E402
    create_root_account,  # noqa: E402
    drop_orm_tables,  # noqa: E402
    purge_db,  # noqa: E402
)

if __name__ == '__main__':

    parser = ArgumentParser(
        prog="reset_database.py",
        description="Reset the local Rucio database used in tests."
    )
    g = parser.add_mutually_exclusive_group()
    g.add_argument(
        "-b", "--purge-build",
        action="store_true",
        help="Purge EVERYTHING (tables, constraints, schema) "
             "and then rebuild a fresh schema with base VO + root account.",
    )
    g.add_argument(
        "-p", "--purge",
        action="store_true",
        help="Purge EVERYTHING and stop – do NOT recreate schema or accounts.",
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # 1. Decide how to reset
    # ------------------------------------------------------------------
    if args.purge_build or args.purge:
        purge_db()
    else:
        drop_orm_tables()

    # ------------------------------------------------------------------
    # 2. Decide what to rebuild
    # ------------------------------------------------------------------
    if not args.purge:
        build_database()
        create_base_vo()
        create_root_account()
