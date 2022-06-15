#!/usr/bin/env python
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

# Run this once to set up the database.
#   PYTHONPATH=/opt/rucio/.venv/lib/python2.7/site-packages/rucio python tools/bootstrap.py
#
# Verify for default SQLite:
#   for i in `sqlite3 /tmp/rucio.db ".tables"`; do echo $i:; sqlite3 /tmp/rucio.db "select * from $i"; echo; done

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

from rucio.db.sqla.util import (build_database, create_base_vo, create_root_account)  # noqa: E402

if __name__ == '__main__':
    build_database()
    create_base_vo()
    create_root_account()
