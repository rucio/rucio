#!/bin/bash
# Copyright 2020 CERN
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

set -euo pipefail
IFS=$'\n\t'

echo "Downgrading the DB to base"
alembic downgrade base

echo "Check if is_old_db function is returning false after the full downgrade (tests it without alembic)"
PYTHONPATH=lib python3 -c 'import sys; import rucio.db.sqla.util; sys.exit(1 if rucio.db.sqla.util.is_old_db() else 0);'

echo "Updating the DB to head-1"
alembic upgrade head-1

echo "Check if is_old_db function is returning true before the full upgrade"
PYTHONPATH=lib python3 -c 'import sys; import rucio.db.sqla.util; sys.exit(0 if rucio.db.sqla.util.is_old_db() else 1);'

echo "Upgrading the DB to head"
alembic upgrade head

echo "Check if is_old_db function returns false after the full upgrade"
PYTHONPATH=lib python3 -c 'import sys; import rucio.db.sqla.util; sys.exit(1 if rucio.db.sqla.util.is_old_db() else 0);'
