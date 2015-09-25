#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne,  <vincent.garonne@cern.ch>, 2013

# Run this once to set up the database.
#   PYTHONPATH=/opt/rucio/.venv/lib/python2.7/site-packages/rucio python tools/bootstrap.py
#
# Verify for default SQLite:
#   for i in `sqlite3 /tmp/rucio.db ".tables"`; do echo $i:; sqlite3 /tmp/rucio.db "select * from $i"; echo; done

from rucio.db.sqla.util import build_database, create_root_account

if __name__ == '__main__':
    build_database()
    create_root_account()
