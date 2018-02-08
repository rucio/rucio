#/usr/local/bin python
# Copyright 2014-2018 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

from rucio.api.account import add_account
from rucio.api.scope import add_scope
from rucio.api.did import add_did
from rucio.db.sqla.util import build_database, create_root_account

if __name__ == '__main__':
    build_database()
    create_root_account()

    add_account('jdoe', 'USER', 'test', 'root')
    
    add_scope('user.jdoe','jdoe', 'root')

    add_did('user.jdoe', 'test1', 'DATASET', 'root', account='jdoe')
