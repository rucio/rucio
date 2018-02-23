#!/usr/bin/env python
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2018

import os

from rucio.api.account import add_account
from rucio.api.identity import add_account_identity
from rucio.api.scope import add_scope
from rucio.api.did import add_did
from rucio.api.rse import add_rse
from rucio.db.sqla.util import build_database, create_root_account
from rucio.core.account_limit import set_account_limit
from rucio.core.rse import add_protocol, get_rse_id, add_rse_attribute

if __name__ == '__main__':
    # Create the Database and the root account
    build_database()
    create_root_account()
    add_account_identity('/CN=docker client', 'x509', 'root', 'test@rucio.com', issuer="root")

    # Create a user called jdoe
    add_account('jdoe', 'USER', 'test', 'root')

    # Add 2 scopes
    add_scope('user.jdoe', 'jdoe', 'root')
    add_scope('tests', 'root', 'root')

    # Create a test dataset for jdoe
    add_did('user.jdoe', 'test1', 'DATASET', 'root', account='jdoe')

    # Create 2 sites into the /tmp partition
    os.mkdir('/tmp/SITE2_DISK')
    os.mkdir('/tmp/SITE1_DISK')

    params = {'scheme': 'file',
              'prefix': '/tmp/SITE1_DISK/',
              'impl': 'rucio.rse.protocols.posix.Default',
              'domains': {"lan": {"read": 1,
                                  "write": 1,
                                  "delete": 1},
                          "wan": {"read": 1,
                                  "write": 1,
                                  "delete": 1}}}

    add_rse('SITE1_DISK', 'root')
    add_protocol('SITE1_DISK', params)
    add_rse_attribute(rse='SITE1_DISK', key='istape', value='False')

    params = {'scheme': 'file',
              'prefix': '/tmp/SITE2_DISK/',
              'impl': 'rucio.rse.protocols.posix.Default',
              'domains': {"lan": {"read": 1,
                                  "write": 1,
                                  "delete": 1},
                          "wan": {"read": 1,
                                  "write": 1,
                                  "delete": 1}}}

    add_rse('SITE2_DISK', 'root')
    add_protocol('SITE2_DISK', params)
    add_rse_attribute(rse='SITE2_DISK', key='istape', value='False')

    # Now set a quota for root and jdoe on the 2 RSEs
    set_account_limit('root', get_rse_id('SITE1_DISK'), 100000000000)
    set_account_limit('root', get_rse_id('SITE2_DISK'), 100000000000)
    set_account_limit('jdoe', get_rse_id('SITE1_DISK'), 1000000000)
    set_account_limit('jdoe', get_rse_id('SITE2_DISK'), 0)
