# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2012

from nose.tools import assert_true, assert_false

from rucio.api.permission import has_permission
from rucio.db.session import build_database, destroy_database, create_root_account
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account


class TestPermissionCoreApi():

    def setUp(self):
        build_database()
        create_root_account()
        self.usr = str(uuid())
        add_account(self.usr, 'user')

    def tearDown(self):
        destroy_database()

    def test_permission_add_account(self):
        """ PERMISSION(CORE): Check permission to add account """
        assert_true(has_permission(accountName='root', action='add_account', kwargs={'accountName': 'account1'}))
        assert_false(has_permission(accountName='self.usr', action='add_account', kwargs={'accountName': 'account1'}))

    def test_permission_add_scope(self):
        """ PERMISSION(CORE): Check permission to add scope """
        assert_true(has_permission(accountName='root', action='add_scope', kwargs={'accountName': 'account1'}))
        assert_false(has_permission(accountName=self.usr, action='add_scope', kwargs={'accountName': 'root'}))
        assert_true(has_permission(accountName=self.usr, action='add_scope', kwargs={'accountName': self.usr}))
