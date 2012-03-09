# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann,  <thomas.beermann@cern.ch> , 2012


import datetime
import random
import logging
import unittest

from nose.tools import *

from rucio.db import api
from rucio.common import exception


logger = logging.getLogger('rucio.test.test_account')
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)


class TestAccountApi(unittest.TestCase):

    """
    Test cases for the account api
    """

    def setUp(self):
        super(TestAccountApi, self).setUp()
        api.configure_db()

    def testCreateAccount(self):
        """
        tests that newly created accounts are added correctly to the database
        """
        test_accounts = []
        test_accounts.append(('tbeerman', 'user'))
        test_accounts.append(('vgaronne', 'user'))
        test_accounts.append(('mlassnig', 'user'))

        for account in test_accounts:
            api.create_account(account[0], account[1])

        for account in test_accounts:
            test_account = api.get_account(account[0])
            self.assertEquals(account[0], test_account.account)
            self.assertEquals(account[1], test_account.type)

    @raises(exception.Duplicate)
    def testDuplicateException(self):
        """
        tests if DuplicateException is correctly thrown when adding an already existing account
        """
        account = api.list_accounts()[0]

        api.create_account(account.account, account.type)

    @raises(exception.NotFound)
    def testNotFoundException(self):
        """
        tests if NotFoundException is correclty thrown when querying for a not existing account
        """
        api.get_account('some_random_account')

    def tearDown(self):
        """Clear the test environment"""
        super(TestAccountApi, self).tearDown()
