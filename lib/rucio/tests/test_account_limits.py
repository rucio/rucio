# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014-2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015

import string
import random

from nose.tools import assert_equal, assert_in

from rucio.client.accountclient import AccountClient
from rucio.client.accountlimitclient import AccountLimitClient
from rucio.core import account_limit
from rucio.core.account import add_account
from rucio.core.rse import get_rse
from rucio.db.sqla.constants import AccountType


class TestCoreAccountLimits():

    @classmethod
    def setUpClass(cls):
        # Add test account
        cls.account = ''.join(random.choice(string.ascii_uppercase) for x in range(10))
        add_account(account=cls.account, type=AccountType.USER, email='rucio@email.com')

        # Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse2 = 'MOCK2'

        cls.rse1_id = get_rse(cls.rse1).id
        cls.rse2_id = get_rse(cls.rse2).id

    def test_set_account_limit(self):
        """ ACCOUNT_LIMIT (CORE): Setting account limit """
        account_limit.set_account_limit(account=self.account, rse_id=self.rse1_id, bytes=100000)

        assert_equal(account_limit.get_account_limit(account=self.account, rse_id=self.rse1_id), 100000)
        assert_equal(account_limit.get_account_limit(account=self.account, rse_id=self.rse2_id), None)


class TestAccountClient():

    @classmethod
    def setUpClass(cls):
        # Add test account
        cls.account = ''.join(random.choice(string.ascii_uppercase) for x in range(10))
        add_account(account=cls.account, type=AccountType.USER, email='rucio@email.com')

        # Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse2 = 'MOCK2'

        cls.rse1_id = get_rse(cls.rse1).id
        cls.rse2_id = get_rse(cls.rse2).id

    def setup(self):
        self.client = AccountClient()
        self.alclient = AccountLimitClient()

    def test_listing_account_limits(self):
        """ ACCOUNT (CLIENTS): Test listing account limits """
        account_limit.set_account_limit(account=self.account, rse_id=self.rse1_id, bytes=12345)
        account_limit.set_account_limit(account=self.account, rse_id=self.rse2_id, bytes=12345)

        limits = self.client.get_account_limits(account=self.account)

        assert_in((self.rse1, 12345), limits.items())
        assert_in((self.rse2, 12345), limits.items())

        account_limit.delete_account_limit(account=self.account, rse_id=self.rse1_id)
        account_limit.delete_account_limit(account=self.account, rse_id=self.rse2_id)

    def test_listing_account_limit(self):
        """ ACCOUNT (CLIENTS): Test listing account limit """
        account_limit.delete_account_limit(account=self.account, rse_id=self.rse1_id)
        account_limit.set_account_limit(account=self.account, rse_id=self.rse1_id, bytes=333)

        limit = self.client.get_account_limit(account=self.account, rse=self.rse1)

        assert_equal(limit, {self.rse1: 333})
        account_limit.delete_account_limit(account=self.account, rse_id=self.rse1_id)

    def test_setting_account_limit(self):
        """ ACCOUNTLIMIT (CLIENTS): Test setting account limit """
        self.alclient.set_account_limit(account=self.account, rse=self.rse1, bytes=987)

        limit = self.client.get_account_limit(account=self.account, rse=self.rse1)

        assert_equal(limit[self.rse1], 987)
        account_limit.delete_account_limit(account=self.account, rse_id=self.rse1_id)

    def test_deleting_account_limit(self):
        """ ACCOUNTLIMIT (CLIENTS): Test deleting account limit """
        self.alclient.set_account_limit(account=self.account, rse=self.rse1, bytes=786)

        limit = self.client.get_account_limit(account=self.account, rse=self.rse1)
        assert_equal(limit, {self.rse1: 786})

        self.alclient.delete_account_limit(account=self.account, rse=self.rse1)
        limit = self.client.get_account_limit(account=self.account, rse=self.rse1)
        assert_equal(limit[self.rse1], None)
        account_limit.delete_account_limit(account=self.account, rse_id=self.rse1_id)
