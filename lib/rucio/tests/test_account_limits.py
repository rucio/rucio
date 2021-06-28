# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2015
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

import random
import string
import unittest

import pytest

from rucio.client.accountclient import AccountClient
from rucio.client.accountlimitclient import AccountLimitClient
from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount
from rucio.core import account_limit
from rucio.core.account import add_account
from rucio.core.rse import get_rse_id
from rucio.db.sqla import session, models
from rucio.db.sqla.constants import AccountType
from rucio.tests.common_server import get_vo


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp and tearDownClass')
class TestCoreAccountLimits(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
            cls.multi_vo = True
        else:
            cls.vo = {}
            cls.multi_vo = False

        # Add test account
        cls.account = InternalAccount(''.join(random.choice(string.ascii_uppercase) for x in range(10)), **cls.vo)
        add_account(account=cls.account, type=AccountType.USER, email='rucio@email.com')

        # Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse2 = 'MOCK2'

        cls.rse1_id = get_rse_id(rse=cls.rse1, **cls.vo)
        cls.rse2_id = get_rse_id(rse=cls.rse2, **cls.vo)

        cls.db_session = session.get_session()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.query(models.AccountLimit).delete()
        cls.db_session.query(models.AccountGlobalLimit).delete()
        cls.db_session.commit()
        cls.db_session.close()

    def setUp(self):
        self.db_session.query(models.AccountLimit).delete()
        self.db_session.query(models.AccountGlobalLimit).delete()
        self.db_session.commit()

    def test_local_account_limit(self):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete local account limit """
        account_limit.set_local_account_limit(account=self.account, rse_id=self.rse1_id, bytes=100000, session=self.db_session)
        assert account_limit.get_local_account_limit(account=self.account, rse_id=self.rse1_id, session=self.db_session) == 100000
        assert account_limit.get_local_account_limit(account=self.account, rse_id=self.rse2_id, session=self.db_session) is None
        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse1_id, session=self.db_session)
        assert account_limit.get_local_account_limit(account=self.account, rse_id=self.rse1_id, session=self.db_session) is None

    def test_global_account_limit(self):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete global account limit """
        account_limit.set_global_account_limit(self.account, 'MOCK', 200000, session=self.db_session)
        assert account_limit.get_global_account_limit(account=self.account, rse_expression='MOCK', session=self.db_session) == 200000
        assert account_limit.get_global_account_limit(account=self.account, rse_expression='MOCK2', session=self.db_session) is None
        account_limit.delete_global_account_limit(self.account, 'MOCK', session=self.db_session)
        assert account_limit.get_global_account_limit(account=self.account, rse_expression='MOCK', session=self.db_session) is None

    def test_global_account_limits(self):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete global account limits """
        resolved_rse_ids = [get_rse_id('MOCK', **self.vo)]
        resolved_rses = ['MOCK']
        limit = 10
        account_limit.set_global_account_limit(self.account, 'MOCK', limit, session=self.db_session)
        results = account_limit.get_global_account_limits(account=self.account, session=self.db_session)
        assert len(results) == 1
        assert 'MOCK' in results
        assert results['MOCK']['resolved_rses'] == resolved_rses
        assert results['MOCK']['resolved_rse_ids'] == resolved_rse_ids
        assert results['MOCK']['limit'] == limit
        account_limit.delete_global_account_limit(self.account, 'MOCK', session=self.db_session)
        results = account_limit.get_global_account_limits(account=self.account, session=self.db_session)
        assert len(results) == 0

    def test_get_global_account_usage(self):
        """ ACCOUNT_LIMIT (CORE): Get global account usage. """
        limit1 = 10
        limit2 = 20
        account_limit.set_global_account_limit(self.account, 'MOCK|MOCK2', limit1)
        account_limit.set_global_account_limit(self.account, 'MOCK4|MOCK3', limit2)
        results = account_limit.get_global_account_usage(account=self.account)
        assert len(results) == 2

        results = account_limit.get_global_account_usage(account=self.account, rse_expression='MOCK|MOCK2')
        assert len(results) == 1

    def test_local_account_limits(self):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete local account limits """
        limit1 = 100
        limit2 = 200
        account_limit.set_local_account_limit(account=self.account, rse_id=self.rse1_id, bytes=limit1, session=self.db_session)
        account_limit.set_local_account_limit(account=self.account, rse_id=self.rse2_id, bytes=limit2, session=self.db_session)
        results = account_limit.get_local_account_limits(account=self.account, session=self.db_session)
        assert len(results) == 2
        assert results[self.rse1_id] == limit1
        assert results[self.rse2_id] == limit2
        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse1_id, session=self.db_session)
        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse2_id, session=self.db_session)
        results = account_limit.get_local_account_limits(account=self.account, session=self.db_session)
        assert len(results) == 0


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp and tearDownClass')
class TestAccountClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
            cls.multi_vo = True
        else:
            cls.vo = {}
            cls.multi_vo = False

        # Add test account
        cls.account = InternalAccount(''.join(random.choice(string.ascii_uppercase) for x in range(10)), **cls.vo)
        add_account(account=cls.account, type=AccountType.USER, email='rucio@email.com')

        # Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse2 = 'MOCK2'

        cls.rse1_id = get_rse_id(rse=cls.rse1, **cls.vo)
        cls.rse2_id = get_rse_id(rse=cls.rse2, **cls.vo)

        cls.db_session = session.get_session()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.query(models.AccountLimit).delete()
        cls.db_session.query(models.AccountGlobalLimit).delete()
        cls.db_session.commit()
        cls.db_session.close()

    def setUp(self):
        self.client = AccountClient()
        self.alclient = AccountLimitClient()
        self.db_session.query(models.AccountLimit).delete()
        self.db_session.query(models.AccountGlobalLimit).delete()
        self.db_session.commit()

    def test_set_global_account_limit(self):
        """ ACCOUNT_LIMIT (CLIENTS): Set global account limit """
        self.alclient.set_global_account_limit(self.account.external, 'MOCK', 200000)
        assert account_limit.get_global_account_limit(account=self.account, rse_expression='MOCK') == 200000
        assert account_limit.get_global_account_limit(account=self.account, rse_expression='MOCK2') is None

    def test_get_global_account_limits(self):
        """ ACCOUNT_LIMIT (CLIENTS): Get global account limits """
        expression = 'MOCK'
        resolved_rses = ['MOCK']
        resolved_rse_ids = [get_rse_id('MOCK', **self.vo)]
        limit = 10
        account_limit.set_global_account_limit(self.account, expression, limit)
        results = self.client.get_global_account_limits(account=self.account.external)
        assert len(results) == 1
        assert results[expression]['resolved_rses'] == resolved_rses
        assert results[expression]['resolved_rse_ids'] == resolved_rse_ids
        assert results[expression]['limit'] == limit

    def test_get_global_account_limit(self):
        """ ACCOUNT_LIMIT (CLIENTS): Get global account limit. """
        expression = 'MOCK'
        limit = 10
        account_limit.set_global_account_limit(self.account, expression, limit)
        result = self.client.get_global_account_limit(account=self.account.external, rse_expression=expression)
        assert result[expression] == limit

    def test_get_local_account_limits(self):
        """ ACCOUNT_LIMIT (CLIENTS): Get local account limits """
        account_limit.set_local_account_limit(account=self.account, rse_id=self.rse1_id, bytes=12345)
        account_limit.set_local_account_limit(account=self.account, rse_id=self.rse2_id, bytes=12345)

        limits = self.client.get_local_account_limits(account=self.account.external)

        assert (self.rse1, 12345) in limits.items()
        assert (self.rse2, 12345) in limits.items()

        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse1_id)
        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse2_id)

    def test_get_local_account_limit(self):
        """ ACCOUNT_LIMIT (CLIENTS): Get local account limit """
        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse1_id)
        account_limit.set_local_account_limit(account=self.account, rse_id=self.rse1_id, bytes=333)

        limit = self.client.get_local_account_limit(account=self.account.external, rse=self.rse1)

        assert limit == {self.rse1: 333}
        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse1_id)

    def test_set_local_account_limit(self):
        """ ACCOUNTLIMIT (CLIENTS): Set local account limit """
        self.alclient.set_local_account_limit(account=self.account.external, rse=self.rse1, bytes=987)

        limit = self.client.get_local_account_limit(account=self.account.external, rse=self.rse1)

        assert limit[self.rse1] == 987
        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse1_id)

    def test_delete_local_account_limit(self):
        """ ACCOUNTLIMIT (CLIENTS): Delete local account limit """
        self.alclient.set_local_account_limit(account=self.account.external, rse=self.rse1, bytes=786)

        limit = self.client.get_local_account_limit(account=self.account.external, rse=self.rse1)
        assert limit == {self.rse1: 786}

        self.alclient.delete_local_account_limit(account=self.account.external, rse=self.rse1)
        limit = self.client.get_local_account_limit(account=self.account.external, rse=self.rse1)
        assert limit[self.rse1] is None
        account_limit.delete_local_account_limit(account=self.account, rse_id=self.rse1_id)

    def test_delete_global_account_limit(self):
        """ ACCOUNTLIMIT (CLIENTS): Delete global account limit """
        rse_exp = 'MOCK'
        account_limit.set_global_account_limit(account=self.account, rse_expression=rse_exp, bytes=10, session=self.db_session)
        self.alclient.delete_global_account_limit(account=self.account.external, rse_expression=rse_exp)
        result = account_limit.get_global_account_limit(account=self.account, rse_expression=rse_exp)
        assert result is None
