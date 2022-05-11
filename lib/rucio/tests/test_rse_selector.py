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

import unittest

import pytest

from rucio.common.config import config_get_bool
from rucio.common.exception import InsufficientAccountLimit, InsufficientTargetRSEs
from rucio.common.types import InternalAccount
from rucio.core.account_counter import update_account_counter, increase
from rucio.core.account_limit import set_local_account_limit, set_global_account_limit
from rucio.core.rse import get_rse_id
from rucio.core.rse_selector import RSESelector
from rucio.db.sqla import session, models
from rucio.tests.common_server import get_vo


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined rses, deletes database content on setUp and tearDownClass')
class TestRSESelectorInit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.account = InternalAccount('jdoe', **cls.vo)
        cls.rse_1_name = 'MOCK4'
        cls.rse_2_name = 'MOCK5'
        cls.mock1_id = get_rse_id(cls.rse_1_name, **cls.vo)
        cls.mock2_id = get_rse_id(cls.rse_2_name, **cls.vo)
        cls.db_session = session.get_session()
        cls.rse_1 = {'id': cls.mock1_id, 'staging_area': False}
        cls.rse_2 = {'id': cls.mock2_id, 'staging_area': False}

    def setUp(self):
        self.db_session.query(models.AccountUsage).delete()
        self.db_session.query(models.AccountLimit).delete()
        self.db_session.query(models.AccountGlobalLimit).delete()
        self.db_session.query(models.UpdatedAccountCounter).delete()
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.query(models.AccountUsage).delete()
        cls.db_session.query(models.AccountLimit).delete()
        cls.db_session.query(models.AccountGlobalLimit).delete()
        cls.db_session.query(models.UpdatedAccountCounter).delete()
        cls.db_session.commit()
        cls.db_session.close()

    def test_1(self):
        # more copies than RSEs -> error
        rses = [self.rse_1]
        copies = 2
        with pytest.raises(InsufficientTargetRSEs):
            RSESelector(self.account, rses, None, copies)

    def test_2(self):
        # local quota not enough -> error
        copies = 2
        rses = [self.rse_1, self.rse_2]
        set_local_account_limit(account=self.account, rse_id=self.mock1_id, bytes_=10)
        increase(self.mock1_id, self.account, 10, 10)
        update_account_counter(account=self.account, rse_id=self.mock1_id)
        with pytest.raises(InsufficientAccountLimit):
            RSESelector(self.account, rses, None, copies)

    def test_3(self):
        # global quota not enough -> error
        copies = 2
        rses = [self.rse_1, self.rse_2]
        set_local_account_limit(account=self.account, rse_id=self.mock1_id, bytes_=20)
        set_global_account_limit(account=self.account, rse_expression=self.rse_1_name, bytes_=10)
        increase(self.mock1_id, self.account, 10, 10)
        update_account_counter(account=self.account, rse_id=self.mock1_id)
        with pytest.raises(InsufficientAccountLimit):
            RSESelector(self.account, rses, None, copies)

    def test_4(self):
        # enough RSEs, local and global quota -> 2 RSEs
        set_global_account_limit(account=self.account, rse_expression=self.rse_1_name, bytes_=20)
        set_global_account_limit(account=self.account, rse_expression=self.rse_2_name, bytes_=20)
        set_local_account_limit(account=self.account, rse_id=self.mock1_id, bytes_=20)
        set_local_account_limit(account=self.account, rse_id=self.mock2_id, bytes_=20)
        copies = 2
        rses = [self.rse_1, self.rse_2]
        rse_selector = RSESelector(self.account, rses, None, copies)
        assert len(rse_selector.rses) == 2

    def test_5(self):
        # enough RSEs and local quota, but global quota missing -> 1 RSE
        copies = 1
        rses = [self.rse_1, self.rse_2]
        set_global_account_limit(account=self.account, rse_expression=self.rse_1_name, bytes_=10)
        increase(self.mock1_id, self.account, 10, 10)
        update_account_counter(account=self.account, rse_id=self.mock1_id)
        set_local_account_limit(account=self.account, rse_id=self.mock2_id, bytes_=20)
        set_local_account_limit(account=self.account, rse_id=self.mock1_id, bytes_=20)
        rse_selector = RSESelector(self.account, rses, None, copies)
        assert len(rse_selector.rses) == 1

    def test_6(self):
        # enough RSEs and global quota, but local quota missing -> 1 RSE
        rses = [self.rse_1, self.rse_2]
        copies = 1
        set_global_account_limit(account=self.account, rse_expression=self.rse_1_name, bytes_=10)
        set_local_account_limit(account=self.account, rse_id=self.mock1_id, bytes_=10)
        increase(self.mock1_id, self.account, 10, 10)
        update_account_counter(account=self.account, rse_id=self.mock1_id)
        set_local_account_limit(account=self.account, rse_id=self.mock2_id, bytes_=10)
        set_global_account_limit(account=self.account, rse_expression=self.rse_2_name, bytes_=10)
        rse_selector = RSESelector(self.account, rses, None, copies)
        assert len(rse_selector.rses) == 1


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined rses, deletes database content on setUp and tearDownClass')
class TestRSESelectorDynamic(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.account = InternalAccount('jdoe', **cls.vo)
        cls.rse_1_name = 'MOCK4'
        cls.rse_2_name = 'MOCK5'
        cls.mock1_id = get_rse_id(cls.rse_1_name, **cls.vo)
        cls.mock2_id = get_rse_id(cls.rse_2_name, **cls.vo)
        cls.db_session = session.get_session()
        cls.rse_1 = {'id': cls.mock1_id, 'staging_area': False}
        cls.rse_2 = {'id': cls.mock2_id, 'staging_area': False}

    def setUp(self):
        self.db_session.query(models.AccountUsage).delete()
        self.db_session.query(models.AccountLimit).delete()
        self.db_session.query(models.AccountGlobalLimit).delete()
        self.db_session.query(models.UpdatedAccountCounter).delete()
        self.db_session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db_session.query(models.AccountUsage).delete()
        cls.db_session.query(models.AccountLimit).delete()
        cls.db_session.query(models.AccountGlobalLimit).delete()
        cls.db_session.query(models.UpdatedAccountCounter).delete()
        cls.db_session.commit()
        cls.db_session.close()

    def test_1(self):
        # enough RSEs and global quota, but not enough local quota after change -> 1 RSE
        set_global_account_limit(account=self.account, rse_expression=self.rse_1_name, bytes_=20)
        set_global_account_limit(account=self.account, rse_expression=self.rse_2_name, bytes_=20)
        set_local_account_limit(account=self.account, rse_id=self.mock1_id, bytes_=10)
        set_local_account_limit(account=self.account, rse_id=self.mock2_id, bytes_=10)
        copies = 2
        rses = [self.rse_1, self.rse_2]
        rse_selector = RSESelector(self.account, rses, None, copies)
        assert len(rse_selector.rses) == 2
        rse_selector.select_rse(9, [self.mock1_id], copies=1)
        rses = rse_selector.select_rse(5, [], copies=1)
        assert len(rses) == 1
        assert rses[0][0] == self.mock2_id

    def test_2(self):
        # enough RSEs and global quota, but not enough global quota after change -> 1 RSE
        set_global_account_limit(account=self.account, rse_expression=self.rse_1_name, bytes_=10)
        set_global_account_limit(account=self.account, rse_expression=self.rse_2_name, bytes_=10)
        set_local_account_limit(account=self.account, rse_id=self.mock1_id, bytes_=20)
        set_local_account_limit(account=self.account, rse_id=self.mock2_id, bytes_=20)
        copies = 2
        rses = [self.rse_1, self.rse_2]
        rse_selector = RSESelector(self.account, rses, None, copies)
        assert len(rse_selector.rses) == 2
        rse_selector.select_rse(10, [self.mock1_id], copies=1)
        rses = rse_selector.select_rse(5, [], copies=1)
        assert len(rses) == 1
        assert rses[0][0] == self.mock2_id

    def test_3(self):
        # enough RSEs and global quota, also after after change -> 2 RSE
        set_global_account_limit(account=self.account, rse_expression=self.rse_1_name, bytes_=20)
        set_global_account_limit(account=self.account, rse_expression=self.rse_2_name, bytes_=20)
        set_local_account_limit(account=self.account, rse_id=self.mock1_id, bytes_=20)
        set_local_account_limit(account=self.account, rse_id=self.mock2_id, bytes_=20)
        copies = 2
        rses = [self.rse_1, self.rse_2]
        rse_selector = RSESelector(self.account, rses, None, copies)
        assert len(rse_selector.rses) == 2
        rse_selector.select_rse(10, [self.mock1_id], copies=1)
        rse_selector.select_rse(10, [self.mock2_id], copies=1)
        rses = rse_selector.select_rse(5, [], copies=2)
        assert len(rses) == 2
