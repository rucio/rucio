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

import random
import string

import pytest

from rucio.common.types import InternalAccount
from rucio.core import account_limit
from rucio.core.account import add_account, del_account
from rucio.core.rse import get_rse_id
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountType


@pytest.fixture
def db_session(db_session):
    db_session.query(models.AccountLimit).delete()
    db_session.query(models.AccountGlobalLimit).delete()
    db_session.commit()
    yield db_session
    db_session.query(models.AccountLimit).delete()
    db_session.query(models.AccountGlobalLimit).delete()
    db_session.commit()


@pytest.fixture(scope='class')
def account(vo):
    account = InternalAccount(''.join(random.choice(string.ascii_uppercase) for _ in range(10)), vo=vo)
    add_account(account=account, type_=AccountType.USER, email='rucio@email.com')
    yield account
    del_account(account)


@pytest.fixture(scope='class')
def rse1():
    return 'MOCK'


@pytest.fixture(scope='class')
def rse2():
    return 'MOCK2'


@pytest.fixture(scope='class')
def rse1_id(rse1, vo):
    return get_rse_id(rse=rse1, vo=vo)


@pytest.fixture(scope='class')
def rse2_id(rse2, vo):
    return get_rse_id(rse=rse2, vo=vo)


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp and tearDownClass')
class TestCoreAccountLimits:

    def test_local_account_limit(self, db_session, account, rse1_id, rse2_id):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete local account limit """

        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=100000, session=db_session)
        assert account_limit.get_local_account_limit(account=account, rse_id=rse1_id, session=db_session) == 100000
        assert account_limit.get_local_account_limit(account=account, rse_id=rse2_id, session=db_session) is None
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)
        assert account_limit.get_local_account_limit(account=account, rse_id=rse1_id, session=db_session) is None

    def test_global_account_limit(self, db_session, account, rse1, rse2):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete global account limit """
        account_limit.set_global_account_limit(account, rse1, 200000, session=db_session)
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse1, session=db_session) == 200000
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse2, session=db_session) is None
        account_limit.delete_global_account_limit(account, rse1, session=db_session)
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse1, session=db_session) is None

    def test_global_account_limits(self, db_session, account, rse1, rse1_id):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete global account limits """
        resolved_rse_ids = [rse1_id]
        resolved_rses = [rse1]
        limit = 10
        account_limit.set_global_account_limit(account, rse1, limit, session=db_session)
        results = account_limit.get_global_account_limits(account=account, session=db_session)
        assert len(results) == 1
        assert rse1 in results
        assert results[rse1]['resolved_rses'] == resolved_rses
        assert results[rse1]['resolved_rse_ids'] == resolved_rse_ids
        assert results[rse1]['limit'] == limit
        account_limit.delete_global_account_limit(account, rse1, session=db_session)
        results = account_limit.get_global_account_limits(account=account, session=db_session)
        assert len(results) == 0

    def test_get_global_account_usage(self, account, rse1, rse2):
        """ ACCOUNT_LIMIT (CORE): Get global account usage. """
        limit1 = 10
        limit2 = 20
        account_limit.set_global_account_limit(account, f'{rse1}|{rse2}', limit1)
        account_limit.set_global_account_limit(account, 'MOCK4|MOCK3', limit2)
        results = account_limit.get_global_account_usage(account=account)
        assert len(results) == 2

        results = account_limit.get_global_account_usage(account=account, rse_expression=f'{rse1}|{rse2}')
        assert len(results) == 1

    def test_local_account_limits(self, db_session, account, rse1_id, rse2_id):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete local account limits """
        limit1 = 100
        limit2 = 200
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=limit1, session=db_session)
        account_limit.set_local_account_limit(account=account, rse_id=rse2_id, bytes_=limit2, session=db_session)
        results = account_limit.get_local_account_limits(account=account, session=db_session)
        assert len(results) == 2
        assert results[rse1_id] == limit1
        assert results[rse2_id] == limit2
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)
        account_limit.delete_local_account_limit(account=account, rse_id=rse2_id, session=db_session)
        results = account_limit.get_local_account_limits(account=account, session=db_session)
        assert len(results) == 0


@pytest.mark.dirty
@pytest.mark.noparallel(reason='deletes database content on setUp and tearDownClass')
class TestAccountClient:

    def test_set_global_account_limit(self, account, rucio_client, rse1, rse2):
        """ ACCOUNT_LIMIT (CLIENTS): Set global account limit """
        rucio_client.set_global_account_limit(account.external, rse1, 200000)
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse1) == 200000
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse2) is None

    def test_get_global_account_limits(self, account, rucio_client, rse1, rse1_id):
        """ ACCOUNT_LIMIT (CLIENTS): Get global account limits """
        expression = rse1
        resolved_rses = [rse1]
        resolved_rse_ids = [rse1_id]
        limit = 10
        account_limit.set_global_account_limit(account, expression, limit)
        results = rucio_client.get_global_account_limits(account=account.external)
        assert len(results) == 1
        assert results[expression]['resolved_rses'] == resolved_rses
        assert results[expression]['resolved_rse_ids'] == resolved_rse_ids
        assert results[expression]['limit'] == limit

    def test_get_global_account_limit(self, account, rucio_client, rse1):
        """ ACCOUNT_LIMIT (CLIENTS): Get global account limit. """
        expression = rse1
        limit = 10
        account_limit.set_global_account_limit(account, expression, limit)
        result = rucio_client.get_global_account_limit(account=account.external, rse_expression=expression)
        assert result[expression] == limit

    def test_get_local_account_limits(self, account, rucio_client, rse1, rse1_id, rse2, rse2_id):
        """ ACCOUNT_LIMIT (CLIENTS): Get local account limits """
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=12345)
        account_limit.set_local_account_limit(account=account, rse_id=rse2_id, bytes_=12345)

        limits = rucio_client.get_local_account_limits(account=account.external)

        assert (rse1, 12345) in limits.items()
        assert (rse2, 12345) in limits.items()

        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)
        account_limit.delete_local_account_limit(account=account, rse_id=rse2_id)

    def test_get_local_account_limit(self, account, rucio_client, rse1, rse1_id):
        """ ACCOUNT_LIMIT (CLIENTS): Get local account limit """
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=333)

        limit = rucio_client.get_local_account_limit(account=account.external, rse=rse1)

        assert limit == {rse1: 333}
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)

    def test_set_local_account_limit(self, account, rucio_client, rse1, rse1_id):
        """ ACCOUNTLIMIT (CLIENTS): Set local account limit """
        rucio_client.set_local_account_limit(account=account.external, rse=rse1, bytes_=987)

        limit = rucio_client.get_local_account_limit(account=account.external, rse=rse1)

        assert limit[rse1] == 987
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)

    def test_delete_local_account_limit(self, account, rucio_client, rse1, rse1_id):
        """ ACCOUNTLIMIT (CLIENTS): Delete local account limit """
        rucio_client.set_local_account_limit(account=account.external, rse=rse1, bytes_=786)

        limit = rucio_client.get_local_account_limit(account=account.external, rse=rse1)
        assert limit == {rse1: 786}

        rucio_client.delete_local_account_limit(account=account.external, rse=rse1)
        limit = rucio_client.get_local_account_limit(account=account.external, rse=rse1)
        assert limit[rse1] is None
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)

    def test_delete_global_account_limit(self, db_session, account, rucio_client, rse1):
        """ ACCOUNTLIMIT (CLIENTS): Delete global account limit """
        rse_exp = rse1
        account_limit.set_global_account_limit(account=account, rse_expression=rse_exp, bytes_=10, session=db_session)
        rucio_client.delete_global_account_limit(account=account.external, rse_expression=rse_exp)
        result = account_limit.get_global_account_limit(account=account, rse_expression=rse_exp)
        assert result is None
