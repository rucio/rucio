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

import pytest
from rucio.core import account_limit


@pytest.fixture
def account(random_account):
    yield random_account


class TestCoreAccountLimits:

    def test_local_account_limit(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete local account limit """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=100000, session=db_session)
        assert account_limit.get_local_account_limit(account=account, rse_id=rse1_id, session=db_session) == 100000
        assert account_limit.get_local_account_limit(account=account, rse_id=rse2_id, session=db_session) is None
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)
        assert account_limit.get_local_account_limit(account=account, rse_id=rse1_id, session=db_session) is None

    def test_global_account_limit(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete global account limit """
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        account_limit.set_global_account_limit(account, rse1, 200000, session=db_session)
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse1, session=db_session) == 200000
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse2, session=db_session) is None
        account_limit.delete_global_account_limit(account, rse1, session=db_session)
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse1, session=db_session) is None

    def test_global_account_limits(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete global account limits """
        rse1, rse1_id = rse_factory.make_mock_rse()
        limit = 10
        account_limit.set_global_account_limit(account, rse1, limit, session=db_session)
        results = account_limit.get_global_account_limits(account=account, session=db_session)
        assert len(results) == 1
        assert rse1 in results
        assert results[rse1]['resolved_rses'] == [rse1]
        assert results[rse1]['resolved_rse_ids'] == [rse1_id]
        assert results[rse1]['limit'] == limit
        account_limit.delete_global_account_limit(account, rse1, session=db_session)
        results = account_limit.get_global_account_limits(account=account, session=db_session)
        assert len(results) == 0

    def test_get_global_account_usage(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Get global account usage. """
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse3, _ = rse_factory.make_mock_rse()
        rse4, _ = rse_factory.make_mock_rse()
        limit1 = 10
        limit2 = 20
        account_limit.set_global_account_limit(account, f'{rse1}|{rse2}', limit1, session=db_session)
        account_limit.set_global_account_limit(account, f'{rse3}|{rse4}', limit2, session=db_session)
        results = account_limit.get_global_account_usage(account=account, session=db_session)
        assert len(results) == 2

        results = account_limit.get_global_account_usage(account=account, rse_expression=f'{rse1}|{rse2}', session=db_session)
        assert len(results) == 1

    def test_local_account_limits(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete local account limits """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()
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


class TestAccountClient:

    def test_set_global_account_limit(self, account, rucio_client, rse_factory):
        """ ACCOUNT_LIMIT (CLIENTS): Set global account limit """
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rucio_client.set_global_account_limit(account.external, rse1, 200000)
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse1) == 200000
        assert account_limit.get_global_account_limit(account=account, rse_expression=rse2) is None

    def test_get_global_account_limits(self, account, rucio_client, rse_factory):
        """ ACCOUNT_LIMIT (CLIENTS): Get global account limits """
        rse1, rse1_id = rse_factory.make_mock_rse()
        limit = 10
        account_limit.set_global_account_limit(account, rse1, limit)
        results = rucio_client.get_global_account_limits(account=account.external)
        assert len(results) == 1
        assert results[rse1]['resolved_rses'] == [rse1]
        assert results[rse1]['resolved_rse_ids'] == [rse1_id]
        assert results[rse1]['limit'] == limit

    def test_get_global_account_limit(self, account, rucio_client, rse_factory):
        """ ACCOUNT_LIMIT (CLIENTS): Get global account limit. """
        rse1, _ = rse_factory.make_mock_rse()
        limit = 10
        account_limit.set_global_account_limit(account, rse1, limit)
        result = rucio_client.get_global_account_limit(account=account.external, rse_expression=rse1)
        assert result[rse1] == limit

    def test_get_local_account_limits(self, account, rucio_client, rse_factory):
        """ ACCOUNT_LIMIT (CLIENTS): Get local account limits """
        rse1, rse1_id = rse_factory.make_mock_rse()
        rse2, rse2_id = rse_factory.make_mock_rse()
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=12345)
        account_limit.set_local_account_limit(account=account, rse_id=rse2_id, bytes_=12345)

        limits = rucio_client.get_local_account_limits(account=account.external)

        assert (rse1, 12345) in limits.items()
        assert (rse2, 12345) in limits.items()

        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)
        account_limit.delete_local_account_limit(account=account, rse_id=rse2_id)

    def test_get_local_account_limit(self, account, rucio_client, rse_factory):
        """ ACCOUNT_LIMIT (CLIENTS): Get local account limit """
        rse1, rse1_id = rse_factory.make_mock_rse()
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=333)

        limit = rucio_client.get_local_account_limit(account=account.external, rse=rse1)

        assert limit == {rse1: 333}
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)

    def test_set_local_account_limit(self, account, rucio_client, rse_factory):
        """ ACCOUNTLIMIT (CLIENTS): Set local account limit """
        rse1, rse1_id = rse_factory.make_mock_rse()
        rucio_client.set_local_account_limit(account=account.external, rse=rse1, bytes_=987)

        limit = rucio_client.get_local_account_limit(account=account.external, rse=rse1)

        assert limit[rse1] == 987
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)

    def test_delete_local_account_limit(self, account, rucio_client, rse_factory):
        """ ACCOUNTLIMIT (CLIENTS): Delete local account limit """
        rse1, rse1_id = rse_factory.make_mock_rse()
        rucio_client.set_local_account_limit(account=account.external, rse=rse1, bytes_=786)

        limit = rucio_client.get_local_account_limit(account=account.external, rse=rse1)
        assert limit == {rse1: 786}

        rucio_client.delete_local_account_limit(account=account.external, rse=rse1)
        limit = rucio_client.get_local_account_limit(account=account.external, rse=rse1)
        assert limit[rse1] is None
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id)

    def test_delete_global_account_limit(self, account, rucio_client, rse_factory, db_session):
        """ ACCOUNTLIMIT (CLIENTS): Delete global account limit """
        rse1, rse1_id = rse_factory.make_mock_rse()
        account_limit.set_global_account_limit(account=account, rse_expression=rse1, bytes_=10, session=db_session)
        rucio_client.delete_global_account_limit(account=account.external, rse_expression=rse1)
        result = account_limit.get_global_account_limit(account=account, rse_expression=rse1)
        assert result is None
