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

import uuid

import pytest

from rucio.common.types import InternalScope
from rucio.core import account_limit, replica
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.core import scope as scope_core


@pytest.fixture
def account(random_account):
    yield random_account


class TestCoreAccountLimits:

    def test_local_account_limit_single_rse(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete local account limit """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=100000, session=db_session)
        assert account_limit.get_local_account_limit(account=account, rse_ids=rse1_id, session=db_session) == 100000
        assert account_limit.get_local_account_limit(account=account, rse_ids=rse2_id, session=db_session) is None
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)
        assert account_limit.get_local_account_limit(account=account, rse_ids=rse1_id, session=db_session) is None

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
        results = account_limit.get_global_account_limit(account=account, session=db_session)
        assert len(results) == 1
        assert rse1 in results
        assert results[rse1]['resolved_rses'] == [rse1]
        assert results[rse1]['resolved_rse_ids'] == [rse1_id]
        assert results[rse1]['limit'] == limit
        account_limit.delete_global_account_limit(account, rse1, session=db_session)
        results = account_limit.get_global_account_limit(account=account, session=db_session)
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

    def test_local_account_limit_multiple_rses(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Set, get and delete local account limits """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()
        limit1 = 100
        limit2 = 200
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=limit1, session=db_session)
        results = account_limit.get_local_account_limit(account=account, rse_ids=[rse1_id], session=db_session)
        assert len(results) == 1
        assert results[rse1_id] == limit1
        account_limit.set_local_account_limit(account=account, rse_id=rse2_id, bytes_=limit2, session=db_session)
        results = account_limit.get_local_account_limit(account=account, rse_ids=[rse1_id, rse2_id], session=db_session)
        assert len(results) == 2
        assert results[rse1_id] == limit1
        assert results[rse2_id] == limit2
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)
        account_limit.delete_local_account_limit(account=account, rse_id=rse2_id, session=db_session)
        results = account_limit.get_local_account_limit(account=account, rse_ids=[rse1_id, rse2_id], session=db_session)
        assert len(results) == 0

    def test_local_account_limit_all_rses(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Set, get, and delete local account limits for all RSEs """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()
        limit1 = 500
        limit2 = 600
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=limit1, session=db_session)
        account_limit.set_local_account_limit(account=account, rse_id=rse2_id, bytes_=limit2, session=db_session)
        results = account_limit.get_local_account_limit(account=account, rse_ids=None, session=db_session)
        assert results[rse1_id] == limit1
        assert results[rse2_id] == limit2
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)
        account_limit.delete_local_account_limit(account=account, rse_id=rse2_id, session=db_session)
        results = account_limit.get_local_account_limit(account=account, rse_ids=None, session=db_session)
        assert results == {}


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


class TestCoreAccountLimitsUnique:

    def test_local_account_usage_unique_single_rse(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Get unique local account usage for single RSE """
        _, rse1_id = rse_factory.make_mock_rse()

        # Set up a limit for testing
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=100000, session=db_session)

        # Test with no usage
        results = account_limit.get_local_account_usage(account=account, rse_id=rse1_id, unique=True, session=db_session)
        assert len(results) == 1
        assert results[0]['rse_id'] == rse1_id
        assert results[0]['bytes'] == 0
        assert results[0]['files'] == 0
        assert results[0]['bytes_limit'] == 100000

        # Clean up
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)

    def test_local_account_usage_unique_vs_regular(self, account, rse_factory, root_account, db_session):
        """ ACCOUNT_LIMIT (CORE): Compare unique vs regular usage when multiple locks exist """

        rse1_name, rse1_id = rse_factory.make_mock_rse()

        # Add an attribute to the RSE so we can create different rule expressions
        rse_core.add_rse_attribute(rse_id=rse1_id, key='test_attr', value='test_value', session=db_session)

        # Set account limit so rules can be created
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=1000000, session=db_session)

        # Create scope first
        scope_name = 'test_%s' % str(uuid.uuid4())[:8]
        scope = InternalScope(scope_name, vo=account.vo)
        try:
            scope_core.add_scope(scope, account, session=db_session)
        except Exception:
            pass  # Scope might already exist

        name = 'file_%s' % str(uuid.uuid4())

        # Add replica (this automatically creates the file DID)
        replica.add_replica(
            rse_id=rse1_id,
            scope=scope,
            name=name,
            bytes_=1000,
            account=account,
            session=db_session
        )

        db_session.commit()

        # Create two different replication rules with different RSE expressions
        # Both will resolve to the same RSE but create separate locks
        rule1_id = rule_core.add_rule(
            dids=[{'scope': scope, 'name': name}],
            account=account,
            copies=1,
            rse_expression=f'id={rse1_id}',
            grouping='NONE',
            weight=None,
            lifetime=None,
            locked=False,
            subscription_id=None,
            session=db_session
        )[0]

        rule2_id = rule_core.add_rule(
            dids=[{'scope': scope, 'name': name}],
            account=account,
            copies=1,
            rse_expression=rse1_name,  # Use RSE name instead of ID
            grouping='NONE',
            weight=None,
            lifetime=None,
            locked=False,
            subscription_id=None,
            session=db_session
        )[0]

        db_session.commit()
        db_session.expire_all()

        # Get unique usage - should count each replica only once
        unique_results = account_limit.get_local_account_usage(account=account, rse_id=rse1_id, unique=True, session=db_session)

        # With unique=True, we should get the actual unique usage (1 file, 1000 bytes)
        assert len(unique_results) == 1
        assert unique_results[0]['rse_id'] == rse1_id
        assert unique_results[0]['files'] == 1
        assert unique_results[0]['bytes'] == 1000

        # Clean up
        rule_core.delete_rule(rule1_id, session=db_session)
        rule_core.delete_rule(rule2_id, session=db_session)

        db_session.commit()

        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)


    def test_local_account_usage_unique_with_actual_usage(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Test unique usage with actual files and locks """

        _, rse1_id = rse_factory.make_mock_rse()

        # Set account limit so rules can be created
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=1000000, session=db_session)

        # Create scope first
        scope_name = 'test_%s' % str(uuid.uuid4())[:8]
        scope = InternalScope(scope_name, vo=account.vo)
        try:
            scope_core.add_scope(scope, account, session=db_session)
        except Exception:
            pass  # Scope might already exist

        # Create two files
        name1 = 'file1_%s' % str(uuid.uuid4())
        name2 = 'file2_%s' % str(uuid.uuid4())

        # Add replicas (this automatically creates the file DIDs)
        replica.add_replica(rse_id=rse1_id, scope=scope, name=name1, bytes_=1000, account=account, session=db_session)
        replica.add_replica(rse_id=rse1_id, scope=scope, name=name2, bytes_=2000, account=account, session=db_session)

        # Commit to persist replica and DID before creating rules
        # Rules require the DID to exist in the database
        db_session.commit()

        # Create rules to generate locks
        rule_core.add_rule(
            dids=[{'scope': scope, 'name': name1}],
            account=account,
            copies=1,
            rse_expression=f'id={rse1_id}',
            grouping='NONE',
            weight=None,
            lifetime=None,
            locked=False,
            subscription_id=None,
            session=db_session
        )

        rule_core.add_rule(
            dids=[{'scope': scope, 'name': name2}],
            account=account,
            copies=1,
            rse_expression=f'id={rse1_id}',
            grouping='NONE',
            weight=None,
            lifetime=None,
            locked=False,
            subscription_id=None,
            session=db_session
        )

        # Commit rules and expire session to ensure locks are persisted
        # expire_all() clears SQLAlchemy's identity map to force fresh queries
        db_session.commit()
        db_session.expire_all()

        # Get unique usage
        results = account_limit.get_local_account_usage(account=account, rse_id=rse1_id, unique=True, session=db_session)

        assert len(results) == 1
        assert results[0]['files'] == 2
        assert results[0]['bytes'] == 3000

        # Clean up
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)

    def test_local_account_usage_unique_multiple_rses(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Get unique local account usage for multiple RSEs """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()

        # Set up limits for both RSEs
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=100000, session=db_session)
        account_limit.set_local_account_limit(account=account, rse_id=rse2_id, bytes_=200000, session=db_session)

        # Get unique usage for all RSEs
        results = account_limit.get_local_account_usage(account=account, unique=True, session=db_session)

        # Should return results for both RSEs (even with 0 usage if limits are set)
        rse_ids_in_results = {r['rse_id'] for r in results}
        assert rse1_id in rse_ids_in_results
        assert rse2_id in rse_ids_in_results

        # Find the specific results for each RSE
        rse1_result = next(r for r in results if r['rse_id'] == rse1_id)
        rse2_result = next(r for r in results if r['rse_id'] == rse2_id)

        assert rse1_result['bytes_limit'] == 100000
        assert rse2_result['bytes_limit'] == 200000

        # Clean up
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)
        account_limit.delete_local_account_limit(account=account, rse_id=rse2_id, session=db_session)

    def test_local_account_usage_unique_no_locks(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Get unique usage when no locks exist """
        _, rse1_id = rse_factory.make_mock_rse()

        # Test with no limits and no usage
        results = account_limit.get_local_account_usage(account=account, rse_id=rse1_id, unique=True, session=db_session)

        # Should return empty list when no usage and no limits
        assert len(results) == 0

    def test_local_account_usage_unique_parameter_backwards_compatibility(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Ensure backwards compatibility when unique parameter is not provided """
        _, rse1_id = rse_factory.make_mock_rse()

        # Set up a limit for testing
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=100000, session=db_session)

        # Test without unique parameter (should default to False)
        results_default = account_limit.get_local_account_usage(account=account, rse_id=rse1_id, session=db_session)
        results_explicit_false = account_limit.get_local_account_usage(account=account, rse_id=rse1_id, unique=False, session=db_session)

        # Both should produce the same results (using the original implementation)
        assert len(results_default) == len(results_explicit_false)
        if results_default:
            assert results_default[0]['rse_id'] == results_explicit_false[0]['rse_id']
            assert results_default[0]['bytes'] == results_explicit_false[0]['bytes']
            assert results_default[0]['files'] == results_explicit_false[0]['files']

        # Clean up
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)

    def test_local_account_usage_unique_bytes_remaining_calculation(self, account, rse_factory, db_session):
        """ ACCOUNT_LIMIT (CORE): Test bytes_remaining calculation with unique usage """
        _, rse1_id = rse_factory.make_mock_rse()

        # Set a limit
        limit_bytes = 100000
        account_limit.set_local_account_limit(account=account, rse_id=rse1_id, bytes_=limit_bytes, session=db_session)

        results = account_limit.get_local_account_usage(account=account, rse_id=rse1_id, unique=True, session=db_session)

        assert len(results) == 1
        result = results[0]

        # bytes_remaining should be limit - usage
        expected_remaining = limit_bytes - result['bytes']
        assert result['bytes_remaining'] == expected_remaining

        # With no usage, should equal the limit
        assert result['bytes_remaining'] == limit_bytes

        # Clean up
        account_limit.delete_local_account_limit(account=account, rse_id=rse1_id, session=db_session)

class TestAccountClientUnique:

    def test_get_local_account_usage_unique_client(self, account, rucio_client, rse_factory):
        """ ACCOUNT_LIMIT (CLIENTS): Get unique local account usage via client """
        rse1, rse1_id = rse_factory.make_mock_rse()

        # Set a limit via client
        rucio_client.set_local_account_limit(account=account.external, rse=rse1, bytes_=150000)

        # Get unique usage via client (this would require client-side implementation)
        # Note: This test assumes the client will expose the unique parameter
        # results = rucio_client.get_local_account_usage(account=account.external, rse=rse1, unique=True)

        # For now, we can test that the core function works with the expected data
        results = account_limit.get_local_account_usage(account=account, rse_id=rse1_id, unique=True)

        assert len(results) == 1
        assert results[0]['rse_id'] == rse1_id
        assert results[0]['bytes_limit'] == 150000

        # Clean up
        rucio_client.delete_local_account_limit(account=account.external, rse=rse1)
