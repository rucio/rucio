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
from datetime import datetime
from json import loads

import pytest

import rucio.api.account_limit as api_acc_lim
import rucio.api.rse as api_rse
import rucio.core.account_counter as account_counter
from rucio.api.account import add_account, get_account_info, list_accounts
from rucio.api.did import add_did, add_did_to_followed, attach_dids_to_dids, get_users_following_did, scope_list
from rucio.api.exporter import export_data
from rucio.api.identity import add_account_identity, list_accounts_for_identity
from rucio.api.replica import add_replicas, get_did_from_pfns, list_replicas
from rucio.api.request import get_request_by_did, list_requests, queue_requests
from rucio.api.rule import add_replication_rule
from rucio.api.scope import add_scope, list_scopes, get_scopes
from rucio.api.subscription import add_subscription, list_subscriptions, list_subscription_rule_states, \
    get_subscription_by_id
from rucio.common.config import config_get_bool
from rucio.common.types import InternalScope
from rucio.common.utils import api_update_return_dict, generate_uuid
from rucio.core.vo import add_vo, vo_exists
from rucio.daemons.abacus import rse as abacus_rse
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.db.sqla import constants
from rucio.tests.common import rse_name_generator, did_name_generator


@pytest.fixture(scope='class')
def vo2():
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo2 = 'new'
        if not vo_exists(vo=vo2):
            add_vo(description='Test', email='rucio@email.com', vo=vo2)
        return vo2
    else:
        return None


@pytest.fixture
def account(random_account):
    return random_account


@pytest.fixture
def account_name(random_account):
    return random_account.external


@pytest.fixture
def scope(account_name, vo):
    scope_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
    add_scope(scope=scope_name, account=account_name, issuer='root', vo=vo)
    scope = InternalScope(scope_name, vo=vo)
    return scope


@pytest.fixture
def scope_name(scope):
    return scope.external


@pytest.fixture(scope="class")
def setup_class(request, rse_factory_unittest, vo, vo2):
    request.cls.vo = vo
    request.cls.vo2 = vo2
    request.cls.setUpClass()


@pytest.mark.usefixtures("setup_class")
@pytest.mark.noparallel(reason='uses pre-defined RSE, fails when run in parallel')
class TestApiExternalRepresentation:

    @classmethod
    def setUpClass(cls):
        # Get test RSEs
        cls.rse3_name = rse_name_generator()
        cls.rse3_id = api_rse.add_rse(cls.rse3_name, 'root', vo=cls.vo2 if cls.vo2 else cls.vo)
        cls.rse4_name = rse_name_generator()
        cls.rse4_id = api_rse.add_rse(cls.rse4_name, 'root', vo=cls.vo2 if cls.vo2 else cls.vo)
        api_rse.add_distance(cls.rse3_name, cls.rse4_name, issuer='root', distance=3, vo=cls.vo2 or cls.vo)

    def test_api_update_return_dict(self, rse_factory, account, account_name, scope_name, scope):
        """ API: Test the conversion of dictionaries to external representation """
        rse1, rse1_id = rse_factory.make_rse()
        rse2, rse2_id = rse_factory.make_rse()
        test_dict = {'account': account,
                     'scope': scope,
                     'rse_expression': f'{rse1}|{rse2}',
                     'rse_id': rse1_id,
                     'src_rse_id': rse1_id,
                     'source_rse_id': rse1_id,
                     'dest_rse_id': rse1_id,
                     'destination_rse_id': rse1_id}
        value = api_update_return_dict(test_dict)
        expected = {'account': account_name, 'scope': scope_name, 'rse_expression': f'{rse1}|{rse2}',
                    'rse_id': rse1_id, 'rse': rse1,
                    'src_rse_id': rse1_id, 'src_rse': rse1,
                    'source_rse_id': rse1_id, 'source_rse': rse1,
                    'dest_rse_id': rse1_id, 'dest_rse': rse1,
                    'destination_rse_id': rse1_id, 'destination_rse': rse1}
        assert value == expected

    def test_api_account(self, vo, vo2, account, account_name):
        """ ACCOUNT (API): Test external representation of account information """
        out = get_account_info(account_name, vo=vo)
        assert account_name == out['account']

        out = [acc['account'] for acc in list_accounts(vo=vo)]
        assert account_name in out
        if vo2:
            assert account.internal not in out
        assert '@' not in ' '.join(out)

    def test_api_account_limit(self, rse_factory, vo, vo2, account_name):
        """ ACCOUNT_LIMIT (API): Test external representation of account limits """
        # Add mock account limits
        rse1, rse1_id = rse_factory.make_rse()
        rse2, rse2_id = rse_factory.make_rse()
        rse_expr = f'{rse1}|{rse2}'
        api_acc_lim.set_local_account_limit(account_name, rse1, 10000, issuer='root', vo=vo)
        api_acc_lim.set_global_account_limit(account_name, rse_expr, 20000, issuer='root', vo=vo)

        out = api_acc_lim.get_local_account_limits(account_name, vo=vo)
        assert rse1 in out
        assert rse1_id not in out

        out = api_acc_lim.get_local_account_limit(account_name, rse1, vo=vo)
        assert rse1 in out
        assert rse1_id not in out

        out = api_acc_lim.get_global_account_limits(account_name, vo=vo)
        assert rse_expr in out
        if vo2:
            assert 'vo={}&({})'.format(vo, rse_expr) not in out

        out = api_acc_lim.get_global_account_limit(account_name, rse_expr, vo=vo)
        assert rse_expr in out
        if vo2:
            assert 'vo={}&({})'.format(vo, rse_expr) not in out

        out = api_acc_lim.get_local_account_usage(account_name, rse1, issuer='root', vo=vo)
        out = list(out)
        assert 0 != len(out)
        assert rse1_id in [usage['rse_id'] for usage in out if 'rse_id' in usage]
        for usage in out:
            if 'rse_id' in usage:
                assert 'rse' in usage
                if usage['rse_id'] == rse1_id:
                    assert rse1 == usage["rse"]

        out = api_acc_lim.get_global_account_usage(account_name, rse_expr, issuer='root', vo=vo)
        out = list(out)
        assert 0 != len(out)
        assert rse_expr in [usage['rse_expression'] for usage in out if 'rse_expression' in usage]

    def test_api_did(self, vo, account_name, scope_name):
        """ DID (API): Test external representation of DIDs """
        # add some dids
        ext_parent = did_name_generator('container')
        ext_child = did_name_generator('dataset')
        add_did(scope_name, ext_parent, 'container', issuer='root', account=account_name, vo=vo)
        add_did(scope_name, ext_child, 'dataset', issuer='root', account=account_name, vo=vo)
        attachment = {'scope': scope_name, 'name': ext_parent,
                      'dids': [{'scope': scope_name, 'name': ext_child, 'type': 'DATASET'}]}
        attach_dids_to_dids([attachment], issuer='root', vo=vo)

        # test scope_list
        out = scope_list(scope_name, recursive=True, vo=vo)
        out = list(out)
        assert 0 != len(out)
        parent_found = False
        for did in out:
            assert did['scope'] == scope_name
            if did['parent'] is not None:
                parent_found = True
                assert did['parent']['scope'] == scope_name
        assert parent_found

        # test get_did
        add_did_to_followed(scope_name, ext_parent, account_name, vo=vo)
        out = get_users_following_did(ext_parent, scope_name, vo=vo)
        out = list(out)
        assert 0 != len(out)
        for user in out:
            assert user['user'] == account_name

    def test_api_exporter(self, vo, rse_factory, vo2):
        """ EXPORTER (API): Test external representation of exported data """

        rse1, rse1_id = rse_factory.make_rse()
        rse2, rse2_id = rse_factory.make_rse()
        out = export_data('root', vo=vo2 if vo2 else vo)
        rses = out['rses']
        assert self.rse3_name in rses
        assert self.rse3_id not in rses

        distances = out['distances']
        assert self.rse3_name in distances
        assert self.rse3_id not in distances
        assert self.rse4_name in distances[self.rse3_name]
        assert self.rse4_id not in distances[self.rse3_name]

        # check for interference from other VOs
        if vo2:
            assert rse1 not in rses
            assert rse1_id not in rses
            assert rse2 not in rses
            assert rse2_id not in rses

            assert rse1 not in distances
            assert rse1_id not in distances
            assert rse2 not in distances
            assert rse2_id not in distances

    def test_api_identity(self, vo, vo2, account, account_name):
        """ IDENTITY (API): Test external representation of identity accounts """

        id_key = ''.join(random.choice(string.ascii_lowercase) for x in range(10))

        add_account_identity(id_key, 'userpass', account_name, 'rucio_test@test.com', 'root', default=True, password='ext_pass', vo=vo)

        out = list_accounts_for_identity(id_key, 'userpass')
        assert account_name in out
        if vo2:
            assert account.internal not in out

    def test_api_replica(self, vo, rse_factory, vo2, account_name, scope_name, scope):
        """ REPLICA (API): Test external representation of replicas """

        did = did_name_generator('file')
        did_parent = did_name_generator('dataset')
        rse2, rse2_id = rse_factory.make_rse(scheme='srm', protocol_impl='rucio.rse.protocols.gfal.Default', deterministic=False)
        protocols = api_rse.get_rse_protocols(rse2, issuer='root', vo=vo)
        pfn = 'srm://%s:%s/srm/managerv2?SFN=%s%s/%s' % (protocols['protocols'][0]['hostname'],
                                                         protocols['protocols'][0]['port'],
                                                         protocols['protocols'][0]['prefix'],
                                                         scope_name,
                                                         generate_uuid())
        add_replicas(rse2, files=[{'scope': scope_name, 'name': did, 'bytes': 100, 'pfn': pfn}], issuer='root', vo=vo)

        add_did(scope_name, did_parent, 'dataset', issuer='root', account=account_name, vo=vo)
        attachment = {'scope': scope_name, 'name': did_parent,
                      'dids': [{'scope': scope_name, 'name': did}]}
        attach_dids_to_dids([attachment], issuer='root', vo=vo)

        out = get_did_from_pfns([pfn], rse2, vo=vo)
        out = list(out)
        assert 0 != len(out)
        did_found = False
        for p in out:
            for key in p:
                if p[key]['name'] == did:
                    did_found = True
                    assert scope_name == p[key]['scope']
        assert did_found

        out = list_replicas(dids=[{'scope': scope_name, 'name': did}], resolve_parents=True, vo=vo)
        out = list(out)
        assert 0 != len(out)
        parents_found = False
        for rep in out:
            assert rep['scope'] == scope_name
            if 'parents' in rep:
                parents_found = True
                for parent in rep['parents']:
                    assert scope_name in parent
                    if vo2:
                        assert scope.internal not in parent
        assert parents_found

    def test_api_request(self, vo, rse_factory, account_name, scope_name):
        """ REQUEST (API): Test external representation of requests """

        rse1, rse1_id = rse_factory.make_rse()
        rse2, rse2_id = rse_factory.make_rse()
        did = did_name_generator('dataset')
        add_did(scope_name, did, 'dataset', issuer='root', account=account_name, rse=rse1, vo=vo)

        requests = [{
            'dest_rse_id': rse2_id,
            'source_rse_id': rse1_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': did,
            'scope': scope_name,
            'account': account_name,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.utcnow(),
            'attributes': {
                'activity': 'Functional Test',
                'bytes': 10,
                'md5': '',
                'adler32': ''
            }
        }]

        reqs = queue_requests(requests, issuer='root', vo=vo)  # this does not pass in the source rse
        reqs = list(reqs)
        assert 0 != len(reqs)
        for r in reqs:
            assert r['scope'] == scope_name
            assert r['account'] == account_name
            assert r['source_rse'] == rse1
            assert r['dest_rse'] == rse2

        out = get_request_by_did(scope_name, did, rse2, issuer='root', vo=vo)
        assert out['scope'] == scope_name
        assert out['account'] == account_name
        assert out['dest_rse'] == rse2
        assert out['source_rse'] == rse1

        out = list_requests([rse1], [rse2], [constants.RequestState.QUEUED], issuer='root', vo=vo)
        out = list(out)
        assert 0 != len(out)
        assert scope_name in [req['scope'] for req in out]
        for req in out:
            if req['scope'] == scope_name:
                assert req['scope'] == scope_name
                assert req['account'] == account_name
                assert req['dest_rse'] == rse2
                assert req['source_rse'] == rse1

    @pytest.mark.noparallel(reason='runs the reaper on a pre-defined rse, might interfere with other tests')
    def test_api_rse(self, vo, rse_factory, vo2, account, account_name, scope_name):
        """ RSE (API): Test external representation of RSEs """

        rse1, rse1_id = rse_factory.make_rse()
        rse2, rse2_id = rse_factory.make_rse()
        out = api_rse.get_rse(rse1, vo=vo)
        assert out['rse'] == rse1
        assert out['id'] == rse1_id

        out = api_rse.list_rses(vo=vo2 if vo2 else vo)
        out = list(out)
        assert 0 != len(out)
        rse_ids = [rse['id'] for rse in out]
        assert self.rse3_id in rse_ids
        assert self.rse4_id in rse_ids
        for rse in out:
            assert 'rse' in rse
            if rse['id'] == self.rse3_id:
                assert rse['rse'] == self.rse3_name
            elif rse['id'] == self.rse4_id:
                assert rse['rse'] == self.rse4_name

        key = "KEY_" + generate_uuid()
        api_rse.add_rse_attribute(rse1, key, 1, issuer='root', vo=vo)
        out = api_rse.get_rses_with_attribute(key)
        out = list(out)
        assert 0 != len(out)
        for rse in out:
            assert rse['rse'] == rse1

        out = api_rse.get_rse_protocols(rse1, issuer='root', vo=vo)
        assert out['rse'] == rse1

        # add some account and RSE counters
        rse_mock, rse_mock_id = rse_factory.make_mock_rse()
        account_counter.del_counter(rse_id=rse_mock_id, account=account)
        account_counter.add_counter(rse_id=rse_mock_id, account=account)
        account_counter.increase(rse_id=rse_mock_id, account=account, files=1, bytes_=10)
        account_counter.update_account_counter(account, rse_mock_id)
        did = did_name_generator('file')
        add_did(scope_name, did, 'DATASET', 'root', account=account_name, rse=rse_mock, vo=vo)
        abacus_rse.run(once=True)

        out = api_rse.get_rse_usage(rse_mock, per_account=True, issuer='root', vo=vo)
        print(out)
        assert rse_mock_id in [o['rse_id'] for o in out]
        for usage in out:
            if usage['rse_id'] == rse_mock_id:
                assert usage['rse'] == rse_mock
                accounts = [u['account'] for u in usage['account_usages']]
                assert account_name in accounts
                if vo2:
                    assert account.internal not in accounts

        # clean up files
        cleaner.run(once=True)
        if vo2:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (vo, rse_mock), greedy=True)
        else:
            reaper.run(once=True, include_rses=rse_mock, greedy=True)
        abacus_rse.run(once=True)

        out = api_rse.parse_rse_expression(f'{rse1}|{rse2}', vo=vo)
        assert rse1 in out
        assert rse2 in out
        assert rse1_id not in out
        assert rse2_id not in out

    def test_api_scope(self, vo, vo2, account_name, scope_name, scope):
        """ SCOPE (API): Test external representation of scopes """

        out = list_scopes()
        assert scope_name in out
        if vo2:
            assert scope.internal not in out

        out = get_scopes(account_name, vo=vo)
        assert scope_name in out
        if vo2:
            assert scope.internal not in out

    def test_api_subscription(self, vo, vo2):
        """ SUBSCRIPTION (API): Test external representation of subscriptions """

        test_vo = vo2 if vo2 else vo

        sub = 'ext_' + generate_uuid()
        did = did_name_generator('file')
        new_acc_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        new_scope_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        add_account(new_acc_name, 'USER', 'test@test.com', 'root', vo=test_vo)
        add_scope(new_scope_name, new_acc_name, 'root', vo=test_vo)
        api_acc_lim.set_local_account_limit(new_acc_name, self.rse3_name, 10, 'root', vo=test_vo)
        api_acc_lim.set_local_account_limit(new_acc_name, self.rse4_name, 10, 'root', vo=test_vo)
        add_did(new_scope_name, did, 'DATASET', 'root', account=new_acc_name, rse=self.rse3_name, vo=test_vo)

        sub_id = add_subscription(sub, new_acc_name, {'account': [new_acc_name], 'scope': [new_scope_name]},
                                  [{'copies': 1, 'rse_expression': self.rse3_name, 'weight': 0, 'activity': 'Functional Test',
                                    'source_replica_expression': self.rse4_name}],
                                  '', False, 0, 0, 3, 'root', vo=test_vo)
        add_replication_rule(dids=[{'scope': new_scope_name, 'name': did}], copies=1, rse_expression=self.rse3_name, weight=None,
                             lifetime=180, grouping='DATASET', account=new_acc_name, locked=False, subscription_id=sub_id,
                             source_replica_expression=self.rse4_name, activity='Functional Test', notify=None,
                             purge_replicas=False, ignore_availability=False, comment='', ask_approval=False, asynchronous=False,
                             delay_injection=None, priority=0, split_container=False, meta='', issuer='root', vo=test_vo)

        out = list_subscriptions(sub, vo=test_vo)
        out = list(out)
        assert 0 != len(out)
        assert sub_id in [o['id'] for o in out]
        for o in out:
            if o['id'] == sub_id:
                assert o['account'] == new_acc_name
                rules = loads(o['replication_rules'])[0]
                assert rules['rse_expression'] == self.rse3_name
                assert rules['source_replica_expression'] == self.rse4_name
                fil = loads(o['filter'])
                assert fil['account'] == [new_acc_name]
                assert fil['scope'] == [new_scope_name]

        out = list_subscription_rule_states(sub, vo=test_vo)
        out = list(out)
        assert 0 != len(out)
        for o in out:
            assert o.account == new_acc_name

        out = get_subscription_by_id(sub_id, vo=test_vo)
        assert out['account'] == new_acc_name
        rules = loads(out['replication_rules'])[0]
        assert rules['rse_expression'] == self.rse3_name
        assert rules['source_replica_expression'] == self.rse4_name
        fil = loads(out['filter'])
        assert fil['account'] == [new_acc_name]
        assert fil['scope'] == [new_scope_name]
