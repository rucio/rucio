# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

import random
import string
import unittest
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
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import api_update_return_dict, generate_uuid
from rucio.core.rse import get_rse_id
from rucio.core.vo import add_vo, vo_exists
from rucio.daemons.abacus import rse as abacus_rse
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.db.sqla import constants
from rucio.tests.common import rse_name_generator
from rucio.tests.common_server import get_vo


@pytest.mark.noparallel(reason='uses pre-defined RSE, fails when run in parallel')
class TestApiExternalRepresentation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
            cls.new_vo = {'vo': 'new'}
            cls.multi_vo = True
            if not vo_exists(**cls.new_vo):
                add_vo(description='Test', email='rucio@email.com', **cls.new_vo)
        else:
            cls.vo = {}
            cls.new_vo = {}
            cls.multi_vo = False

        # Add test account
        cls.account_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        add_account(account=cls.account_name, type='user', email='rucio@email.com', issuer='root', **cls.vo)
        cls.account = InternalAccount(cls.account_name, **cls.vo)

        # Add test scope
        cls.scope_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        add_scope(scope=cls.scope_name, account=cls.account_name, issuer='root', **cls.vo)
        cls.scope = InternalScope(cls.scope_name, **cls.vo)

        # Get test RSEs
        cls.rse_name = 'MOCK'
        cls.rse_id = get_rse_id(rse=cls.rse_name, **cls.vo)
        cls.rse2_name = 'MOCK2'
        cls.rse2_id = get_rse_id(rse=cls.rse2_name, **cls.vo)

        cls.rse3_name = rse_name_generator()
        cls.rse3_id = api_rse.add_rse(cls.rse3_name, 'root', **cls.new_vo)
        cls.rse4_name = rse_name_generator()
        cls.rse4_id = api_rse.add_rse(cls.rse4_name, 'root', **cls.new_vo)
        api_rse.add_distance(cls.rse3_name, cls.rse4_name, issuer='root', distance=3, **cls.new_vo)

    def test_api_update_return_dict(self):
        """ API: Test the conversion of dictionaries to external representation """
        test_dict = {'account': self.account,
                     'scope': self.scope,
                     'rse_expression': 'MOCK|MOCK2',
                     'rse_id': self.rse_id,
                     'src_rse_id': self.rse_id,
                     'source_rse_id': self.rse_id,
                     'dest_rse_id': self.rse_id,
                     'destination_rse_id': self.rse_id}
        value = api_update_return_dict(test_dict)
        expected = {'account': self.account_name, 'scope': self.scope_name, 'rse_expression': 'MOCK|MOCK2',
                    'rse_id': self.rse_id, 'rse': self.rse_name,
                    'src_rse_id': self.rse_id, 'src_rse': self.rse_name,
                    'source_rse_id': self.rse_id, 'source_rse': self.rse_name,
                    'dest_rse_id': self.rse_id, 'dest_rse': self.rse_name,
                    'destination_rse_id': self.rse_id, 'destination_rse': self.rse_name}
        assert value == expected

    def test_api_account(self):
        """ ACCOUNT (API): Test external representation of account information """
        out = get_account_info(self.account_name, **self.vo)
        assert self.account_name == out['account']

        out = [acc['account'] for acc in list_accounts(**self.vo)]
        assert self.account_name in out
        if self.multi_vo:
            assert self.account.internal not in out
        assert '@' not in ' '.join(out)

    def test_api_account_limit(self):
        """ ACCOUNT_LIMIT (API): Test external representation of account limits """
        # Add mock account limits
        rse_expr = '{}|{}'.format(self.rse_name, self.rse2_name)
        api_acc_lim.set_local_account_limit(self.account_name, self.rse_name, 10000, issuer='root', **self.vo)
        api_acc_lim.set_global_account_limit(self.account_name, rse_expr, 20000, issuer='root', **self.vo)

        out = api_acc_lim.get_local_account_limits(self.account_name, **self.vo)
        assert self.rse_name in out
        assert self.rse_id not in out

        out = api_acc_lim.get_local_account_limit(self.account_name, self.rse_name, **self.vo)
        assert self.rse_name in out
        assert self.rse_id not in out

        out = api_acc_lim.get_global_account_limits(self.account_name, **self.vo)
        assert rse_expr in out
        if self.multi_vo:
            assert 'vo={}&({})'.format(self.vo['vo'], rse_expr) not in out

        out = api_acc_lim.get_global_account_limit(self.account_name, rse_expr, **self.vo)
        assert rse_expr in out
        if self.multi_vo:
            assert 'vo={}&({})'.format(self.vo['vo'], rse_expr) not in out

        out = api_acc_lim.get_local_account_usage(self.account_name, self.rse_name, issuer='root', **self.vo)
        out = list(out)
        assert 0 != len(out)
        assert self.rse_id in [usage['rse_id'] for usage in out if 'rse_id' in usage]
        for usage in out:
            if 'rse_id' in usage:
                assert 'rse' in usage
                if usage['rse_id'] == self.rse_id:
                    assert self.rse_name == usage["rse"]

        out = api_acc_lim.get_global_account_usage(self.account_name, rse_expr, issuer='root', **self.vo)
        out = list(out)
        assert 0 != len(out)
        assert rse_expr in [usage['rse_expression'] for usage in out if 'rse_expression' in usage]

    def test_api_did(self):
        """ DID (API): Test external representation of DIDs """
        # add some dids
        add_did(self.scope_name, 'ext_parent', 'container', issuer='root', account=self.account_name, **self.vo)
        add_did(self.scope_name, 'ext_child', 'dataset', issuer='root', account=self.account_name, **self.vo)
        attachment = {'scope': self.scope_name, 'name': 'ext_parent',
                      'dids': [{'scope': self.scope_name, 'name': 'ext_child', 'type': 'DATASET'}]}
        attach_dids_to_dids([attachment], issuer='root', **self.vo)

        # test scope_list
        out = scope_list(self.scope_name, recursive=True, **self.vo)
        out = list(out)
        assert 0 != len(out)
        parent_found = False
        for did in out:
            assert did['scope'] == self.scope_name
            if did['parent'] is not None:
                parent_found = True
                assert did['parent']['scope'] == self.scope_name
        assert parent_found

        # test get_did
        add_did_to_followed(self.scope_name, 'ext_parent', self.account_name, **self.vo)
        out = get_users_following_did('ext_parent', self.scope_name, **self.vo)
        out = list(out)
        assert 0 != len(out)
        for user in out:
            assert user['user'] == self.account_name

    def test_api_exporter(self):
        """ EXPORTER (API): Test external representation of exported data """

        out = export_data('root', **self.new_vo)
        rses = out['rses']
        assert self.rse3_name in rses
        assert self.rse3_id not in rses

        distances = out['distances']
        assert self.rse3_name in distances
        assert self.rse3_id not in distances
        assert self.rse4_name in distances[self.rse3_name]
        assert self.rse4_id not in distances[self.rse3_name]

        # check for interference from other VOs
        if self.multi_vo:
            assert self.rse_name not in rses
            assert self.rse_id not in rses
            assert self.rse2_name not in rses
            assert self.rse2_id not in rses

            assert self.rse_name not in distances
            assert self.rse_id not in distances
            assert self.rse2_name not in distances
            assert self.rse2_id not in distances

    def test_api_identity(self):
        """ IDENTITY (API): Test external representation of identity accounts """

        id_key = ''.join(random.choice(string.ascii_lowercase) for x in range(10))

        add_account_identity(id_key, 'userpass', self.account_name, 'rucio_test@test.com', 'root', default=True, password='ext_pass', **self.vo)

        out = list_accounts_for_identity(id_key, 'userpass')
        assert self.account_name in out
        if self.multi_vo:
            assert self.account.internal not in out

    def test_api_replica(self):
        """ REPLICA (API): Test external representation of replicas """

        did = 'ext_' + str(generate_uuid())
        pfn = 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (self.scope_name, generate_uuid())
        add_replicas(self.rse2_name, files=[{'scope': self.scope_name, 'name': did, 'bytes': 100, 'pfn': pfn}], issuer='root', **self.vo)

        add_did(self.scope_name, 'ext_parent_2', 'dataset', issuer='root', account=self.account_name, **self.vo)
        attachment = {'scope': self.scope_name, 'name': 'ext_parent_2',
                      'dids': [{'scope': self.scope_name, 'name': did}]}
        attach_dids_to_dids([attachment], issuer='root', **self.vo)

        out = get_did_from_pfns([pfn], self.rse2_name, **self.vo)
        out = list(out)
        assert 0 != len(out)
        did_found = False
        for p in out:
            for key in p:
                if p[key]['name'] == did:
                    did_found = True
                    assert self.scope_name == p[key]['scope']
        assert did_found

        out = list_replicas(dids=[{'scope': self.scope_name, 'name': did}], resolve_parents=True, **self.vo)
        out = list(out)
        assert 0 != len(out)
        parents_found = False
        for rep in out:
            assert rep['scope'] == self.scope_name
            if 'parents' in rep:
                parents_found = True
                for parent in rep['parents']:
                    assert self.scope_name in parent
                    if self.multi_vo:
                        assert self.scope.internal not in parent
        assert parents_found

    def test_api_request(self):
        """ REQUEST (API): Test external representation of requests """

        did = generate_uuid()
        add_did(self.scope_name, did, 'dataset', issuer='root', account=self.account_name, rse=self.rse_name, **self.vo)

        requests = [{
            'dest_rse_id': self.rse2_id,
            'source_rse_id': self.rse_id,
            'request_type': constants.RequestType.TRANSFER,
            'request_id': generate_uuid(),
            'name': did,
            'scope': self.scope_name,
            'account': self.account_name,
            'rule_id': generate_uuid(),
            'retry_count': 1,
            'requested_at': datetime.now(),
            'attributes': {
                'activity': 'User Subscription',
                'bytes': 10,
                'md5': '',
                'adler32': ''
            }
        }]

        reqs = queue_requests(requests, issuer='root', **self.vo)  # this does not pass in the source rse
        reqs = list(reqs)
        assert 0 != len(reqs)
        for r in reqs:
            assert r['scope'] == self.scope_name
            assert r['account'] == self.account_name
            assert r['source_rse'] == self.rse_name
            assert r['dest_rse'] == self.rse2_name

        out = get_request_by_did(self.scope_name, did, self.rse2_name, issuer='root', **self.vo)
        assert out['scope'] == self.scope_name
        assert out['account'] == self.account_name
        assert out['dest_rse'] == self.rse2_name
        assert out['source_rse'] == self.rse_name

        out = list_requests([self.rse_name], [self.rse2_name], [constants.RequestState.QUEUED], issuer='root', **self.vo)
        out = list(out)
        assert 0 != len(out)
        assert self.scope_name in [req['scope'] for req in out]
        for req in out:
            if req['scope'] == self.scope_name:
                assert req['scope'] == self.scope_name
                assert req['account'] == self.account_name
                assert req['dest_rse'] == self.rse2_name
                assert req['source_rse'] == self.rse_name

    @pytest.mark.noparallel(reason='runs the reaper on a pre-defined rse, might interfere with other tests')
    def test_api_rse(self):
        """ RSE (API): Test external representation of RSEs """

        out = api_rse.get_rse(self.rse_name, **self.vo)
        assert out['rse'] == self.rse_name
        assert out['id'] == self.rse_id

        out = api_rse.list_rses(**self.new_vo)
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
        api_rse.add_rse_attribute(self.rse_name, key, 1, issuer='root', **self.vo)
        out = api_rse.get_rses_with_attribute(key)
        out = list(out)
        assert 0 != len(out)
        for rse in out:
            assert rse['rse'] == self.rse_name

        out = api_rse.get_rse_protocols(self.rse_name, issuer='root', **self.vo)
        assert out['rse'] == self.rse_name

        # add some account and RSE counters
        rse_mock = 'MOCK4'
        rse_mock_id = get_rse_id(rse_mock, **self.vo)
        account_counter.del_counter(rse_id=rse_mock_id, account=self.account)
        account_counter.add_counter(rse_id=rse_mock_id, account=self.account)
        account_counter.increase(rse_id=rse_mock_id, account=self.account, files=1, bytes=10)
        account_counter.update_account_counter(self.account, rse_mock_id)
        did = 'file_' + generate_uuid()
        add_did(self.scope_name, did, 'DATASET', 'root', account=self.account_name, rse=rse_mock, **self.vo)
        abacus_rse.run(once=True)

        out = api_rse.get_rse_usage(rse_mock, per_account=True, issuer='root', **self.vo)
        assert rse_mock_id in [o['rse_id'] for o in out]
        for usage in out:
            if usage['rse_id'] == rse_mock_id:
                assert usage['rse'] == rse_mock
                accounts = [u['account'] for u in usage['account_usages']]
                assert self.account_name in accounts
                if self.multi_vo:
                    assert self.account.internal not in accounts

        # clean up files
        cleaner.run(once=True)
        if self.multi_vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (self.vo['vo'], rse_mock), greedy=True)
        else:
            reaper.run(once=True, include_rses=rse_mock, greedy=True)
        abacus_rse.run(once=True)

        out = api_rse.parse_rse_expression('%s|%s' % (self.rse_name, self.rse2_name), **self.vo)
        assert self.rse_name in out
        assert self.rse2_name in out
        assert self.rse_id not in out
        assert self.rse2_id not in out

    def test_api_scope(self):
        """ SCOPE (API): Test external representation of scopes """

        out = list_scopes()
        assert self.scope_name in out
        if self.multi_vo:
            assert self.scope.internal not in out

        out = get_scopes(self.account_name, **self.vo)
        assert self.scope_name in out
        if self.multi_vo:
            assert self.scope.internal not in out

    def test_api_subscription(self):
        """ SUBSCRIPTION (API): Test external representation of subscriptions """

        sub = 'ext_' + generate_uuid()
        did = 'ext_' + generate_uuid()
        new_acc_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        new_scope_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        add_account(new_acc_name, 'USER', 'test@test.com', 'root', **self.new_vo)
        add_scope(new_scope_name, new_acc_name, 'root', **self.new_vo)
        api_acc_lim.set_local_account_limit(new_acc_name, self.rse3_name, 10, 'root', **self.new_vo)
        api_acc_lim.set_local_account_limit(new_acc_name, self.rse4_name, 10, 'root', **self.new_vo)
        add_did(new_scope_name, did, 'DATASET', 'root', account=new_acc_name, rse=self.rse3_name, **self.new_vo)

        sub_id = add_subscription(sub, new_acc_name, {'account': [new_acc_name], 'scope': [new_scope_name]},
                                  [{'copies': 1, 'rse_expression': self.rse3_name, 'weight': 0, 'activity': 'User Subscriptions',
                                    'source_replica_expression': self.rse4_name}],
                                  '', False, 0, 0, 3, 'root', **self.new_vo)
        add_replication_rule(dids=[{'scope': new_scope_name, 'name': did}], copies=1, rse_expression=self.rse3_name, weight=None,
                             lifetime=180, grouping='DATASET', account=new_acc_name, locked=False, subscription_id=sub_id,
                             source_replica_expression=self.rse4_name, activity='User Subscriptions', notify=None,
                             purge_replicas=False, ignore_availability=False, comment='', ask_approval=False, asynchronous=False,
                             delay_injection=None, priority=0, split_container=False, meta='', issuer='root', **self.new_vo)

        out = list_subscriptions(sub, **self.new_vo)
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

        out = list_subscription_rule_states(sub, **self.new_vo)
        out = list(out)
        assert 0 != len(out)
        for o in out:
            assert o.account == new_acc_name

        out = get_subscription_by_id(sub_id, **self.new_vo)
        assert out['account'] == new_acc_name
        rules = loads(out['replication_rules'])[0]
        assert rules['rse_expression'] == self.rse3_name
        assert rules['source_replica_expression'] == self.rse4_name
        fil = loads(out['filter'])
        assert fil['account'] == [new_acc_name]
        assert fil['scope'] == [new_scope_name]
