# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015, 2017
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin, <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from json import loads
import random
import string

from datetime import datetime
from nose.tools import assert_equal, assert_in, assert_not_equal, assert_not_in, assert_true

from rucio.api.account import add_account, get_account_info, list_accounts
import rucio.api.account_limit as api_acc_lim
from rucio.api.did import add_did, add_did_to_followed, attach_dids_to_dids, get_users_following_did, scope_list
from rucio.api.exporter import export_data
from rucio.api.identity import add_account_identity, list_accounts_for_identity
from rucio.api.replica import add_replicas, get_did_from_pfns, list_replicas
from rucio.api.request import get_request_by_did, list_requests, queue_requests
import rucio.api.rse as api_rse
from rucio.api.rule import add_replication_rule
from rucio.api.scope import add_scope, list_scopes, get_scopes
from rucio.api.subscription import add_subscription, list_subscriptions, list_subscription_rule_states, get_subscription_by_id
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import api_update_return_dict, generate_uuid
import rucio.core.account_counter as account_counter
from rucio.core.rse import get_rse_id
from rucio.core.vo import add_vo, vo_exists
from rucio.db.sqla import constants
from rucio.daemons.abacus import rse as abacus_rse
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.tests.common import rse_name_generator


class TestApiExternalRepresentation():

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
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
        out = api_update_return_dict(test_dict)
        assert_equal({'account': self.account_name, 'scope': self.scope_name, 'rse_expression': 'MOCK|MOCK2',
                      'rse_id': self.rse_id, 'rse': self.rse_name,
                      'src_rse_id': self.rse_id, 'src_rse': self.rse_name,
                      'source_rse_id': self.rse_id, 'source_rse': self.rse_name,
                      'dest_rse_id': self.rse_id, 'dest_rse': self.rse_name,
                      'destination_rse_id': self.rse_id, 'destination_rse': self.rse_name},
                     out)

    def test_api_account(self):
        """ ACCOUNT (API): Test external representation of account information """
        out = get_account_info(self.account_name, **self.vo)
        assert_equal(self.account_name, out['account'])

        out = [acc['account'] for acc in list_accounts(**self.vo)]
        assert_in(self.account_name, out)
        if self.multi_vo:
            assert_not_in(self.account.internal, out)
        assert_not_in('@', ' '.join(out))

    def test_api_account_limit(self):
        """ ACCOUNT_LIMIT (API): Test external representation of account limits """
        # Add mock account limits
        rse_expr = '{}|{}'.format(self.rse_name, self.rse2_name)
        api_acc_lim.set_local_account_limit(self.account_name, self.rse_name, 10000, issuer='root', **self.vo)
        api_acc_lim.set_global_account_limit(self.account_name, rse_expr, 20000, issuer='root', **self.vo)

        out = api_acc_lim.get_local_account_limits(self.account_name, **self.vo)
        assert_in(self.rse_name, out)
        assert_not_in(self.rse_id, out)

        out = api_acc_lim.get_local_account_limit(self.account_name, self.rse_name, **self.vo)
        assert_in(self.rse_name, out)
        assert_not_in(self.rse_id, out)

        out = api_acc_lim.get_global_account_limits(self.account_name, **self.vo)
        assert_in(rse_expr, out)
        if self.multi_vo:
            assert_not_in('vo={}&({})'.format(self.vo['vo'], rse_expr), out)

        out = api_acc_lim.get_global_account_limit(self.account_name, rse_expr, **self.vo)
        assert_in(rse_expr, out)
        if self.multi_vo:
            assert_not_in('vo={}&({})'.format(self.vo['vo'], rse_expr), out)

        out = api_acc_lim.get_local_account_usage(self.account_name, self.rse_name, issuer='root', **self.vo)
        out = list(out)
        assert_not_equal(0, len(out))
        assert_in(self.rse_id, [usage['rse_id'] for usage in out if 'rse_id' in usage])
        for usage in out:
            if 'rse_id' in usage:
                assert_in('rse', usage)
                if usage['rse_id'] == self.rse_id:
                    assert_equal(self.rse_name, usage["rse"])

        out = api_acc_lim.get_global_account_usage(self.account_name, rse_expr, issuer='root', **self.vo)
        out = list(out)
        assert_not_equal(0, len(out))
        assert_in(rse_expr, [usage['rse_expression'] for usage in out if 'rse_expression' in usage])

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
        assert_not_equal(0, len(out))
        parent_found = False
        for did in out:
            assert_equal(did['scope'], self.scope_name)
            if did['parent'] is not None:
                parent_found = True
                assert_equal(did['parent']['scope'], self.scope_name)
        assert_true(parent_found)

        # test get_did
        add_did_to_followed(self.scope_name, 'ext_parent', self.account_name, **self.vo)
        out = get_users_following_did('ext_parent', self.scope_name, **self.vo)
        out = list(out)
        assert_not_equal(0, len(out))
        for user in out:
            assert_equal(user['user'], self.account_name)

    def test_api_exporter(self):
        """ EXPORTER (API): Test external representation of exported data """

        out = export_data('root', **self.new_vo)
        rses = out['rses']
        assert_in(self.rse3_name, rses)
        assert_not_in(self.rse3_id, rses)

        distances = out['distances']
        assert_in(self.rse3_name, distances)
        assert_not_in(self.rse3_id, distances)
        assert_in(self.rse4_name, distances[self.rse3_name])
        assert_not_in(self.rse4_id, distances[self.rse3_name])

        # check for interference from other VOs
        if self.multi_vo:
            assert_not_in(self.rse_name, rses)
            assert_not_in(self.rse_id, rses)
            assert_not_in(self.rse2_name, rses)
            assert_not_in(self.rse2_id, rses)

            assert_not_in(self.rse_name, distances)
            assert_not_in(self.rse_id, distances)
            assert_not_in(self.rse2_name, distances)
            assert_not_in(self.rse2_id, distances)

    def test_api_identity(self):
        """ IDENTITY (API): Test external representation of identity accounts """

        id_key = ''.join(random.choice(string.ascii_lowercase) for x in range(10))

        add_account_identity(id_key, 'userpass', self.account_name, 'rucio_test@test.com', 'root', default=True, password='ext_pass', **self.vo)

        out = list_accounts_for_identity(id_key, 'userpass')
        assert_in(self.account_name, out)
        if self.multi_vo:
            assert_not_in(self.account.internal, out)

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
        assert_not_equal(0, len(out))
        did_found = False
        for p in out:
            for key in p:
                if p[key]['name'] == did:
                    did_found = True
                    assert_equal(self.scope_name, p[key]['scope'])
        assert_true(did_found)

        out = list_replicas(dids=[{'scope': self.scope_name, 'name': did}], resolve_parents=True, **self.vo)
        out = list(out)
        assert_not_equal(0, len(out))
        parents_found = False
        for rep in out:
            assert_equal(rep['scope'], self.scope_name)
            if 'parents' in rep:
                parents_found = True
                for parent in rep['parents']:
                    assert_in(self.scope_name, parent)
                    if self.multi_vo:
                        assert_not_in(self.scope.internal, parent)
        assert_true(parents_found)

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
        assert_not_equal(0, len(reqs))
        for r in reqs:
            assert_equal(r['scope'], self.scope_name)
            assert_equal(r['account'], self.account_name)
            assert_equal(r['source_rse'], self.rse_name)
            assert_equal(r['dest_rse'], self.rse2_name)

        out = get_request_by_did(self.scope_name, did, self.rse2_name, issuer='root', **self.vo)
        assert_equal(out['scope'], self.scope_name)
        assert_equal(out['account'], self.account_name)
        assert_equal(out['dest_rse'], self.rse2_name)
        assert_equal(out['source_rse'], self.rse_name)

        out = list_requests([self.rse_name], [self.rse2_name], [constants.RequestState.QUEUED], issuer='root', **self.vo)
        out = list(out)
        assert_not_equal(0, len(out))
        assert_in(self.scope_name, [req['scope'] for req in out])
        for req in out:
            if req['scope'] == self.scope_name:
                assert_equal(req['scope'], self.scope_name)
                assert_equal(req['account'], self.account_name)
                assert_equal(req['dest_rse'], self.rse2_name)
                assert_equal(req['source_rse'], self.rse_name)

    def test_api_rse(self):
        """ RSE (API): Test external representation of RSEs """

        out = api_rse.get_rse(self.rse_name, **self.vo)
        assert_equal(out['rse'], self.rse_name)
        assert_equal(out['id'], self.rse_id)

        out = api_rse.list_rses(**self.new_vo)
        out = list(out)
        assert_not_equal(0, len(out))
        rse_ids = [rse['id'] for rse in out]
        assert_in(self.rse3_id, rse_ids)
        assert_in(self.rse4_id, rse_ids)
        for rse in out:
            assert_in('rse', rse)
            if rse['id'] == self.rse3_id:
                assert_equal(rse['rse'], self.rse3_name)
            elif rse['id'] == self.rse4_id:
                assert_equal(rse['rse'], self.rse4_name)

        key = "KEY_" + generate_uuid()
        api_rse.add_rse_attribute(self.rse_name, key, 1, issuer='root', **self.vo)
        out = api_rse.get_rses_with_attribute(key)
        out = list(out)
        assert_not_equal(0, len(out))
        for rse in out:
            assert_equal(rse['rse'], self.rse_name)

        out = api_rse.get_rse_protocols(self.rse_name, issuer='root', **self.vo)
        assert_equal(out['rse'], self.rse_name)

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
        assert_in(rse_mock_id, [o['rse_id'] for o in out])
        for usage in out:
            if usage['rse_id'] == rse_mock_id:
                assert_equal(usage['rse'], rse_mock)
                accounts = [u['account'] for u in usage['account_usages']]
                assert_in(self.account_name, accounts)
                if self.multi_vo:
                    assert_not_in(self.account.internal, accounts)

        # clean up files
        cleaner.run(once=True)
        if self.multi_vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (self.vo['vo'], rse_mock), greedy=True)
        else:
            reaper.run(once=True, include_rses=rse_mock, greedy=True)
        abacus_rse.run(once=True)

        out = api_rse.parse_rse_expression('%s|%s' % (self.rse_name, self.rse2_name), **self.vo)
        assert_in(self.rse_name, out)
        assert_in(self.rse2_name, out)
        assert_not_in(self.rse_id, out)
        assert_not_in(self.rse2_id, out)

    def test_api_scope(self):
        """ SCOPE (API): Test external representation of scopes """

        out = list_scopes()
        assert_in(self.scope_name, out)
        if self.multi_vo:
            assert_not_in(self.scope.internal, out)

        out = get_scopes(self.account_name, **self.vo)
        assert_in(self.scope_name, out)
        if self.multi_vo:
            assert_not_in(self.scope.internal, out)

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
                             priority=0, split_container=False, meta='', issuer='root', **self.new_vo)

        out = list_subscriptions(sub, **self.new_vo)
        out = list(out)
        assert_not_equal(0, len(out))
        assert_in(sub_id, [o['id'] for o in out])
        for o in out:
            if o['id'] == sub_id:
                assert_equal(o['account'], new_acc_name)
                rules = loads(o['replication_rules'])[0]
                assert_equal(rules['rse_expression'], self.rse3_name)
                assert_equal(rules['source_replica_expression'], self.rse4_name)
                fil = loads(o['filter'])
                assert_equal(fil['account'], [new_acc_name])
                assert_equal(fil['scope'], [new_scope_name])

        out = list_subscription_rule_states(sub, **self.new_vo)
        out = list(out)
        assert_not_equal(0, len(out))
        for o in out:
            assert_equal(o.account, new_acc_name)

        out = get_subscription_by_id(sub_id, **self.new_vo)
        assert_equal(out['account'], new_acc_name)
        rules = loads(out['replication_rules'])[0]
        assert_equal(rules['rse_expression'], self.rse3_name)
        assert_equal(rules['source_replica_expression'], self.rse4_name)
        fil = loads(out['filter'])
        assert_equal(fil['account'], [new_acc_name])
        assert_equal(fil['scope'], [new_scope_name])
