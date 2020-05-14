# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

from logging import getLogger
from nose.tools import assert_equal, assert_false, assert_in, assert_is_not_none, assert_not_in, assert_raises, assert_true
from random import choice
from string import ascii_uppercase, ascii_lowercase

from rucio.api import vo as vo_api
from rucio.api.account import account_exists, add_account, list_accounts
from rucio.api.account_limit import set_local_account_limit
from rucio.api.did import add_did, list_dids
from rucio.api.identity import list_accounts_for_identity
from rucio.api.rse import add_rse, list_rses
from rucio.api.rule import delete_replication_rule, get_replication_rule
from rucio.api.scope import add_scope, list_scopes
from rucio.api.subscription import add_subscription, list_subscriptions
from rucio.client.accountclient import AccountClient
from rucio.client.accountlimitclient import AccountLimitClient
from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.rseclient import RSEClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.scopeclient import ScopeClient
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get_bool
from rucio.common.exception import AccessDenied, AccountNotFound, Duplicate
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.rule import add_rule
from rucio.core.vo import add_vo, vo_exists


LOG = getLogger(__name__)


class TestVOCoreAPI(object):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': 'tst'}
            cls.new_vo = {'vo': 'new'}
            if not vo_exists(**cls.new_vo):
                add_vo(description='Test', email='rucio@email.com', **cls.new_vo)
        else:
            LOG.warning('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode will result in failures.')
            cls.vo = {}
            cls.new_vo = {}

    def test_access_rule(self):
        """ MULTI VO (CORE): Test accessing rules from a different VO """
        scope = InternalScope('mock', **self.vo)
        dataset = 'dataset_' + str(generate_uuid())
        account = InternalAccount('root', **self.vo)
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        rse_name = 'MOCK_%s' % rse_str
        add_rse(rse_name, 'root', **self.vo)
        add_did('mock', dataset, 'DATASET', 'root', **self.vo)
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=account, copies=0, rse_expression=rse_name, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        with assert_raises(AccessDenied):
            delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', **self.new_vo)
        delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', **self.vo)
        rule_dict = get_replication_rule(rule_id=rule_id, issuer='root', **self.vo)
        assert_is_not_none(rule_dict['expires_at'])

    def test_add_vo(self):
        """ MULTI VO (CORE): Test creation of VOs """
        with assert_raises(AccessDenied):
            vo_api.add_vo(self.new_vo['vo'], 'root', 'Add new VO with root', 'rucio@email.com', **self.vo)
        with assert_raises(Duplicate):
            vo_api.add_vo(self.new_vo['vo'], 'super_root', 'Add existing VO', 'rucio@email.com', 'def')

    def test_recover_root_identity(self):
        """ MULTI VO (CORE): Test adding a new identity for root using super_root """
        identity_key = ''.join(choice(ascii_lowercase) for x in range(10))
        with assert_raises(AccessDenied):
            vo_api.recover_vo_root_identity(root_vo=self.new_vo['vo'], identity_key=identity_key, id_type='userpass', email='rucio@email.com', issuer='root', password='password', **self.vo)
        vo_api.recover_vo_root_identity(root_vo=self.new_vo['vo'], identity_key=identity_key, id_type='userpass', email='rucio@email.com', issuer='super_root', password='password', vo='def')
        assert_in('root', list_accounts_for_identity(identity_key=identity_key, id_type='userpass'))

    def test_update_vo(self):
        """ MULTI VO (CORE): Test updating VOs """
        description = generate_uuid()
        email = generate_uuid()
        parameters = {'vo': self.new_vo['vo'], 'description': description, 'email': email}
        with assert_raises(AccessDenied):
            vo_api.update_vo(self.new_vo['vo'], parameters, 'root', **self.vo)
        vo_api.update_vo(self.new_vo['vo'], parameters, 'super_root', 'def')
        vo_update_success = False
        for v in vo_api.list_vos('super_root', 'def'):
            if v['vo'] == parameters['vo']:
                assert_equal(email, v['email'])
                assert_equal(description, v['description'])
                vo_update_success = True
        assert_true(vo_update_success)

    def test_super_root_permissions(self):
        """ MULTI VO (CORE): Test super_root cannot access root/user functions """
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        rse_name = 'MOCK_%s' % rse_str
        scope_uuid = str(generate_uuid()).lower()[:16]
        scope = 'mock_%s' % scope_uuid

        # Test an account name that exists at one VO cannot be found if paired with a different VO
        with assert_raises(AccountNotFound):
            add_scope(scope, 'super_root', 'super_root', **self.vo)

        # Test super_root@def with functions at vo='def'
        with assert_raises(AccessDenied):
            add_rse(rse_name, 'super_root', vo='def')
        with assert_raises(AccessDenied):
            add_scope(scope, 'root', 'super_root', vo='def')
        add_scope(scope, 'super_root', 'super_root', vo='def')
        assert_in(scope, [s for s in list_scopes(filter={}, vo='def')])

        # Test the permissions of a user account with name super_root
        if not account_exists('super_root', **self.new_vo):
            add_account('super_root', 'USER', 'rucio@email.com', 'root', **self.new_vo)
        with assert_raises(AccessDenied):
            vo_api.list_vos('super_root', **self.new_vo)
        with assert_raises(AccessDenied):
            add_rse(rse_name, 'super_root', **self.new_vo)
        with assert_raises(AccessDenied):
            add_scope(scope, 'root', 'super_root', **self.new_vo)
        add_scope(scope, 'super_root', 'super_root', **self.new_vo)
        assert_in(scope, [s for s in list_scopes(filter={}, **self.new_vo)])


class TestMultiVoClients(object):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': 'tst'}
            cls.new_vo = {'vo': 'new'}
            if not vo_exists(**cls.new_vo):
                add_vo(description='Test', email='rucio@email.com', **cls.new_vo)
        else:
            LOG.warning('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode will result in failures.')
            cls.vo = {}
            cls.new_vo = {}

    def test_get_vo_from_config(self):
        """ MULTI VO (CLIENT): Get vo from config file when starting clients """
        # Start clients with vo explicitly set to None
        replica_client = ReplicaClient(vo=None)
        client = Client(vo=None)
        upload_client = UploadClient(_client=client)
        # Check the vo has been got from the config file
        assert_equal(replica_client.vo, self.vo['vo'])
        assert_equal(upload_client.client.vo, self.vo['vo'])

    def test_accounts_at_different_vos(self):
        """ MULTI VO (CLIENT): Test that accounts from 2nd vo don't interfere """
        account_client = AccountClient()
        usr_uuid = str(generate_uuid()).lower()[:16]
        tst = 'tst-%s' % usr_uuid
        new = 'new-%s' % usr_uuid
        shr = 'shr-%s' % usr_uuid
        account_client.add_account(tst, 'USER', 'rucio@email.com')
        account_client.add_account(shr, 'USER', 'rucio@email.com')
        add_account(new, 'USER', 'rucio@email.com', 'root', **self.new_vo)
        add_account(shr, 'USER', 'rucio@email.com', 'root', **self.new_vo)
        account_list_tst = [a['account'] for a in account_client.list_accounts()]
        account_list_new = [a['account'] for a in list_accounts(filter={}, **self.new_vo)]
        assert_true(tst in account_list_tst)
        assert_false(new in account_list_tst)
        assert_true(shr in account_list_tst)
        assert_false(tst in account_list_new)
        assert_true(new in account_list_new)
        assert_true(shr in account_list_new)

    def test_dids_at_different_vos(self):
        """ MULTI VO (CLIENT): Test that dids from 2nd vo don't interfere """
        scope_uuid = str(generate_uuid()).lower()[:16]
        scope = 'shr_%s' % scope_uuid
        add_scope(scope, 'root', 'root', **self.vo)
        add_scope(scope, 'root', 'root', **self.new_vo)
        did_client = DIDClient()
        did_uuid = str(generate_uuid()).lower()[:16]
        tst = 'tstset_%s' % did_uuid
        new = 'newset_%s' % did_uuid
        shr = 'shrset_%s' % did_uuid
        did_client.add_did(scope, tst, 'DATASET')
        did_client.add_did(scope, shr, 'DATASET')
        add_did(scope, new, 'DATASET', 'root', **self.new_vo)
        add_did(scope, shr, 'DATASET', 'root', **self.new_vo)
        did_list_tst = [d for d in did_client.list_dids(scope, {})]
        did_list_new = [d for d in list_dids(scope, {}, **self.new_vo)]
        assert_true(tst in did_list_tst)
        assert_false(new in did_list_tst)
        assert_true(shr in did_list_tst)
        assert_false(tst in did_list_new)
        assert_true(new in did_list_new)
        assert_true(shr in did_list_new)

    def test_rses_at_different_vos(self):
        """ MULTI VO (CLIENT): Test that RSEs from 2nd vo don't interfere """
        rse_client = RSEClient()
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        tst = 'TST_%s' % rse_str
        new = 'NEW_%s' % rse_str
        shr = 'SHR_%s' % rse_str
        rse_client.add_rse(tst)
        rse_client.add_rse(shr)
        add_rse(new, 'root', **self.new_vo)
        add_rse(shr, 'root', **self.new_vo)
        rse_list_tst = [r['rse'] for r in rse_client.list_rses()]
        rse_list_new = [r['rse'] for r in list_rses(filters={}, **self.new_vo)]
        assert_true(tst in rse_list_tst)
        assert_false(new in rse_list_tst)
        assert_true(shr in rse_list_tst)
        assert_false(tst in rse_list_new)
        assert_true(new in rse_list_new)
        assert_true(shr in rse_list_new)

    def test_scopes_at_different_vos(self):
        """ MULTI VO (CLIENT): Test that scopes from 2nd vo don't interfere """
        scope_client = ScopeClient()
        scope_uuid = str(generate_uuid()).lower()[:16]
        tst = 'tst_%s' % scope_uuid
        new = 'new_%s' % scope_uuid
        shr = 'shr_%s' % scope_uuid
        scope_client.add_scope('root', tst)
        scope_client.add_scope('root', shr)
        add_scope(new, 'root', 'root', **self.new_vo)
        add_scope(shr, 'root', 'root', **self.new_vo)
        scope_list_tst = [s for s in scope_client.list_scopes()]
        scope_list_new = [s for s in list_scopes(filter={}, **self.new_vo)]
        assert_true(tst in scope_list_tst)
        assert_false(new in scope_list_tst)
        assert_true(shr in scope_list_tst)
        assert_false(tst in scope_list_new)
        assert_true(new in scope_list_new)
        assert_true(shr in scope_list_new)

    def test_subscriptions_at_different_vos(self):
        """ MULTI VO (CLIENT): Test that subscriptions from 2nd vo don't interfere """

        account_client = AccountClient()
        usr_uuid = str(generate_uuid()).lower()[:16]
        shr_acc = 'shr-%s' % usr_uuid
        account_client.add_account(shr_acc, 'USER', 'rucio@email.com')
        add_account(shr_acc, 'USER', 'rucio@email.com', 'root', **self.new_vo)

        scope_client = ScopeClient()
        scope_uuid = str(generate_uuid()).lower()[:16]
        tst_scope = 'tst_%s' % scope_uuid
        new_scope = 'new_%s' % scope_uuid
        scope_client.add_scope('root', tst_scope)
        add_scope(new_scope, 'root', 'root', **self.new_vo)

        did_client = DIDClient()
        did_uuid = str(generate_uuid()).lower()[:16]
        tst_did = 'tstset_%s' % did_uuid
        new_did = 'newset_%s' % did_uuid

        rse_client = RSEClient()
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        tst_rse1 = 'TST1_%s' % rse_str
        tst_rse2 = 'TST2_%s' % rse_str
        new_rse1 = 'NEW1_%s' % rse_str
        new_rse2 = 'NEW2_%s' % rse_str
        rse_client.add_rse(tst_rse1)
        rse_client.add_rse(tst_rse2)
        add_rse(new_rse1, 'root', **self.new_vo)
        add_rse(new_rse2, 'root', **self.new_vo)

        acc_lim_client = AccountLimitClient()
        acc_lim_client.set_local_account_limit(shr_acc, tst_rse1, 10)
        acc_lim_client.set_local_account_limit(shr_acc, tst_rse2, 10)
        set_local_account_limit(shr_acc, new_rse1, 10, 'root', **self.new_vo)
        set_local_account_limit(shr_acc, new_rse2, 10, 'root', **self.new_vo)

        did_client.add_did(tst_scope, tst_did, 'DATASET', rse=tst_rse1)
        add_did(new_scope, new_did, 'DATASET', 'root', rse=new_rse1, **self.new_vo)

        sub_client = SubscriptionClient()
        sub_str = generate_uuid()
        tst_sub = 'tstsub_' + sub_str
        new_sub = 'newsub_' + sub_str
        shr_sub = 'shrsub_' + sub_str

        tst_sub_id = sub_client.add_subscription(tst_sub, shr_acc, {'scope': [tst_scope]},
                                                 [{'copies': 1, 'rse_expression': tst_rse2, 'weight': 0,
                                                   'activity': 'User Subscriptions'}],
                                                 '', None, 0, 0)
        shr_tst_sub_id = sub_client.add_subscription(shr_sub, shr_acc, {'scope': [tst_scope]},
                                                     [{'copies': 1, 'rse_expression': tst_rse2, 'weight': 0,
                                                       'activity': 'User Subscriptions'}],
                                                     '', None, 0, 0)

        new_sub_id = add_subscription(new_sub, shr_acc, {'scope': [new_scope]},
                                      [{'copies': 1, 'rse_expression': new_rse2, 'weight': 0, 'activity': 'User Subscriptions'}],
                                      '', False, 0, 0, 3, 'root', **self.new_vo)
        shr_new_sub_id = add_subscription(shr_sub, shr_acc, {'scope': [new_scope]},
                                          [{'copies': 1, 'rse_expression': new_rse2, 'weight': 0, 'activity': 'User Subscriptions'}],
                                          '', False, 0, 0, 3, 'root', **self.new_vo)

        tst_subs = [s['id'] for s in sub_client.list_subscriptions()]
        assert_in(tst_sub_id, tst_subs)
        assert_in(shr_tst_sub_id, tst_subs)
        assert_not_in(new_sub_id, tst_subs)
        assert_not_in(shr_new_sub_id, tst_subs)

        new_subs = [s['id'] for s in list_subscriptions(**self.new_vo)]
        assert_in(new_sub_id, new_subs)
        assert_in(shr_new_sub_id, new_subs)
        assert_not_in(tst_sub_id, new_subs)
        assert_not_in(shr_tst_sub_id, new_subs)

        shr_tst_subs = [s['id'] for s in sub_client.list_subscriptions(name=shr_sub)]
        assert_in(shr_tst_sub_id, shr_tst_subs)
        assert_not_in(shr_new_sub_id, shr_tst_subs)

        shr_new_subs = [s['id'] for s in list_subscriptions(name=shr_sub, **self.new_vo)]
        assert_in(shr_new_sub_id, shr_new_subs)
        assert_not_in(shr_tst_sub_id, shr_new_subs)

        acc_tst_subs = [s['id'] for s in sub_client.list_subscriptions(account=shr_acc)]
        assert_in(tst_sub_id, acc_tst_subs)
        assert_in(shr_tst_sub_id, acc_tst_subs)
        assert_not_in(new_sub_id, acc_tst_subs)
        assert_not_in(shr_new_sub_id, acc_tst_subs)

        acc_new_subs = [s['id'] for s in list_subscriptions(account=shr_acc, **self.new_vo)]
        assert_in(new_sub_id, acc_new_subs)
        assert_in(shr_new_sub_id, acc_new_subs)
        assert_not_in(tst_sub_id, acc_new_subs)
        assert_not_in(shr_tst_sub_id, acc_new_subs)
