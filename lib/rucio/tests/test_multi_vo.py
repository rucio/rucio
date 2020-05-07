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

from nose.tools import assert_equal, assert_false, assert_in, assert_is_not_none, assert_raises, assert_true
from random import choice
from string import ascii_uppercase

from rucio.api import vo as vo_api
from rucio.api.account import add_account, list_accounts
from rucio.api.did import add_did, list_dids
from rucio.api.identity import list_accounts_for_identity
from rucio.api.rse import add_rse, list_rses
from rucio.api.rule import delete_replication_rule, get_replication_rule
from rucio.api.scope import add_scope, list_scopes
from rucio.client.accountclient import AccountClient
from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.rseclient import RSEClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.scopeclient import ScopeClient
from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get_bool
from rucio.common.exception import AccessDenied, Duplicate
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.did import add_did
from rucio.core.rule import add_rule
from rucio.core.vo import add_vo
from rucio.db.sqla.constants import DIDType


class TestVOCoreAPI(object):

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': 'tst'}
            self.new_vo = generate_uuid()[:3]
        else:
            self.vo = {}

    def test_access_rule(self):
        """ MULTI VO (CORE): Test accessing rules from a different VO """
        scope = InternalScope('mock', **self.vo)
        dataset = 'dataset_' + str(generate_uuid())
        account = InternalAccount('root', **self.vo)
        add_did(scope, dataset, DIDType.from_sym('DATASET'), account)
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=account, copies=1, rse_expression='MOCK', grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        vo_api.add_vo(self.new_vo, 'super_root', 'Add new VO with super_root', 'rucio@email.com', 'def')
        with assert_raises(AccessDenied):
            delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', vo=self.new_vo)
        delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', **self.vo)
        rule_dict = get_replication_rule(rule_id=rule_id, issuer='root', **self.vo)
        assert_is_not_none(rule_dict['expires_at'])

    def test_add_vo(self):
        """ MULTI VO (CORE): Test creation of VOs """
        with assert_raises(AccessDenied):
            vo_api.add_vo(self.new_vo, 'root', 'Add new VO with root', 'rucio@email.com', **self.vo)
        vo_api.add_vo(self.new_vo, 'super_root', 'Add new VO with super_root', 'rucio@email.com', 'def')
        with assert_raises(Duplicate):
            vo_api.add_vo(self.new_vo, 'super_root', 'Add existing VO', 'rucio@email.com', 'def')
        vo_list = [v['vo'] for v in vo_api.list_vos('super_root', 'def')]
        assert_in(self.new_vo, vo_list)

    def test_recover_root_identity(self):
        """ MULTI VO (CORE): Test adding a new identity for root using super_root """
        vo_api.add_vo(self.new_vo, 'super_root', 'Add new VO with super_root', 'rucio@email.com', 'def')
        with assert_raises(AccessDenied):
            vo_api.recover_vo_root_identity(root_vo=self.new_vo, identity_key='recovered@%s' % self.new_vo, id_type='userpass',
                                            email='rucio@email.com', issuer='root', password='password', vo=self.new_vo)
        vo_api.recover_vo_root_identity(root_vo=self.new_vo, identity_key='recovered@%s' % self.new_vo, id_type='userpass',
                                        email='rucio@email.com', issuer='super_root', password='password', vo='def')
        assert_in('root', list_accounts_for_identity(identity_key='recovered@%s' % self.new_vo, id_type='userpass'))

    def test_update_vo(self):
        """ MULTI VO (CORE): Test updating VOs """
        vo_api.add_vo(self.new_vo, 'super_root', 'Add new VO with super_root', 'rucio@email.com', 'def')
        parameters = {'vo': self.new_vo, 'description': 'Updated description', 'email': 'updated@email.com'}
        with assert_raises(AccessDenied):
            vo_api.update_vo(self.new_vo, parameters, 'root', **self.vo)
        vo_api.update_vo(self.new_vo, parameters, 'super_root', 'def')
        vo_update_success = False
        for v in vo_api.list_vos('super_root', 'def'):
            if v['vo'] == parameters['vo']:
                assert_equal(parameters['email'], v['email'])
                assert_equal(parameters['description'], v['description'])
                vo_update_success = True
        assert_true(vo_update_success)


class TestMultiVoClients(object):

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': 'tst'}
            self.new_vo = {'vo': 'new'}
            try:
                add_vo(description='Test', email='rucio@email.com', **self.new_vo)
            except Duplicate:
                print('VO "%s" already exists' % self.new_vo['vo'])
        else:
            self.vo = {}
            self.new_vo = {}

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
