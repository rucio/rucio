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
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020

from json import dumps
from logging import getLogger
from mock import patch
from nose.tools import assert_equal, assert_false, assert_in, assert_is_not_none, assert_not_equal, assert_not_in, assert_raises, assert_true
from oic import rndstr
from os import remove
from paste.fixture import TestApp
from random import choice
from re import search
from string import ascii_uppercase, ascii_lowercase
try:
    # Python 2
    from urlparse import urlparse, parse_qs
except ImportError:
    # Python 3
    from urllib.parse import urlparse, parse_qs

from rucio.api import vo as vo_api
from rucio.api.account import add_account, list_accounts
from rucio.api.account_limit import set_local_account_limit
from rucio.api.authentication import get_auth_token_gss, get_auth_token_saml, get_auth_token_x509
from rucio.api.did import add_did, list_dids
from rucio.api.identity import add_account_identity, list_accounts_for_identity
from rucio.api.lock import get_replica_locks_for_rule_id
from rucio.api.replica import list_replicas
from rucio.api.rse import add_protocol, add_rse, add_rse_attribute, list_rses
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
from rucio.common.config import config_get, config_get_bool, config_remove_option, config_set
from rucio.common.exception import AccessDenied, Duplicate, InvalidRSEExpression, UnsupportedAccountName, UnsupportedOperation
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, get_tmp_dir, parse_response, ssh_sign
from rucio.core.replica import add_replica
from rucio.core.rse import get_rses_with_attribute_value, get_rse_id, get_rse_vo
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import add_rule
from rucio.core.vo import add_vo, vo_exists
from rucio.daemons.automatix.automatix import automatix
from rucio.db.sqla import models, session as db_session
from rucio.tests.common import execute
from rucio.tests.test_authentication import PRIVATE_KEY, PUBLIC_KEY
from rucio.tests.test_oidc import get_mock_oidc_client, NEW_TOKEN_DICT
from rucio.web.rest.account import APP as account_app
from rucio.web.rest.authentication import APP as auth_app
from rucio.web.rest.vo import APP as vo_app


LOG = getLogger(__name__)


class TestVOCoreAPI(object):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            cls.new_vo = {'vo': 'new'}
            if not vo_exists(**cls.new_vo):
                add_vo(description='Test', email='rucio@email.com', **cls.new_vo)
        else:
            LOG.warning('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode will result in failures.')
            cls.vo = {}
            cls.new_vo = {}

    def test_multi_vo_flag(self):
        """ MULTI VO (CORE): Test operations fail in single_vo mode """
        try:
            config_set('common', 'multi_vo', 'False')
            with assert_raises(UnsupportedOperation):
                vo_api.list_vos(issuer='super_root', vo='def')
            config_remove_option('common', 'multi_vo')
            with assert_raises(UnsupportedOperation):
                vo_api.list_vos(issuer='super_root', vo='def')
        finally:
            # Make sure we don't leave the config changed due to a test failure
            if self.vo:
                config_set('common', 'multi_vo', 'True')
            else:
                config_remove_option('common', 'multi_vo')

    def test_access_rule_vo(self):
        """ MULTI VO (CORE): Test accessing rules from a different VO """
        scope = InternalScope('mock', **self.vo)
        dataset = 'dataset_' + str(generate_uuid())
        account = InternalAccount('root', **self.vo)
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        rse_name = 'MOCK_%s' % rse_str
        rse_id = add_rse(rse_name, 'root', **self.vo)

        add_replica(rse_id=rse_id, scope=scope, name=dataset, bytes=10, account=account)
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=account, copies=1, rse_expression='MOCK', grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        with assert_raises(AccessDenied):
            delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', **self.new_vo)

        # check locks are not accessible from other VO
        locks = list(get_replica_locks_for_rule_id(rule_id, **self.vo))
        assert_equal(len(locks), 1)
        locks = list(get_replica_locks_for_rule_id(rule_id, **self.new_vo))
        assert_equal(len(locks), 0)

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

        # Test super_root@def with functions at vo='def'
        with assert_raises(AccessDenied):
            add_rse(rse_name, 'super_root', vo='def')
        with assert_raises(AccessDenied):
            add_scope(scope, 'root', 'super_root', vo='def')
        add_scope(scope, 'super_root', 'super_root', vo='def')
        assert_in(scope, [s for s in list_scopes(filter={}, vo='def')])

    def test_super_root_naming(self):
        """ MULTI VO (CORE): Test we can only name accounts super_root when appropriate """
        with assert_raises(Duplicate):  # Ensure we fail from duplication rather than the choice of name
            add_account('super_root', 'USER', 'rucio@email.com', 'root', vo='def')
        with assert_raises(UnsupportedAccountName):
            add_account('super_root', 'USER', 'rucio@email.com', 'root', **self.vo)
        try:
            config_remove_option('common', 'multi_vo')
            with assert_raises(UnsupportedAccountName):
                add_account('super_root', 'USER', 'rucio@email.com', 'root', **self.vo)
            with assert_raises(UnsupportedAccountName):
                add_account('super_root', 'USER', 'rucio@email.com', 'root', vo='def')
        finally:
            # Make sure we don't leave the config changed due to a test failure
            if self.vo:
                config_set('common', 'multi_vo', 'True')
            else:
                config_remove_option('common', 'multi_vo')


class TestVORestAPI(object):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            cls.new_vo = {'vo': 'new'}
            cls.def_header = {'X-Rucio-VO': 'def'}
            cls.vo_header = {'X-Rucio-VO': cls.vo['vo']}
            cls.new_header = {'X-Rucio-VO': 'new'}
            if not vo_exists(**cls.new_vo):
                add_vo(description='Test', email='rucio@email.com', **cls.new_vo)

            # Setup accounts at two VOs so we can determine which VO we authenticated against
            usr_uuid = str(generate_uuid()).lower()[:16]
            cls.account_tst = 'tst-%s' % usr_uuid
            cls.account_new = 'new-%s' % usr_uuid
            add_account(cls.account_tst, 'USER', 'rucio@email.com', 'root', **cls.vo)
            add_account(cls.account_new, 'USER', 'rucio@email.com', 'root', **cls.new_vo)

        else:
            LOG.warning('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode will result in failures.')
            cls.vo = {}
            cls.new_vo = {}
            cls.def_header = {}
            cls.vo_header = {}
            cls.new_header = {}
            cls.account_tst = ''
            cls.account_new = ''

    def auth_oidc_handling(self, mock_oidc_client, vo, account_in, account_not_in, auto, polling):
        """
        Utility script to handle the REST calls with various urls and codes needed to authenticate via OIDC.
        IdP responses are faked using code from `test_oidc.py`.

        :param mock_oidc_client: Mock OIDC client used to fake responses from the IdP for test purposes.
        :param vo: Dictionary containing the VO to authenticate against under the key 'vo'.
        :param account_in: A string (externally) representing an account we DO expect to find at the VO.
        :param account_not_in: A string (externally) representing an account we DO NOT expect to find at the VO.
        :param auto: Boolean to specify whether we automatically submit userpass to the IdP as part of authentication.
        :param auto: Boolean to specify whether we poll the IdP for a successful login as part of authentication.
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        mw = []

        try:
            add_account_identity('SUB=knownsub, ISS=https://test_issuer/', 'OIDC', 'root', 'rucio_test@test.com', 'root', **vo)
        except Duplicate:
            pass  # Might already exist, can skip

        # Define headers
        headers = {'X-Rucio-Account': 'root',
                   'X-Rucio-VO': vo['vo'],
                   'X-Rucio-Client-Authorize-Auto': str(auto),
                   'X-Rucio-Client-Authorize-Polling': str(polling),
                   'X-Rucio-Client-Authorize-Scope': 'openid profile',
                   'X-Rucio-Client-Authorize-Refresh-Lifetime': '96',
                   'X-Rucio-Client-Authorize-Audience': 'rucio',
                   'X-Rucio-Client-Authorize-Issuer': 'dummy_admin_iss_nickname'}

        res = TestApp(auth_app.wsgifunc(*mw)).get('/oidc', headers=headers, expect_errors=True)
        assert_equal(res.status, 200)
        if auto:
            # Get the auth_url without any redirect
            auth_url = res.header('X-Rucio-OIDC-Auth-URL')
        else:
            # Get the redirect_url
            redirect_url = res.header('X-Rucio-OIDC-Auth-URL')
            assert_in('https://test_redirect_string/auth/oidc_redirect?', redirect_url)
            if polling:
                assert_in('_polling', redirect_url)
            else:
                assert_not_in('_polling', redirect_url)
            redirect_url_parsed = urlparse(redirect_url)

            # Get the auth_url from the redirect_url
            res = TestApp(auth_app.wsgifunc(*mw)).get('/oidc_redirect?%s' % redirect_url_parsed.query, headers=headers, expect_errors=True)
            assert_equal(res.status, 303)
            auth_url = res.header('location')

        assert_in('https://test_auth_url_string?', auth_url)
        auth_url_parsed = urlparse(auth_url)
        auth_url_params = parse_qs(auth_url_parsed.query)

        # Fake the IdP response for a successful login
        code_response = rndstr()
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_url_params['nonce'][0]}
        headers['X-Rucio-Client-Fetch-Token'] = 'True'

        if auto:
            # Can get the token now
            res = TestApp(auth_app.wsgifunc(*mw)).get('/oidc_token?state=%s&code=%s' % (auth_url_params['state'][0], code_response), headers=headers, expect_errors=True)
        else:
            # Get the html response
            res = TestApp(auth_app.wsgifunc(*mw)).get('/oidc_code?state=%s&code=%s' % (auth_url_params['state'][0], code_response), headers=headers, expect_errors=True)
            assert_equal(res.status, 200)
            split_res = res.body.decode().split('\n')
            if polling:
                # Check the response is OK, then poll the original redirect_url for the token
                for text in split_res:
                    ok_code = search('Rucio Client should now be able to fetch your token automatically.', text)
                    if ok_code:
                        ok_code = ok_code.group()
                        break
                assert_is_not_none(ok_code)
                res = TestApp(auth_app.wsgifunc(*mw)).get('/oidc_redirect?%s' % redirect_url_parsed.query, headers=headers, expect_errors=True)
            else:
                # Get the fetch_code from the response, then submit it
                for text in split_res:
                    fetch_code = search(r'<b>[a-zA-Z0-9]{50}</b>', text)
                    if fetch_code:
                        fetch_code = fetch_code.group()[3:53]
                        break
                assert_is_not_none(fetch_code)
                res = TestApp(auth_app.wsgifunc(*mw)).get('/oidc_redirect?%s' % fetch_code, headers=headers, expect_errors=True)

        # Regardless of how we got it, check we have the token and that we only get results from our VO when using it
        assert_equal(res.status, 200)
        token = str(res.header('X-Rucio-Auth-Token'))
        headers = {'X-Rucio-Auth-Token': str(token)}
        res = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers, expect_errors=True)
        assert_equal(res.status, 200)
        accounts = [parse_response(a)['account'] for a in res.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts), 0)
        assert_in(account_in, accounts)
        assert_not_in(account_not_in, accounts)

    @patch('rucio.core.oidc.__get_init_oidc_client')
    def test_auth_oidc(self, mock_oidc_client):
        """ MULTI VO (REST): Test oidc authentication to multiple VOs """
        self.auth_oidc_handling(mock_oidc_client, self.vo, self.account_tst, self.account_new, auto=False, polling=False)
        self.auth_oidc_handling(mock_oidc_client, self.new_vo, self.account_new, self.account_tst, auto=False, polling=False)

    @patch('rucio.core.oidc.__get_init_oidc_client')
    def test_auth_oidc_polling(self, mock_oidc_client):
        """ MULTI VO (REST): Test oidc authentication to multiple VOs using 'polling' option """
        self.auth_oidc_handling(mock_oidc_client, self.vo, self.account_tst, self.account_new, auto=False, polling=True)
        self.auth_oidc_handling(mock_oidc_client, self.new_vo, self.account_new, self.account_tst, auto=False, polling=True)

    @patch('rucio.core.oidc.__get_init_oidc_client')
    def test_auth_oidc_auto(self, mock_oidc_client):
        """ MULTI VO (REST): Test oidc authentication to multiple VOs using 'auto' option """
        self.auth_oidc_handling(mock_oidc_client, self.vo, self.account_tst, self.account_new, auto=True, polling=False)
        self.auth_oidc_handling(mock_oidc_client, self.new_vo, self.account_new, self.account_tst, auto=True, polling=False)

    def test_auth_gss(self):
        """ MULTI VO (REST): Test gss authentication to multiple VOs """
        mw = []

        # Can't rely on `requests_kerberos` module being present, so get tokens from API instead
        token_tst = get_auth_token_gss('root', 'rucio-dev@CERN.CH', 'unknown', None, **self.vo).token
        token_new = get_auth_token_gss('root', 'rucio-dev@CERN.CH', 'unknown', None, **self.new_vo).token

        headers_tst = {'X-Rucio-Auth-Token': str(token_tst)}
        res_tst = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_tst, expect_errors=True)
        assert_equal(res_tst.status, 200)
        accounts_tst = [parse_response(a)['account'] for a in res_tst.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_tst), 0)
        assert_in(self.account_tst, accounts_tst)
        assert_not_in(self.account_new, accounts_tst)

        headers_new = {'X-Rucio-Auth-Token': str(token_new)}
        res_new = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_new, expect_errors=True)
        assert_equal(res_new.status, 200)
        accounts_new = [parse_response(a)['account'] for a in res_new.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_new), 0)
        assert_in(self.account_new, accounts_new)
        assert_not_in(self.account_tst, accounts_new)

    def test_auth_saml(self):
        """ MULTI VO (REST): Test saml authentication to multiple VOs """
        mw = []

        try:
            add_account_identity('ddmlab', 'SAML', 'root', 'rucio@email.com', 'root', **self.vo)
            add_account_identity('ddmlab', 'SAML', 'root', 'rucio@email.com', 'root', **self.new_vo)
        except Duplicate:
            pass  # Might already exist, can skip

        # Can't rely on `onelogin` module being present, so get tokens from API instead
        token_tst = get_auth_token_saml('root', 'ddmlab', 'unknown', None, **self.vo).token
        token_new = get_auth_token_saml('root', 'ddmlab', 'unknown', None, **self.new_vo).token

        headers_tst = {'X-Rucio-Auth-Token': str(token_tst)}
        res_tst = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_tst, expect_errors=True)
        assert_equal(res_tst.status, 200)
        accounts_tst = [parse_response(a)['account'] for a in res_tst.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_tst), 0)
        assert_in(self.account_tst, accounts_tst)
        assert_not_in(self.account_new, accounts_tst)

        headers_new = {'X-Rucio-Auth-Token': str(token_new)}
        res_new = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_new, expect_errors=True)
        assert_equal(res_new.status, 200)
        accounts_new = [parse_response(a)['account'] for a in res_new.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_new), 0)
        assert_in(self.account_new, accounts_new)
        assert_not_in(self.account_tst, accounts_new)

    def test_auth_ssh(self):
        """ MULTI VO (REST): Test ssh authentication to multiple VOs """
        mw = []

        try:
            add_account_identity(PUBLIC_KEY, 'SSH', 'root', 'rucio@email.com', 'root', **self.vo)
            add_account_identity(PUBLIC_KEY, 'SSH', 'root', 'rucio@email.com', 'root', **self.new_vo)
        except Duplicate:
            pass  # Might already exist, can skip

        headers_tst = {'X-Rucio-Account': 'root'}
        headers_tst.update(self.vo_header)
        res_tst = TestApp(auth_app.wsgifunc(*mw)).get('/ssh_challenge_token', headers=headers_tst, expect_errors=True)
        assert_equal(res_tst.status, 200)
        challenge_tst = str(res_tst.header('X-Rucio-SSH-Challenge-Token'))
        headers_tst.update({'X-Rucio-SSH-Signature': ssh_sign(PRIVATE_KEY, challenge_tst)})
        res_tst = TestApp(auth_app.wsgifunc(*mw)).get('/ssh', headers=headers_tst, expect_errors=True)
        assert_equal(res_tst.status, 200)
        token_tst = str(res_tst.header('X-Rucio-Auth-Token'))

        headers_new = {'X-Rucio-Account': 'root'}
        headers_new.update(self.new_header)
        res_new = TestApp(auth_app.wsgifunc(*mw)).get('/ssh_challenge_token', headers=headers_new, expect_errors=True)
        assert_equal(res_new.status, 200)
        challenge_tst = str(res_new.header('X-Rucio-SSH-Challenge-Token'))
        headers_new.update({'X-Rucio-SSH-Signature': ssh_sign(PRIVATE_KEY, challenge_tst)})
        res_new = TestApp(auth_app.wsgifunc(*mw)).get('/ssh', headers=headers_new, expect_errors=True)
        assert_equal(res_new.status, 200)
        token_new = str(res_new.header('X-Rucio-Auth-Token'))

        headers_tst = {'X-Rucio-Auth-Token': str(token_tst)}
        res_tst = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_tst, expect_errors=True)
        assert_equal(res_tst.status, 200)
        accounts_tst = [parse_response(a)['account'] for a in res_tst.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_tst), 0)
        assert_in(self.account_tst, accounts_tst)
        assert_not_in(self.account_new, accounts_tst)

        headers_new = {'X-Rucio-Auth-Token': str(token_new)}
        res_new = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_new, expect_errors=True)
        assert_equal(res_new.status, 200)
        accounts_new = [parse_response(a)['account'] for a in res_new.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_new), 0)
        assert_in(self.account_new, accounts_new)
        assert_not_in(self.account_tst, accounts_new)

    def test_auth_userpass(self):
        """ MULTI VO (REST): Test userpass authentication to multiple VOs """
        mw = []

        headers_tst = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers_tst.update(self.vo_header)
        res_tst = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers_tst, expect_errors=True)
        assert_equal(res_tst.status, 200)
        token_tst = str(res_tst.header('X-Rucio-Auth-Token'))

        headers_new = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers_new.update(self.new_header)
        res_new = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers_new, expect_errors=True)
        assert_equal(res_new.status, 200)
        token_new = str(res_new.header('X-Rucio-Auth-Token'))

        headers_tst = {'X-Rucio-Auth-Token': str(token_tst)}
        res_tst = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_tst, expect_errors=True)
        assert_equal(res_tst.status, 200)
        accounts_tst = [parse_response(a)['account'] for a in res_tst.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_tst), 0)
        assert_in(self.account_tst, accounts_tst)
        assert_not_in(self.account_new, accounts_tst)

        headers_new = {'X-Rucio-Auth-Token': str(token_new)}
        res_new = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_new, expect_errors=True)
        assert_equal(res_new.status, 200)
        accounts_new = [parse_response(a)['account'] for a in res_new.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_new), 0)
        assert_in(self.account_new, accounts_new)
        assert_not_in(self.account_tst, accounts_new)

    def test_auth_x509(self):
        """ MULTI VO (REST): Test X509 authentication to multiple VOs """
        mw = []

        # TestApp doesn't support `cert` argument, so get tokens from API instead
        token_tst = get_auth_token_x509('root', '/CN=Rucio User', 'unknown', None, **self.vo).token
        token_new = get_auth_token_x509('root', '/CN=Rucio User', 'unknown', None, **self.new_vo).token

        headers_tst = {'X-Rucio-Auth-Token': str(token_tst)}
        res_tst = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_tst, expect_errors=True)
        assert_equal(res_tst.status, 200)
        accounts_tst = [parse_response(a)['account'] for a in res_tst.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_tst), 0)
        assert_in(self.account_tst, accounts_tst)
        assert_not_in(self.account_new, accounts_tst)

        headers_new = {'X-Rucio-Auth-Token': str(token_new)}
        res_new = TestApp(account_app.wsgifunc(*mw)).get('/', headers=headers_new, expect_errors=True)
        assert_equal(res_new.status, 200)
        accounts_new = [parse_response(a)['account'] for a in res_new.body.decode().split('\n')[:-1]]
        assert_not_equal(len(accounts_new), 0)
        assert_in(self.account_new, accounts_new)
        assert_not_in(self.account_tst, accounts_new)

    def test_list_vos_success(self):
        """ MULTI VO (REST): Test list VOs through REST layer succeeds """
        mw = []

        headers1 = {'X-Rucio-Account': 'super_root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.def_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
        assert_equal(res2.status, 200)
        vo_dicts = [parse_response(r) for r in res2.body.decode().split('\n')[:-1]]
        assert_not_equal(len(vo_dicts), 0)
        for vo_dict in vo_dicts:
            assert_is_not_none(vo_dict['vo'])
            assert_is_not_none(vo_dict['email'])
            assert_is_not_none(vo_dict['description'])
            assert_is_not_none(vo_dict['created_at'])
            assert_is_not_none(vo_dict['updated_at'])

    def test_list_vos_denied(self):
        """ MULTI VO (REST): Test list VOs through REST layer raises AccessDenied """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
        assert_equal(res2.status, 401)

    def test_list_vos_unsupported(self):
        """ MULTI VO (REST): Test list VOs through REST layer raises UnsupportedOperation """
        mw = []

        headers1 = {'X-Rucio-Account': 'super_root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.def_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        try:
            config_set('common', 'multi_vo', 'False')
            headers2 = {'X-Rucio-Auth-Token': str(token)}
            res2 = TestApp(vo_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
            assert_equal(res2.status, 409)

            config_remove_option('common', 'multi_vo')
            headers2 = {'X-Rucio-Auth-Token': str(token)}
            res2 = TestApp(vo_app.wsgifunc(*mw)).get('/', headers=headers2, expect_errors=True)
            assert_equal(res2.status, 409)

        finally:
            # Make sure we don't leave the config changed due to a test failure
            if self.vo:
                config_set('common', 'multi_vo', 'True')
            else:
                config_remove_option('common', 'multi_vo')

    def test_add_vo_denied(self):
        """ MULTI VO (REST): Test adding VO through REST layer raises AccessDenied """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try adding with root'}
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).post('/' + self.vo['vo'], headers=headers2, expect_errors=True, params=dumps(params))
        assert_equal(res2.status, 401)

    def test_add_vo_unsupported(self):
        """ MULTI VO (REST): Test adding VO through REST layer raises UnsupportedOperation """
        mw = []

        headers1 = {'X-Rucio-Account': 'super_root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.def_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try adding in single vo mode'}
        try:
            config_set('common', 'multi_vo', 'False')
            headers2 = {'X-Rucio-Auth-Token': str(token)}
            res2 = TestApp(vo_app.wsgifunc(*mw)).post('/' + self.vo['vo'], headers=headers2, expect_errors=True, params=dumps(params))
            assert_equal(res2.status, 409)

            config_remove_option('common', 'multi_vo')
            headers2 = {'X-Rucio-Auth-Token': str(token)}
            res2 = TestApp(vo_app.wsgifunc(*mw)).post('/' + self.vo['vo'], headers=headers2, expect_errors=True, params=dumps(params))
            assert_equal(res2.status, 409)

        finally:
            # Make sure we don't leave the config changed due to a test failure
            if self.vo:
                config_set('common', 'multi_vo', 'True')
            else:
                config_remove_option('common', 'multi_vo')

    def test_add_vo_duplicate(self):
        """ MULTI VO (REST): Test adding VO through REST layer raises Duplicate """
        mw = []

        headers1 = {'X-Rucio-Account': 'super_root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.def_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try adding duplicate'}
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).post('/' + self.vo['vo'], headers=headers2, expect_errors=True, params=dumps(params))
        assert_equal(res2.status, 409)

    def test_update_vo_success(self):
        """ MULTI VO (REST): Test updating VO through REST layer succeeds """
        mw = []

        headers1 = {'X-Rucio-Account': 'super_root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.def_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        params = {'email': generate_uuid(), 'description': generate_uuid()}
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).put('/' + self.vo['vo'], headers=headers2, expect_errors=True, params=dumps(params))
        assert_equal(res2.status, 200)

        vo_update_success = False
        for v in vo_api.list_vos('super_root', 'def'):
            if v['vo'] == self.vo['vo']:
                assert_equal(params['email'], v['email'])
                assert_equal(params['description'], v['description'])
                vo_update_success = True
        assert_true(vo_update_success)

    def test_update_vo_denied(self):
        """ MULTI VO (REST): Test updating VO through REST layer raises AccessDenied """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try updating with root'}
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).put('/' + self.vo['vo'], headers=headers2, expect_errors=True, params=dumps(params))
        assert_equal(res2.status, 401)

    def test_update_vo_unsupported(self):
        """ MULTI VO (REST): Test updating VO through REST layer raises UnsupportedOperation """
        mw = []

        headers1 = {'X-Rucio-Account': 'super_root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.def_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try updating in single vo mode'}
        try:
            config_set('common', 'multi_vo', 'False')
            headers2 = {'X-Rucio-Auth-Token': str(token)}
            res2 = TestApp(vo_app.wsgifunc(*mw)).put('/' + self.vo['vo'], headers=headers2, expect_errors=True, params=dumps(params))
            assert_equal(res2.status, 409)

            config_remove_option('common', 'multi_vo')
            headers2 = {'X-Rucio-Auth-Token': str(token)}
            res2 = TestApp(vo_app.wsgifunc(*mw)).put('/' + self.vo['vo'], headers=headers2, expect_errors=True, params=dumps(params))
            assert_equal(res2.status, 409)

        finally:
            # Make sure we don't leave the config changed due to a test failure
            if self.vo:
                config_set('common', 'multi_vo', 'True')
            else:
                config_remove_option('common', 'multi_vo')

    def test_update_vo_not_found(self):
        """ MULTI VO (REST): Test updating VO through REST layer raises VONotFound """
        mw = []

        headers1 = {'X-Rucio-Account': 'super_root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.def_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try updating non-existent'}
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).put('/000', headers=headers2, expect_errors=True, params=dumps(params))
        assert_equal(res2.status, 404)

    def test_recover_vo_success(self):
        """ MULTI VO (REST): Test recovering VO through REST layer succeeds """
        mw = []

        headers1 = {'X-Rucio-Account': 'super_root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.def_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        identity_key = ''.join(choice(ascii_lowercase) for x in range(10))
        params = {'identity': identity_key, 'authtype': 'userpass', 'email': 'rucio@email.com', 'password': 'password'}
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).post('/' + self.vo['vo'] + '/recover', headers=headers2, expect_errors=True, params=dumps(params))
        assert_equal(res2.status, 201)

        assert_in('root', list_accounts_for_identity(identity_key=identity_key, id_type='userpass'))

    def test_recover_vo_denied(self):
        """ MULTI VO (REST): Test recovering VO through REST layer raises AccessDenied """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        headers1.update(self.vo_header)
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        identity_key = ''.join(choice(ascii_lowercase) for x in range(10))
        params = {'identity': identity_key, 'authtype': 'userpass', 'email': 'rucio@email.com', 'password': 'password'}
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(vo_app.wsgifunc(*mw)).post('/' + self.vo['vo'] + '/recover', headers=headers2, expect_errors=True, params=dumps(params))
        assert_equal(res2.status, 401)


class TestMultiVoClients(object):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
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
        did_list_tst = list(did_client.list_dids(scope, {}))
        did_list_new = list(list_dids(scope, {}, **self.new_vo))
        assert_true(tst in did_list_tst)
        assert_false(new in did_list_tst)
        assert_true(shr in did_list_tst)
        assert_false(tst in did_list_new)
        assert_true(new in did_list_new)
        assert_true(shr in did_list_new)

    def test_rses_at_different_vos(self):
        """ MULTI VO (CLIENT): Test that RSEs from 2nd vo don't interfere """
        # Set up RSEs at two VOs
        rse_client = RSEClient()
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        tst = 'TST_%s' % rse_str
        new = 'NEW_%s' % rse_str
        shr = 'SHR_%s' % rse_str
        rse_client.add_rse(tst)
        rse_client.add_rse(shr)
        add_rse(new, 'root', **self.new_vo)
        shr_id_new_original = add_rse(shr, 'root', **self.new_vo)  # Accurate rse_id for shared RSE at 'new'

        # Check the cached rse-id from each VO does not interfere
        shr_id_tst = get_rse_id(shr, **self.vo)
        shr_id_new = get_rse_id(shr, **self.new_vo)
        assert_equal(shr_id_new, shr_id_new_original)
        assert_not_equal(shr_id_new, shr_id_tst)

        # Check that when listing RSEs we only get RSEs for our VO
        rse_list_tst = [r['rse'] for r in rse_client.list_rses()]
        rse_list_new = [r['rse'] for r in list_rses(filters={}, **self.new_vo)]
        assert_true(tst in rse_list_tst)
        assert_false(new in rse_list_tst)
        assert_true(shr in rse_list_tst)
        assert_false(tst in rse_list_new)
        assert_true(new in rse_list_new)
        assert_true(shr in rse_list_new)

        # Check the cached attribute-value results do not interfere and only give results from the appropriate VO
        attribute_value = generate_uuid()
        add_rse_attribute(new, 'test', attribute_value, 'root', **self.new_vo)
        rses_tst_1 = list(get_rses_with_attribute_value('test', attribute_value, 'test', **self.vo))
        rses_new_1 = list(get_rses_with_attribute_value('test', attribute_value, 'test', **self.new_vo))
        rses_tst_2 = list(get_rses_with_attribute_value('test', attribute_value, 'test', **self.vo))
        rses_new_2 = list(get_rses_with_attribute_value('test', attribute_value, 'test', **self.new_vo))
        assert_equal(len(rses_tst_1), 0)
        assert_not_equal(len(rses_new_1), 0)
        assert_equal(len(rses_tst_2), 0)
        assert_not_equal(len(rses_new_2), 0)

        # check parse_expression
        rses_tst_3 = parse_expression(shr, filter={'vo': self.vo['vo']})
        rses_tst_4 = parse_expression(tst, filter={'vo': self.vo['vo']})
        rses_new_3 = parse_expression(shr, filter={'vo': self.new_vo['vo']})
        with assert_raises(InvalidRSEExpression):
            parse_expression(tst, filter={'vo': self.new_vo['vo']})
        assert_equal(len(rses_tst_3), 1)
        assert_equal(shr_id_tst, rses_tst_3[0]['id'])
        assert_equal(len(rses_tst_4), 1)
        assert_equal(tst, rses_tst_4[0]['rse'])
        assert_equal(len(rses_new_3), 1)
        assert_equal(shr_id_new, rses_new_3[0]['id'])

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
        scope_list_tst = list(scope_client.list_scopes())
        scope_list_new = list(list_scopes(filter={}, **self.new_vo))
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

    def test_account_counters_at_different_vos(self):
        """ MULTI VO (CLIENT): Test that account counters from 2nd vo don't interfere """

        session = db_session.get_session()

        # add some RSEs to test create_counters_for_new_account
        rse_client = RSEClient()
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        tst_rse1 = 'TST1_%s' % rse_str
        new_rse1 = 'NEW1_%s' % rse_str
        rse_client.add_rse(tst_rse1)
        add_rse(new_rse1, 'root', **self.new_vo)

        # add an account - should have counters created for RSEs on the same VO
        usr_uuid = str(generate_uuid()).lower()[:16]
        new_acc_str = 'shr-%s' % usr_uuid
        new_acc = InternalAccount(new_acc_str, **self.new_vo)
        add_account(new_acc_str, 'USER', 'rucio@email.com', 'root', **self.new_vo)

        query = session.query(models.AccountUsage.account, models.AccountUsage.rse_id).\
            distinct(models.AccountUsage.account, models.AccountUsage.rse_id).\
            filter_by(account=new_acc)
        acc_counters = list(query.all())

        assert_not_equal(0, len(acc_counters))
        for counter in acc_counters:
            rse_id = counter[1]
            vo = get_rse_vo(rse_id)
            assert_equal(vo, self.new_vo['vo'])

        # add an RSE - should have counters created for accounts on the same VO
        new_rse2 = 'NEW2_' + rse_str
        new_rse2_id = add_rse(new_rse2, 'root', **self.new_vo)

        query = session.query(models.AccountUsage.account, models.AccountUsage.rse_id).\
            distinct(models.AccountUsage.account, models.AccountUsage.rse_id).\
            filter_by(rse_id=new_rse2_id)
        rse_counters = list(query.all())

        assert_not_equal(0, len(rse_counters))
        for counter in rse_counters:
            account = counter[0]
            assert_equal(account.vo, self.new_vo['vo'])

        session.commit()


class TestMultiVOBinRucio():

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            cls.new_vo = {'vo': 'new'}
            cls.fake_vo = {'vo': 'fke'}
            if not vo_exists(**cls.new_vo):
                add_vo(description='Test', email='rucio@email.com', **cls.new_vo)

            # Setup RSEs at two VOs so we can determine which VO we authenticated against
            rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
            cls.rse_tst = 'TST_%s' % rse_str
            cls.rse_new = 'NEW_%s' % rse_str
            add_rse(cls.rse_tst, 'root', **cls.vo)
            add_rse(cls.rse_new, 'root', **cls.new_vo)

            try:
                remove(get_tmp_dir() + '/.rucio_root@%s/auth_token_root' % cls.vo['vo'])
            except OSError as e:
                if e.args[0] != 2:
                    raise e
            try:
                remove(get_tmp_dir() + '/.rucio_root@%s/auth_token_root' % cls.new_vo['vo'])
            except OSError as e:
                if e.args[0] != 2:
                    raise e

        else:
            LOG.warning('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode will result in failures.')
            cls.vo = {}
            cls.new_vo = {}
            cls.fake_vo = {}
            cls.rse_tst = ''
            cls.rse_new = ''

        cls.marker = '$> '

    def test_vo_option_admin_cli(self):
        """ MULTI VO (USER): Test authentication to multiple VOs via the admin CLI """
        cmd = 'rucio-admin --vo %s rse list' % self.vo['vo']
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert_in(self.rse_tst, out)
        assert_not_in(self.rse_new, out)

        cmd = 'rucio-admin --vo %s rse list' % self.new_vo['vo']
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert_not_in(self.rse_tst, out)
        assert_in(self.rse_new, out)

        cmd = 'rucio-admin --vo %s rse list' % self.fake_vo['vo']
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert_equal(len(out), 0)
        assert_in('cannot get auth_token', err)

        cmd = 'rucio-admin rse list'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert_in(self.rse_tst, out)
        assert_not_in(self.rse_new, out)

    def test_vo_option_cli(self):
        """ MULTI VO (USER): Test authentication to multiple VOs via the CLI """
        cmd = 'rucio --vo %s list-rses' % self.vo['vo']
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert_in(self.rse_tst, out)
        assert_not_in(self.rse_new, out)

        cmd = 'rucio --vo %s list-rses' % self.new_vo['vo']
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert_not_in(self.rse_tst, out)
        assert_in(self.rse_new, out)

        cmd = 'rucio --vo %s list-rses' % self.fake_vo['vo']
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert_equal(len(out), 0)
        assert_in('cannot get auth_token', err)

        cmd = 'rucio list-rses'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert_in(self.rse_tst, out)
        assert_not_in(self.rse_new, out)


class TestMultiVODaemons(object):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
            cls.new_vo = {'vo': 'new'}
            if not vo_exists(**cls.new_vo):
                add_vo(description='Test', email='rucio@email.com', **cls.new_vo)
        else:
            LOG.warning('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode will result in failures.')
            cls.vo = {}
            cls.new_vo = {}

    def test_automatix(self):
        """ MULTI VO (DAEMON): Test that automatix runs on a single VO """
        scope_client = ScopeClient()
        scope_uuid = str(generate_uuid()).lower()[:16]
        shr_scope = 'shr_%s' % scope_uuid
        scope_client.add_scope('root', shr_scope)
        add_scope(shr_scope, 'root', 'root', **self.new_vo)

        rse_client = RSEClient()
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        shr_rse = 'SHR_%s' % rse_str
        mock_protocol = {'scheme': 'MOCK',
                         'hostname': 'localhost',
                         'port': 123,
                         'prefix': '/test/automatix',
                         'impl': 'rucio.rse.protocols.mock.Default',
                         'domains': {
                             'lan': {'read': 1,
                                     'write': 1,
                                     'delete': 1},
                             'wan': {'read': 1,
                                     'write': 1,
                                     'delete': 1}}}
        rse_client.add_rse(shr_rse)
        rse_client.add_rse_attribute(rse=shr_rse, key='verify_checksum', value=False)
        rse_client.add_protocol(shr_rse, mock_protocol)
        add_rse(shr_rse, 'root', **self.new_vo)
        add_rse_attribute(rse=shr_rse, key='verify_checksum', value=False, issuer='root', **self.new_vo)
        add_protocol(rse=shr_rse, data=mock_protocol, issuer='root', **self.new_vo)

        automatix(sites=[shr_rse], inputfile='/opt/rucio/etc/automatix.json', sleep_time=30, account='root', once=True, scope=shr_scope)

        did_list_tst = list(DIDClient().list_dids(shr_scope, {}))
        did_list_new = list(list_dids(shr_scope, {}, **self.new_vo))
        assert_not_equal(len(did_list_tst), 0)
        assert_equal(len(did_list_new), 0)

        did_dicts = [{'scope': shr_scope, 'name': n} for n in did_list_tst]
        replicas_tst = list(ReplicaClient().list_replicas(did_dicts, rse_expression=shr_rse))
        replicas_new = list(list_replicas(did_dicts, rse_expression=shr_rse, **self.new_vo))
        assert_not_equal(len(replicas_tst), 0)
        assert_equal(len(replicas_new), 0)
