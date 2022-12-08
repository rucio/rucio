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

import os
from logging import getLogger
from os import remove
from random import choice
from re import search
from string import ascii_uppercase, ascii_lowercase, ascii_letters, digits
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

import pytest
from oic import rndstr

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
from rucio.client.accountlimitclient import AccountLimitClient
from rucio.client.client import Client
from rucio.client.replicaclient import ReplicaClient
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_remove_option, config_set, config_has_section, config_add_section
from rucio.common.exception import AccessDenied, Duplicate, InvalidRSEExpression, UnsupportedAccountName, \
    UnsupportedOperation, RucioException
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, get_tmp_dir, parse_response, ssh_sign
from rucio.core import config as config_db
from rucio.core.account_counter import add_counter
from rucio.core.replica import add_replica
from rucio.core.rse import get_rses_with_attribute_value, get_rse_id, get_rse_vo
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import add_rule
from rucio.core.vo import map_vo
from rucio.daemons.automatix.automatix import automatix
from rucio.db.sqla import models, session as db_session
from rucio.tests.common import execute, headers, hdrdict, vohdr, auth, loginhdr, get_long_vo
from rucio.tests.test_authentication import PRIVATE_KEY, PUBLIC_KEY
from rucio.tests.test_oidc import get_mock_oidc_client, NEW_TOKEN_DICT

LOG = getLogger(__name__)

# module-level skip, see https://docs.pytest.org/en/latest/skipping.html#skip-all-test-functions-of-a-class-or-module
pytestmark = pytest.mark.skipif('SUITE' in os.environ and os.environ['SUITE'] != 'multi_vo',
                                reason='No execution of the multi_vo tests in a suite other than the multi_vo suite')


class TestVOCoreAPI:

    @pytest.mark.noparallel(reason='changes global configuration value')
    def test_multi_vo_flag(self, vo, second_vo):
        """ MULTI VO (CORE): Test operations fail in single_vo mode """
        try:
            config_set('common', 'multi_vo', 'False')
            with pytest.raises(UnsupportedOperation):
                vo_api.list_vos(issuer='super_root', vo='def')
            config_remove_option('common', 'multi_vo')
            with pytest.raises(UnsupportedOperation):
                vo_api.list_vos(issuer='super_root', vo='def')
        finally:
            config_set('common', 'multi_vo', 'True')

    @pytest.mark.noparallel(reason='uses global RSE (MOCK) and fails when run in parallel')
    def test_access_rule_vo(self, vo, second_vo):
        """ MULTI VO (CORE): Test accessing rules from a different VO """
        scope = InternalScope('mock', vo=vo)
        dataset = 'dataset_' + str(generate_uuid())
        account = InternalAccount('root', vo=vo)
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        rse_name = 'MOCK_%s' % rse_str
        rse_id = add_rse(rse_name, 'root', vo=vo)

        add_replica(rse_id=rse_id, scope=scope, name=dataset, bytes_=10, account=account)
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=account, copies=1, rse_expression='MOCK', grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        with pytest.raises(AccessDenied):
            delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', vo=second_vo)

        # check locks are not accessible from other VO
        locks = list(get_replica_locks_for_rule_id(rule_id, vo=vo))
        assert len(locks) == 1
        locks = list(get_replica_locks_for_rule_id(rule_id, vo=second_vo))
        assert len(locks) == 0

        delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', vo=vo)
        rule_dict = get_replication_rule(rule_id=rule_id, issuer='root', vo=vo)
        assert rule_dict['expires_at'] is not None

    def test_add_vo(self, vo, second_vo):
        """ MULTI VO (CORE): Test creation of VOs """
        with pytest.raises(AccessDenied):
            vo_api.add_vo(second_vo, 'root', 'Add new VO with root', 'rucio@email.com', vo=vo)
        with pytest.raises(Duplicate):
            vo_api.add_vo(second_vo, 'super_root', 'Add existing VO', 'rucio@email.com', 'def')

    def test_recover_root_identity(self, vo, second_vo):
        """ MULTI VO (CORE): Test adding a new identity for root using super_root """
        identity_key = ''.join(choice(ascii_lowercase) for x in range(10))
        with pytest.raises(AccessDenied):
            vo_api.recover_vo_root_identity(root_vo=second_vo, identity_key=identity_key, id_type='userpass', email='rucio@email.com', issuer='root', password='password', vo=vo)
        vo_api.recover_vo_root_identity(root_vo=second_vo, identity_key=identity_key, id_type='userpass', email='rucio@email.com', issuer='super_root', password='password', vo='def')
        assert 'root' in list_accounts_for_identity(identity_key=identity_key, id_type='userpass')

    def test_update_vo(self, vo, second_vo):
        """ MULTI VO (CORE): Test updating VOs """
        description = generate_uuid()
        email = generate_uuid()
        parameters = {'vo': second_vo, 'description': description, 'email': email}
        with pytest.raises(AccessDenied):
            vo_api.update_vo(second_vo, parameters, 'root', vo=vo)
        vo_api.update_vo(second_vo, parameters, 'super_root', 'def')
        vo_update_success = False
        for v in vo_api.list_vos('super_root', 'def'):
            if v['vo'] == parameters['vo']:
                assert email == v['email']
                assert description == v['description']
                vo_update_success = True
        assert vo_update_success

    def test_super_root_permissions(self, vo, second_vo):
        """ MULTI VO (CORE): Test super_root cannot access root/user functions """
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        rse_name = 'MOCK_%s' % rse_str
        scope_uuid = str(generate_uuid()).lower()[:16]
        scope = 'mock_%s' % scope_uuid

        # Test super_root@def with functions at vo='def'
        with pytest.raises(AccessDenied):
            add_rse(rse_name, 'super_root', vo='def')
        with pytest.raises(AccessDenied):
            add_scope(scope, 'root', 'super_root', vo='def')
        add_scope(scope, 'super_root', 'super_root', vo='def')
        assert scope in [s for s in list_scopes(filter_={}, vo='def')]

    @pytest.mark.noparallel(reason='changes global configuration value')
    def test_super_root_naming(self, vo, second_vo):
        """ MULTI VO (CORE): Test we can only name accounts super_root when appropriate """
        with pytest.raises(Duplicate):  # Ensure we fail from duplication rather than the choice of name
            add_account('super_root', 'USER', 'rucio@email.com', 'root', vo='def')
        with pytest.raises(UnsupportedAccountName):
            add_account('super_root', 'USER', 'rucio@email.com', 'root', vo=vo)
        try:
            config_remove_option('common', 'multi_vo')
            with pytest.raises(UnsupportedAccountName):
                add_account('super_root', 'USER', 'rucio@email.com', 'root', vo=vo)
            with pytest.raises(UnsupportedAccountName):
                add_account('super_root', 'USER', 'rucio@email.com', 'root', vo='def')
        finally:
            # Make sure we don't leave the config changed due to a test failure
            config_set('common', 'multi_vo', 'True')


@pytest.fixture(scope='class')
def usr_uuid():
    return str(generate_uuid()).lower()[:16]


@pytest.fixture(scope='class')
def account_tst(usr_uuid, vo):
    account_tst = 'tst-%s' % usr_uuid
    add_account(account_tst, 'USER', 'rucio@email.com', 'root', vo=vo)
    yield account_tst


@pytest.fixture(scope='class')
def account_new(usr_uuid, second_vo):
    account_new = 'new-%s' % usr_uuid
    add_account(account_new, 'USER', 'rucio@email.com', 'root', vo=second_vo)
    yield account_new


class TestVORestAPI:

    @staticmethod
    def auth_oidc_handling(mock_oidc_client, rest_client, vo, long_vo, account_in, account_not_in, auto, polling):
        """
        Utility script to handle the REST calls with various urls and codes needed to authenticate via OIDC.
        IdP responses are faked using code from `test_oidc.py`.

        :param mock_oidc_client: Mock OIDC client used to fake responses from the IdP for test purposes.
        :param vo: VO to authenticate
        :param account_in: A string (externally) representing an account we DO expect to find at the VO.
        :param account_not_in: A string (externally) representing an account we DO NOT expect to find at the VO.
        :param auto: Boolean to specify whether we automatically submit userpass to the IdP as part of authentication.
        :param auto: Boolean to specify whether we poll the IdP for a successful login as part of authentication.
        """
        mock_oidc_client.side_effect = get_mock_oidc_client

        try:
            add_account_identity('SUB=knownsub, ISS=https://test_issuer/', 'OIDC', 'root', 'rucio_test@test.com', 'root', vo=vo)
        except Duplicate:
            pass  # Might already exist, can skip

        # Define headers
        headers_dict = {'X-Rucio-Account': 'root',
                        'X-Rucio-VO': long_vo,
                        'X-Rucio-Client-Authorize-Auto': str(auto),
                        'X-Rucio-Client-Authorize-Polling': str(polling),
                        'X-Rucio-Client-Authorize-Scope': 'openid profile',
                        'X-Rucio-Client-Authorize-Refresh-Lifetime': '96',
                        'X-Rucio-Client-Authorize-Audience': 'rucio',
                        'X-Rucio-Client-Authorize-Issuer': 'dummy_admin_iss_nickname'}

        response = rest_client.get('/auth/oidc', headers=headers(hdrdict(headers_dict)))
        assert response.status_code == 200
        if auto:
            # Get the auth_url without any redirect
            auth_url = response.headers.get('X-Rucio-OIDC-Auth-URL')
        else:
            # Get the redirect_url
            redirect_url = response.headers.get('X-Rucio-OIDC-Auth-URL')
            assert 'https://test_redirect_string/auth/oidc_redirect?' in redirect_url
            if polling:
                assert '_polling' in redirect_url
            else:
                assert '_polling' not in redirect_url
            redirect_url_parsed = urlparse(redirect_url)

            # Get the auth_url from the redirect_url
            response = rest_client.get('/auth/oidc_redirect?%s' % redirect_url_parsed.query, headers=headers(hdrdict(headers_dict)))
            assert response.status_code == 303
            auth_url = response.headers.get('location')

        assert 'https://test_auth_url_string?' in auth_url
        auth_url_parsed = urlparse(auth_url)
        auth_url_params = parse_qs(auth_url_parsed.query)

        # Fake the IdP response for a successful login
        code_response = rndstr()
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_url_params['nonce'][0]}
        headers_dict['X-Rucio-Client-Fetch-Token'] = 'True'

        if auto:
            # Can get the token now
            response = rest_client.get('/auth/oidc_token?state=%s&code=%s' % (auth_url_params['state'][0], code_response), headers=headers(hdrdict(headers_dict)))
        else:
            # Get the html response
            response = rest_client.get('/auth/oidc_code?state=%s&code=%s' % (auth_url_params['state'][0], code_response), headers=headers(hdrdict(headers_dict)))
            assert response.status_code == 200
            if polling:
                assert 'Rucio Client should now be able to fetch your token automatically.' in response.get_data(as_text=True)
                response = rest_client.get('/auth/oidc_redirect?%s' % redirect_url_parsed.query, headers=headers(hdrdict(headers_dict)))
            else:
                # Get the fetch_code from the response, then submit it
                fetch_code = search(r'<b>[a-zA-Z0-9]{50}</b>', response.get_data(as_text=True))
                assert fetch_code is not None
                fetch_code = fetch_code.group()[3:53]
                response = rest_client.get('/auth/oidc_redirect?%s' % fetch_code, headers=headers(hdrdict(headers_dict)))

        # Regardless of how we got it, check we have the token and that we only get results from our VO when using it
        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))
        response = rest_client.get('/accounts/', headers=headers(auth(token)))
        assert response.status_code == 200
        accounts = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts) != 0
        assert account_in in accounts
        assert account_not_in not in accounts

    @patch('rucio.core.oidc.__get_init_oidc_client')
    def test_auth_oidc(self, mock_oidc_client, vo, long_vo, second_vo, account_tst, account_new, rest_client):
        """ MULTI VO (REST): Test oidc authentication to multiple VOs """
        self.auth_oidc_handling(mock_oidc_client, rest_client, vo, long_vo, account_tst, account_new, auto=False, polling=False)
        self.auth_oidc_handling(mock_oidc_client, rest_client, second_vo, second_vo, account_new, account_tst, auto=False, polling=False)

    @patch('rucio.core.oidc.__get_init_oidc_client')
    def test_auth_oidc_polling(self, mock_oidc_client, vo, long_vo, second_vo, account_tst, account_new, rest_client):
        """ MULTI VO (REST): Test oidc authentication to multiple VOs using 'polling' option """
        self.auth_oidc_handling(mock_oidc_client, rest_client, vo, long_vo, account_tst, account_new, auto=False, polling=True)
        self.auth_oidc_handling(mock_oidc_client, rest_client, second_vo, second_vo, account_new, account_tst, auto=False, polling=True)

    @patch('rucio.core.oidc.__get_init_oidc_client')
    def test_auth_oidc_auto(self, mock_oidc_client, vo, long_vo, second_vo, account_tst, account_new, rest_client):
        """ MULTI VO (REST): Test oidc authentication to multiple VOs using 'auto' option """
        self.auth_oidc_handling(mock_oidc_client, rest_client, vo, long_vo, account_tst, account_new, auto=True, polling=False)
        self.auth_oidc_handling(mock_oidc_client, rest_client, second_vo, second_vo, account_new, account_tst, auto=True, polling=False)

    def test_auth_gss(self, vo, second_vo, account_tst, account_new, rest_client):
        """ MULTI VO (REST): Test gss authentication to multiple VOs """
        # Can't rely on `requests_kerberos` module being present, so get tokens from API instead
        token_tst = get_auth_token_gss('root', 'rucio-dev@CERN.CH', 'unknown', None, vo=vo).get('token')
        token_new = get_auth_token_gss('root', 'rucio-dev@CERN.CH', 'unknown', None, vo=second_vo).get('token')

        response = rest_client.get('/accounts/', headers=headers(auth(token_tst)))
        assert response.status_code == 200
        accounts_tst = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_tst) != 0
        assert account_tst in accounts_tst
        assert account_new not in accounts_tst

        response = rest_client.get('/accounts/', headers=headers(auth(token_new)))
        assert response.status_code == 200
        accounts_new = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_new) != 0
        assert account_new in accounts_new
        assert account_tst not in accounts_new

    def test_auth_saml(self, vo, second_vo, account_tst, account_new, rest_client):
        """ MULTI VO (REST): Test saml authentication to multiple VOs """
        try:
            add_account_identity('ddmlab', 'SAML', 'root', 'rucio@email.com', 'root', vo=vo)
        except Duplicate:
            pass  # Might already exist, can skip

        try:
            add_account_identity('ddmlab', 'SAML', 'root', 'rucio@email.com', 'root', vo=second_vo)
        except Duplicate:
            pass  # Might already exist, can skip

        # Can't rely on `onelogin` module being present, so get tokens from API instead
        token_tst = get_auth_token_saml('root', 'ddmlab', 'unknown', None, vo=vo).get('token')
        token_new = get_auth_token_saml('root', 'ddmlab', 'unknown', None, vo=second_vo).get('token')

        response = rest_client.get('/accounts/', headers=headers(auth(token_tst)))
        assert response.status_code == 200
        accounts_tst = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_tst) != 0
        assert account_tst in accounts_tst
        assert account_new not in accounts_tst

        response = rest_client.get('/accounts/', headers=headers(auth(token_new)))
        assert response.status_code == 200
        accounts_new = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_new) != 0
        assert account_new in accounts_new
        assert account_tst not in accounts_new

    def test_auth_ssh(self, vo, long_vo, second_vo, account_tst, account_new, rest_client):
        """ MULTI VO (REST): Test ssh authentication to multiple VOs """
        try:
            add_account_identity(PUBLIC_KEY, 'SSH', 'root', 'rucio@email.com', 'root', vo=vo)
        except Duplicate:
            pass  # Might already exist, can skip

        try:
            add_account_identity(PUBLIC_KEY, 'SSH', 'root', 'rucio@email.com', 'root', vo=second_vo)
        except Duplicate:
            pass  # Might already exist, can skip

        headers_dict = {'X-Rucio-Account': 'root'}
        response = rest_client.get('/auth/ssh_challenge_token', headers=headers(hdrdict(headers_dict), vohdr(long_vo)))
        assert response.status_code == 200
        challenge_tst = str(response.headers.get('X-Rucio-SSH-Challenge-Token'))
        headers_dict.update({'X-Rucio-SSH-Signature': ssh_sign(PRIVATE_KEY, challenge_tst)})
        response = rest_client.get('/auth/ssh', headers=headers(hdrdict(headers_dict), vohdr(long_vo)))
        assert response.status_code == 200
        token_tst = str(response.headers.get('X-Rucio-Auth-Token'))

        headers_dict = {'X-Rucio-Account': 'root'}
        response = rest_client.get('/auth/ssh_challenge_token', headers=headers(hdrdict(headers_dict), vohdr(second_vo)))
        assert response.status_code == 200
        challenge_tst = str(response.headers.get('X-Rucio-SSH-Challenge-Token'))
        headers_dict.update({'X-Rucio-SSH-Signature': ssh_sign(PRIVATE_KEY, challenge_tst)})
        response = rest_client.get('/auth/ssh', headers=headers(hdrdict(headers_dict), vohdr(second_vo)))
        assert response.status_code == 200
        token_new = str(response.headers.get('X-Rucio-Auth-Token'))

        response = rest_client.get('/accounts/', headers=headers(auth(token_tst)))
        assert response.status_code == 200
        accounts_tst = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_tst) != 0
        assert account_tst in accounts_tst
        assert account_new not in accounts_tst

        response = rest_client.get('/accounts/', headers=headers(auth(token_new)))
        assert response.status_code == 200
        accounts_new = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_new) != 0
        assert account_new in accounts_new
        assert account_tst not in accounts_new

    def test_auth_userpass(self, vo, long_vo, second_vo, account_tst, account_new, rest_client):
        """ MULTI VO (REST): Test userpass authentication to multiple VOs """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(long_vo)))
        assert response.status_code == 200
        token_tst = str(response.headers.get('X-Rucio-Auth-Token'))

        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(second_vo)))
        assert response.status_code == 200
        token_new = str(response.headers.get('X-Rucio-Auth-Token'))

        response = rest_client.get('/accounts/', headers=headers(auth(token_tst)))
        assert response.status_code == 200
        accounts_tst = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_tst) != 0
        assert account_tst in accounts_tst
        assert account_new not in accounts_tst

        response = rest_client.get('/accounts/', headers=headers(auth(token_new)))
        assert response.status_code == 200
        accounts_new = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_new) != 0
        assert account_new in accounts_new
        assert account_tst not in accounts_new

    def test_auth_x509(self, vo, second_vo, account_tst, account_new, rest_client):
        """ MULTI VO (REST): Test X509 authentication to multiple VOs """
        # Flasks test client doesn't support client certificates, so get tokens from API instead
        token_tst = get_auth_token_x509('root', '/CN=Rucio User', 'unknown', None, vo=vo).get('token')
        token_new = get_auth_token_x509('root', '/CN=Rucio User', 'unknown', None, vo=second_vo).get('token')

        response = rest_client.get('/accounts/', headers=headers(auth(token_tst)))
        assert response.status_code == 200
        accounts_tst = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_tst) != 0
        assert account_tst in accounts_tst
        assert account_new not in accounts_tst

        response = rest_client.get('/accounts/', headers=headers(auth(token_new)))
        assert response.status_code == 200
        accounts_new = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(accounts_new) != 0
        assert account_new in accounts_new
        assert account_tst not in accounts_new

    def test_list_vos_success(self, vo, second_vo, rest_client):
        """ MULTI VO (REST): Test list VOs through REST layer succeeds """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('super_root', 'ddmlab', 'secret'), vohdr('def')))

        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        response = rest_client.get('/vos/', headers=headers(auth(token)))
        assert response.status_code == 200
        vo_dicts = [parse_response(r) for r in response.get_data(as_text=True).split('\n')[:-1]]
        assert len(vo_dicts) != 0
        for vo_dict in vo_dicts:
            assert vo_dict['vo'] is not None
            assert vo_dict['email'] is not None
            assert vo_dict['description'] is not None
            assert vo_dict['created_at'] is not None
            assert vo_dict['updated_at'] is not None

    def test_list_vos_denied(self, vo, long_vo, second_vo, rest_client):
        """ MULTI VO (REST): Test list VOs through REST layer raises AccessDenied """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(long_vo)))
        assert response.status_code == 200
        token = response.headers.get('X-Rucio-Auth-Token')
        assert token

        response = rest_client.get('/vos/', headers=headers(auth(token)))
        assert response.status_code == 401

    @pytest.mark.noparallel(reason='changes global configuration value')
    def test_list_vos_unsupported(self, vo, second_vo, rest_client):
        """ MULTI VO (REST): Test list VOs through REST layer raises UnsupportedOperation """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('super_root', 'ddmlab', 'secret'), vohdr('def')))

        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        try:
            config_set('common', 'multi_vo', 'False')
            response = rest_client.get('/vos/', headers=headers(auth(token)))
            assert response.status_code == 409

            config_remove_option('common', 'multi_vo')
            response = rest_client.get('/vos/', headers=headers(auth(token)))
            assert response.status_code == 409

        finally:
            # Make sure we don't leave the config changed due to a test failure
            config_set('common', 'multi_vo', 'True')

    def test_add_vo_denied(self, vo, long_vo, second_vo, rest_client):
        """ MULTI VO (REST): Test adding VO through REST layer raises AccessDenied """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(long_vo)))

        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try adding with root'}
        response = rest_client.post('/vos/' + vo, headers=headers(auth(token)), json=params)
        assert response.status_code == 401

    @pytest.mark.noparallel(reason='changes global configuration value')
    def test_add_vo_unsupported(self, vo, second_vo, rest_client):
        """ MULTI VO (REST): Test adding VO through REST layer raises UnsupportedOperation """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('super_root', 'ddmlab', 'secret'), vohdr('def')))

        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try adding in single vo mode'}
        try:
            config_set('common', 'multi_vo', 'False')
            response = rest_client.post('/vos/' + vo, headers=headers(auth(token)), json=params)
            assert response.status_code == 409

            config_remove_option('common', 'multi_vo')
            response = rest_client.post('/vos/' + vo, headers=headers(auth(token)), json=params)
            assert response.status_code == 409

        finally:
            # Make sure we don't leave the config changed due to a test failure
            config_set('common', 'multi_vo', 'True')

    def test_add_vo_duplicate(self, vo, second_vo, rest_client):
        """ MULTI VO (REST): Test adding VO through REST layer raises Duplicate """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('super_root', 'ddmlab', 'secret'), vohdr('def')))

        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try adding duplicate'}
        response = rest_client.post('/vos/' + vo, headers=headers(auth(token)), json=params)
        assert response.status_code == 409

    def test_update_vo_success(self, vo, second_vo, rest_client):
        """ MULTI VO (REST): Test updating VO through REST layer succeeds """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('super_root', 'ddmlab', 'secret'), vohdr('def')))

        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        params = {'email': generate_uuid(), 'description': generate_uuid()}
        response = rest_client.put('/vos/' + vo, headers=headers(auth(token)), json=params)
        assert response.status_code == 200

        vo_update_success = False
        for v in vo_api.list_vos('super_root', 'def'):
            if v['vo'] == vo:
                assert params['email'] == v['email']
                assert params['description'] == v['description']
                vo_update_success = True
        assert vo_update_success

    def test_update_vo_denied(self, vo, long_vo, second_vo, rest_client):
        """ MULTI VO (REST): Test updating VO through REST layer raises AccessDenied """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(long_vo)))
        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try updating with root'}
        response = rest_client.put('/vos/' + vo, headers=headers(auth(token)), json=params)
        assert response.status_code == 401

    @pytest.mark.noparallel(reason='changes global configuration value')
    def test_update_vo_unsupported(self, vo, second_vo, rest_client):
        """ MULTI VO (REST): Test updating VO through REST layer raises UnsupportedOperation """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('super_root', 'ddmlab', 'secret'), vohdr('def')))
        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try updating in single vo mode'}
        try:
            config_set('common', 'multi_vo', 'False')
            response = rest_client.put('/vos/' + vo, headers=headers(auth(token)), json=params)
            assert response.status_code == 409

            config_remove_option('common', 'multi_vo')
            response = rest_client.put('/vos/' + vo, headers=headers(auth(token)), json=params)
            assert response.status_code == 409

        finally:
            # Make sure we don't leave the config changed due to a test failure
            config_set('common', 'multi_vo', 'True')

    def test_update_vo_not_found(self, vo, second_vo, rest_client):
        """ MULTI VO (REST): Test updating VO through REST layer raises VONotFound """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('super_root', 'ddmlab', 'secret'), vohdr('def')))

        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        params = {'email': 'rucio@email.com', 'decription': 'Try updating non-existent'}
        response = rest_client.put('/vos/bad', headers=headers(auth(token)), json=params)
        assert response.status_code == 404

    def test_recover_vo_success(self, vo, second_vo, rest_client):
        """ MULTI VO (REST): Test recovering VO through REST layer succeeds """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('super_root', 'ddmlab', 'secret'), vohdr('def')))

        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        identity_key = ''.join(choice(ascii_lowercase) for x in range(10))
        params = {'identity': identity_key, 'authtype': 'userpass', 'email': 'rucio@email.com', 'password': 'password'}
        response = rest_client.post('/vos/' + vo + '/recover', headers=headers(auth(token)), json=params)
        assert response.status_code == 201

        assert 'root' in list_accounts_for_identity(identity_key=identity_key, id_type='userpass')

    def test_recover_vo_denied(self, vo, long_vo, rest_client):
        """ MULTI VO (REST): Test recovering VO through REST layer raises AccessDenied """
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(long_vo)))
        assert response.status_code == 200
        token = str(response.headers.get('X-Rucio-Auth-Token'))

        identity_key = ''.join(choice(ascii_lowercase) for x in range(10))
        params = {'identity': identity_key, 'authtype': 'userpass', 'email': 'rucio@email.com', 'password': 'password'}
        response = rest_client.post('/vos/' + vo + '/recover', headers=headers(auth(token)), json=params)
        assert response.status_code == 401

    @pytest.mark.noparallel(reason='account lists may be changed by other tests')
    def test_rest_vomap(self, vo, long_vo, rest_client):
        """ MULTI VO (REST): Test that both the long and short version of a VO name return the same results. """
        def get_vo_accounts(vo):
            response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr(vo)))
            assert response.status_code == 200
            token = str(response.headers.get('X-Rucio-Auth-Token'))
            response = rest_client.get('/accounts/', headers=headers(auth(token)))
            assert response.status_code == 200
            accounts = [parse_response(a)['account'] for a in response.get_data(as_text=True).split('\n')[:-1]]
            return sorted(accounts)
        # The test VOs contain different account names
        # We get all the account names with the long VO name and short VO name and check they are equal
        accounts_long = get_vo_accounts(long_vo)
        accounts_short = get_vo_accounts(vo)
        assert len(accounts_short) > 0
        assert accounts_short == accounts_long

    def test_rest_vomap_bad(self, rest_client):
        """ MULTI VO (REST): Test that we get a bad paramter (400) error with an invalid (out of spec) VO name. """
        # VO names cannot include an exclaimation mark
        response = rest_client.get('/auth/userpass', headers=headers(loginhdr('root', 'ddmlab', 'secret'), vohdr("BadVO!")))
        assert response.status_code == 400


class TestMultiVoClients:

    def test_get_vo_from_config(self, vo):
        """ MULTI VO (CLIENT): Get vo from config file when starting clients """
        # Start clients with vo explicitly set to None
        replica_client = ReplicaClient(vo=None)
        client = Client(vo=None)
        upload_client = UploadClient(_client=client)
        # Check the vo has been got from the config file
        long_vo = get_long_vo()
        assert replica_client.vo == long_vo
        assert upload_client.client.vo == long_vo

    def test_accounts_at_different_vos(self, second_vo, account_client):
        """ MULTI VO (CLIENT): Test that accounts from 2nd vo don't interfere """
        usr_uuid = str(generate_uuid()).lower()[:16]
        tst = 'tst-%s' % usr_uuid
        new = 'new-%s' % usr_uuid
        shr = 'shr-%s' % usr_uuid
        account_client.add_account(tst, 'USER', 'rucio@email.com')
        account_client.add_account(shr, 'USER', 'rucio@email.com')
        add_account(new, 'USER', 'rucio@email.com', 'root', vo=second_vo)
        add_account(shr, 'USER', 'rucio@email.com', 'root', vo=second_vo)
        account_list_tst = [a['account'] for a in account_client.list_accounts()]
        account_list_new = [a['account'] for a in list_accounts(filter_={}, vo=second_vo)]
        assert tst in account_list_tst
        assert new not in account_list_tst
        assert shr in account_list_tst
        assert tst not in account_list_new
        assert new in account_list_new
        assert shr in account_list_new

    def test_dids_at_different_vos(self, vo, second_vo, did_client):
        """ MULTI VO (CLIENT): Test that dids from 2nd vo don't interfere """
        scope_uuid = str(generate_uuid()).lower()[:16]
        scope = 'shr_%s' % scope_uuid
        add_scope(scope, 'root', 'root', vo=vo)
        add_scope(scope, 'root', 'root', vo=second_vo)
        did_uuid = str(generate_uuid()).lower()[:16]
        tst = 'tstset_%s' % did_uuid
        new = 'newset_%s' % did_uuid
        shr = 'shrset_%s' % did_uuid
        did_client.add_did(scope, tst, 'DATASET')
        did_client.add_did(scope, shr, 'DATASET')
        add_did(scope, new, 'DATASET', 'root', vo=second_vo)
        add_did(scope, shr, 'DATASET', 'root', vo=second_vo)
        did_list_tst = list(did_client.list_dids(scope, {}))
        did_list_new = list(list_dids(scope, {}, vo=second_vo))
        assert tst in did_list_tst
        assert new not in did_list_tst
        assert shr in did_list_tst
        assert tst not in did_list_new
        assert new in did_list_new
        assert shr in did_list_new

    def test_rses_at_different_vos(self, vo, second_vo, rse_client):
        """ MULTI VO (CLIENT): Test that RSEs from 2nd vo don't interfere """
        # Set up RSEs at two VOs
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        tst = 'TST_%s' % rse_str
        new = 'NEW_%s' % rse_str
        shr = 'SHR_%s' % rse_str
        rse_client.add_rse(tst)
        rse_client.add_rse(shr)
        add_rse(new, 'root', vo=second_vo)
        shr_id_new_original = add_rse(shr, 'root', vo=second_vo)  # Accurate rse_id for shared RSE at 'new'

        # Check the cached rse-id from each VO does not interfere
        shr_id_tst = get_rse_id(shr, vo=vo)
        shr_id_new = get_rse_id(shr, vo=second_vo)
        assert shr_id_new == shr_id_new_original
        assert shr_id_new != shr_id_tst

        # Check that when listing RSEs we only get RSEs for our VO
        rse_list_tst = [r['rse'] for r in rse_client.list_rses()]
        rse_list_new = [r['rse'] for r in list_rses(filters={}, vo=second_vo)]
        assert tst in rse_list_tst
        assert new not in rse_list_tst
        assert shr in rse_list_tst
        assert tst not in rse_list_new
        assert new in rse_list_new
        assert shr in rse_list_new

        # Check the cached attribute-value results do not interfere and only give results from the appropriate VO
        attribute_value = generate_uuid()
        add_rse_attribute(new, 'test', attribute_value, 'root', vo=second_vo)
        rses_tst_1 = list(get_rses_with_attribute_value('test', attribute_value, 'test', vo=vo))
        rses_new_1 = list(get_rses_with_attribute_value('test', attribute_value, 'test', vo=second_vo))
        rses_tst_2 = list(get_rses_with_attribute_value('test', attribute_value, 'test', vo=vo))
        rses_new_2 = list(get_rses_with_attribute_value('test', attribute_value, 'test', vo=second_vo))
        assert len(rses_tst_1) == 0
        assert len(rses_new_1) != 0
        assert len(rses_tst_2) == 0
        assert len(rses_new_2) != 0

        # check parse_expression
        rses_tst_3 = parse_expression(shr, filter_={'vo': vo})
        rses_tst_4 = parse_expression(tst, filter_={'vo': vo})
        rses_new_3 = parse_expression(shr, filter_={'vo': second_vo})
        with pytest.raises(InvalidRSEExpression):
            parse_expression(tst, filter_={'vo': second_vo})
        assert len(rses_tst_3) == 1
        assert shr_id_tst == rses_tst_3[0]['id']
        assert len(rses_tst_4) == 1
        assert tst == rses_tst_4[0]['rse']
        assert len(rses_new_3) == 1
        assert shr_id_new == rses_new_3[0]['id']

    def test_scopes_at_different_vos(self, second_vo, scope_client):
        """ MULTI VO (CLIENT): Test that scopes from 2nd vo don't interfere """
        scope_uuid = str(generate_uuid()).lower()[:16]
        tst = 'tst_%s' % scope_uuid
        new = 'new_%s' % scope_uuid
        shr = 'shr_%s' % scope_uuid
        scope_client.add_scope('root', tst)
        scope_client.add_scope('root', shr)
        add_scope(new, 'root', 'root', vo=second_vo)
        add_scope(shr, 'root', 'root', vo=second_vo)
        scope_list_tst = list(scope_client.list_scopes())
        scope_list_new = list(list_scopes(filter_={}, vo=second_vo))
        assert tst in scope_list_tst
        assert new not in scope_list_tst
        assert shr in scope_list_tst
        assert tst not in scope_list_new
        assert new in scope_list_new
        assert shr in scope_list_new

    def test_subscriptions_at_different_vos(self, second_vo, account_client, did_client, rse_client, scope_client):
        """ MULTI VO (CLIENT): Test that subscriptions from 2nd vo don't interfere """

        usr_uuid = str(generate_uuid()).lower()[:16]
        shr_acc = 'shr-%s' % usr_uuid
        account_client.add_account(shr_acc, 'USER', 'rucio@email.com')
        add_account(shr_acc, 'USER', 'rucio@email.com', 'root', vo=second_vo)

        scope_uuid = str(generate_uuid()).lower()[:16]
        tst_scope = 'tst_%s' % scope_uuid
        new_scope = 'new_%s' % scope_uuid
        scope_client.add_scope('root', tst_scope)
        add_scope(new_scope, 'root', 'root', vo=second_vo)

        did_uuid = str(generate_uuid()).lower()[:16]
        tst_did = 'tstset_%s' % did_uuid
        new_did = 'newset_%s' % did_uuid

        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        tst_rse1 = 'TST1_%s' % rse_str
        tst_rse2 = 'TST2_%s' % rse_str
        new_rse1 = 'NEW1_%s' % rse_str
        new_rse2 = 'NEW2_%s' % rse_str
        rse_client.add_rse(tst_rse1)
        rse_client.add_rse(tst_rse2)
        add_rse(new_rse1, 'root', vo=second_vo)
        add_rse(new_rse2, 'root', vo=second_vo)

        acc_lim_client = AccountLimitClient()
        acc_lim_client.set_local_account_limit(shr_acc, tst_rse1, 10)
        acc_lim_client.set_local_account_limit(shr_acc, tst_rse2, 10)
        set_local_account_limit(shr_acc, new_rse1, 10, 'root', vo=second_vo)
        set_local_account_limit(shr_acc, new_rse2, 10, 'root', vo=second_vo)

        did_client.add_did(tst_scope, tst_did, 'DATASET', rse=tst_rse1)
        add_did(new_scope, new_did, 'DATASET', 'root', rse=new_rse1, vo=second_vo)

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
                                      '', False, 0, 0, 3, 'root', vo=second_vo)
        shr_new_sub_id = add_subscription(shr_sub, shr_acc, {'scope': [new_scope]},
                                          [{'copies': 1, 'rse_expression': new_rse2, 'weight': 0, 'activity': 'User Subscriptions'}],
                                          '', False, 0, 0, 3, 'root', vo=second_vo)

        tst_subs = [s['id'] for s in sub_client.list_subscriptions()]
        assert tst_sub_id in tst_subs
        assert shr_tst_sub_id in tst_subs
        assert new_sub_id not in tst_subs
        assert shr_new_sub_id not in tst_subs

        new_subs = [s['id'] for s in list_subscriptions(vo=second_vo)]
        assert new_sub_id in new_subs
        assert shr_new_sub_id in new_subs
        assert tst_sub_id not in new_subs
        assert shr_tst_sub_id not in new_subs

        shr_tst_subs = [s['id'] for s in sub_client.list_subscriptions(name=shr_sub)]
        assert shr_tst_sub_id in shr_tst_subs
        assert shr_new_sub_id not in shr_tst_subs

        shr_new_subs = [s['id'] for s in list_subscriptions(name=shr_sub, vo=second_vo)]
        assert shr_new_sub_id in shr_new_subs
        assert shr_tst_sub_id not in shr_new_subs

        acc_tst_subs = [s['id'] for s in sub_client.list_subscriptions(account=shr_acc)]
        assert tst_sub_id in acc_tst_subs
        assert shr_tst_sub_id in acc_tst_subs
        assert new_sub_id not in acc_tst_subs
        assert shr_new_sub_id not in acc_tst_subs

        acc_new_subs = [s['id'] for s in list_subscriptions(account=shr_acc, vo=second_vo)]
        assert new_sub_id in acc_new_subs
        assert shr_new_sub_id in acc_new_subs
        assert tst_sub_id not in acc_new_subs
        assert shr_tst_sub_id not in acc_new_subs

    def test_account_counters_at_different_vos(self, vo, second_vo, rse_client):
        """ MULTI VO (CLIENT): Test that account counters from 2nd vo don't interfere """

        session = db_session.get_session()

        # add some RSEs to test create_counters_for_new_account
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        tst_rse1 = 'TST1_%s' % rse_str
        new_rse1 = 'NEW1_%s' % rse_str
        rse_client.add_rse(tst_rse1)
        new_rse1_vo1_id = add_rse(new_rse1, 'root', vo=vo)
        new_rse1_vo2_id = add_rse(new_rse1, 'root', vo=second_vo)

        # add an account
        usr_uuid = str(generate_uuid()).lower()[:16]
        new_acc_str = 'shr-%s' % usr_uuid
        add_account(new_acc_str, 'USER', 'rucio@email.com', 'root', vo=vo)
        add_account(new_acc_str, 'USER', 'rucio@email.com', 'root', vo=second_vo)
        new_acc_vo1 = InternalAccount(new_acc_str, vo=vo)
        new_acc_vo2 = InternalAccount(new_acc_str, vo=second_vo)

        # Create counters
        add_counter(new_rse1_vo1_id, new_acc_vo1)
        add_counter(new_rse1_vo2_id, new_acc_vo2)

        query = session.query(models.AccountUsage.account, models.AccountUsage.rse_id).\
            distinct(models.AccountUsage.account, models.AccountUsage.rse_id).\
            filter_by(account=new_acc_vo2)
        acc_counters = list(query.all())

        assert 1 == len(acc_counters)
        for counter in acc_counters:
            rse_id = counter[1]
            vo = get_rse_vo(rse_id)
            assert vo == second_vo


class TestMultiVOBinRucio:

    marker = '$> '

    @pytest.fixture(autouse=True)
    def setup_object(self, vo, second_vo):
        # Setup RSEs at two VOs so we can determine which VO we authenticated against
        rse_str = ''.join(choice(ascii_uppercase) for x in range(10))
        self.rse_tst = 'TST_%s' % rse_str
        self.rse_new = 'NEW_%s' % rse_str
        add_rse(self.rse_tst, 'root', vo=vo)
        add_rse(self.rse_new, 'root', vo=second_vo)

        try:
            remove(get_tmp_dir() + '/.rucio_root@%s/auth_token_for_account_root' % vo)
        except OSError as e:
            if e.args[0] != 2:
                raise e
        try:
            remove(get_tmp_dir() + '/.rucio_root@%s/auth_token_for_account_root' % second_vo)
        except OSError as e:
            if e.args[0] != 2:
                raise e

    def test_vo_option_admin_cli(self, long_vo, second_vo):
        """ MULTI VO (USER): Test authentication to multiple VOs via the admin CLI """
        fake_vo = 'fke'

        cmd = 'rucio-admin --vo %s rse list' % long_vo
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert self.rse_tst in out
        assert self.rse_new not in out

        cmd = 'rucio-admin --vo %s rse list' % second_vo
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert self.rse_tst not in out
        assert self.rse_new in out

        cmd = 'rucio-admin --vo %s rse list' % fake_vo
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert len(out) == 0
        assert 'Details: CannotAuthenticate' in err

        cmd = 'rucio-admin rse list'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert self.rse_tst in out
        assert self.rse_new not in out

    def test_vo_option_cli(self, long_vo, second_vo):
        """ MULTI VO (USER): Test authentication to multiple VOs via the CLI """
        fake_vo = 'fke'

        cmd = 'rucio --vo %s list-rses' % long_vo
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert self.rse_tst in out
        assert self.rse_new not in out

        cmd = 'rucio --vo %s list-rses' % second_vo
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert self.rse_tst not in out
        assert self.rse_new in out

        cmd = 'rucio --vo %s list-rses' % fake_vo
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert len(out) == 0
        assert 'Details: CannotAuthenticate' in err

        cmd = 'rucio list-rses'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, )
        assert self.rse_tst in out
        assert self.rse_new not in out


@pytest.mark.noparallel(reason='runs daemons, fails when run in parallel')
class TestMultiVODaemons:

    @pytest.mark.parametrize("core_config_mock", [{"table_content": []}], indirect=True)
    def test_automatix(self, second_vo, rse_client, did_client, replica_client, scope_client, core_config_mock):
        """ MULTI VO (DAEMON): Test that automatix runs on a single VO """
        scope_uuid = str(generate_uuid()).lower()[:16]
        shr_scope = 'shr_%s' % scope_uuid
        scope_client.add_scope('root', shr_scope)
        add_scope(shr_scope, 'root', 'root', vo=second_vo)

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
        rse_client.add_rse_attribute(rse=shr_rse, key='skip_upload_stat', value=True)
        rse_client.add_protocol(shr_rse, mock_protocol)
        add_rse(shr_rse, 'root', vo=second_vo)
        add_rse_attribute(rse=shr_rse, key='verify_checksum', value=False, issuer='root', vo=second_vo)
        add_rse_attribute(rse=shr_rse, key='skip_upload_stat', value=True, issuer='root', vo=second_vo)
        add_protocol(rse=shr_rse, data=mock_protocol, issuer='root', vo=second_vo)

        if not config_has_section("automatix"):
            config_add_section("automatix")
        config_set("automatix", "rses", shr_rse)
        config_set("automatix", "scope", shr_scope)

        automatix(
            inputfile='/opt/rucio/etc/automatix.json',
            sleep_time=10,
            once=True,
        )

        did_list_tst = list(did_client.list_dids(shr_scope, {}))
        did_list_new = list(list_dids(shr_scope, {}, vo=second_vo))
        assert len(did_list_tst) != 0
        assert len(did_list_new) == 0

        did_dicts = [{'scope': shr_scope, 'name': n} for n in did_list_tst]
        replicas_tst = list(replica_client.list_replicas(did_dicts, rse_expression=shr_rse))
        replicas_new = list(list_replicas(did_dicts, rse_expression=shr_rse, vo=second_vo))
        assert len(replicas_tst) != 0
        assert len(replicas_new) == 0


class TestVOMap:
    """ Test VO Mapping functions. """

    @pytest.mark.parametrize("core_config_mock", [{"table_content": []}], indirect=True)
    def test_map_vo(self, core_config_mock):
        """ Test a few typical map_vo use cases """
        # Check things still work if section is missing
        assert map_vo("def") == "def"
        assert map_vo("tst") == "tst"
        assert map_vo("test.vo1-one") == "test.vo1-one"

        # Add config and do mapping tests
        # This first VO name uses all allowed character sets for the long VO name
        config_db.set("vo-map", "test.vo1-one", "tst")
        config_db.set("vo-map", "second.vo", "ts2")

        # Mapping not in config
        assert map_vo("test") == "test"
        # VO in config, but use short name directly
        assert map_vo("tst") == "tst"
        # Test two mappings from config
        assert map_vo("test.vo1-one") == "tst"
        assert map_vo("second.vo") == "ts2"
        # Invalid VO name tests
        # Generate a list of all 1-byte characters and remove ones that we should accept
        test_chars = set([chr(x) for x in range(0, 256)])
        test_chars -= set(ascii_letters)
        test_chars -= set(digits)
        test_chars -= set(['.', '-'])
        for test_chr in test_chars:
            with pytest.raises(RucioException):
                map_vo("bad%s" % test_chr)
