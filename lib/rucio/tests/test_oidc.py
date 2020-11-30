# -*- coding: utf-8 -*-
# Copyright 2020 CERN
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
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

from __future__ import print_function

import sys
import time
import traceback
import unittest
from datetime import datetime, timedelta

from oic import rndstr

from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import (CannotAuthenticate, DatabaseException)
from rucio.common.exception import Duplicate
from rucio.common.types import InternalAccount
from rucio.common.utils import oidc_identity_string
from rucio.core.account import add_account
from rucio.core.authentication import redirect_auth_oidc, validate_auth_token
from rucio.core.identity import add_account_identity
from rucio.core.oidc import (get_auth_oidc, get_token_oidc,
                             get_token_for_account_operation, EXPECTED_OIDC_AUDIENCE, EXPECTED_OIDC_SCOPE)
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountType
from rucio.db.sqla.constants import IdentityType
from rucio.db.sqla.session import get_session

try:
    # Python 2
    from urlparse import urlparse, parse_qs
except ImportError:
    # Python 3
    from urllib.parse import urlparse, parse_qs

if sys.version_info >= (3, 3):
    from unittest.mock import MagicMock, patch
else:
    from mock import MagicMock, patch

NEW_TOKEN_DICT = {'access_token': 'eyJ3bG...',
                  'expires_in': 3599,
                  'id_token': {'sub': 'abcdefg23', 'iss': 'https://test_auth_url_string/', 'nonce': 'mynonce'},
                  'scope': 'openid profile',
                  'token_type': 'Bearer',
                  'audience': 'rucio'}


EXCHANGED_TOKEN_DICT = {'access_token': 'eyJ3bG...',
                        'expires_in': 3599,
                        'id_token': {'sub': 'abcdefg23', 'iss': 'https://test_auth_url_string/', 'nonce': 'mynonce'},
                        'scope': 'openid profile',
                        'token_type': 'Bearer',
                        'audience': 'rucio'}


def encode_access_token(tokenlist):
    # tokenlist = [tokenstr, scope, audience, sub, iss]
    identity = oidc_identity_string(tokenlist[3], tokenlist[4])
    tokenout = tokenlist[0] + '_||_' + tokenlist[1] + '_||_' + tokenlist[2] + '_||_' + identity
    return tokenout


def dencode_access_token(tokenstr):
    # tokenlist = [tokenstr, scope, audience, sub, iss]
    tokenout = tokenstr.split("_||_")
    dictout = {'token': tokenout[0],
               'scope': tokenout[1],
               'audience': tokenout[2],
               'identity': tokenout[3]}
    return dictout


def save_validated_token(token, valid_dict, extra_dict=None, session=None):
    """
    Save JWT token to the Rucio DB.

    :param token: Authentication token as a variable-length string.
    :param valid_dict: Validation Rucio dictionary as the output
                       of the __get_rucio_jwt_dict function

    :returns: DB token object if successful, raises an exception otherwise.
    """
    try:
        if not extra_dict:
            extra_dict = {}
        new_token = models.Token(account=valid_dict.get('account', None),
                                 token=token,
                                 oidc_scope=valid_dict.get('authz_scope', None),
                                 expired_at=valid_dict.get('lifetime', None),
                                 audience=valid_dict.get('audience', None),
                                 identity=valid_dict.get('identity', None),
                                 refresh=extra_dict.get('refresh', False),
                                 refresh_token=extra_dict.get('refresh_token', None),
                                 refresh_expired_at=extra_dict.get('refresh_expired_at', None),
                                 refresh_lifetime=extra_dict.get('refresh_lifetime', None),
                                 refresh_start=extra_dict.get('refresh_start', None),
                                 ip=extra_dict.get('ip', None))
        new_token.save(session=session)
        return new_token
    except Exception as error:
        raise Exception(error.args)


def validate_jwt(token, **kwargs):
    account = kwargs.get('account', None)
    oidc_token_dict = dencode_access_token(token)
    expirydate = datetime.utcnow() + timedelta(seconds=3600)
    validate_dict = {'account': account,
                     'identity': oidc_token_dict['identity'],
                     'lifetime': expirydate,
                     'audience': oidc_token_dict['audience'],
                     'authz_scope': oidc_token_dict['scope']}
    return validate_dict


def create_preexisting_exchange_token(request_args, session=None):
    oidc_tokens = EXCHANGED_TOKEN_DICT.copy()
    oidc_tokens['scope'] = request_args['scope']
    oidc_tokens['audience'] = request_args['audience']
    oidc_tokens['expires_in'] = 3600
    oidc_tokens['id_token'] = {'sub': request_args['client_id'], 'iss': request_args['issuer']}
    access_token = encode_access_token([request_args['token'],
                                        request_args['scope'],
                                        request_args['audience'],
                                        request_args['client_id'],
                                        request_args['issuer']])
    validate_dict = validate_jwt(access_token, account=request_args['account'])
    pre_existing_token = save_validated_token(access_token, validate_dict, session=session)
    return pre_existing_token


def get_mock_oidc_client(**kwargs):
    # issuer_id = kwargs.get('issuer_id', None)
    # redirect_to = kwargs.get('redirect_to', None)
    state = str(kwargs.get('state', None))
    nonce = str(kwargs.get('nonce', None))
    # scope = kwargs.get('scope', None)
    # audience = kwargs.get('audience', None)
    # first_init = kwargs.get('first_init', None)

    return {'client': MockClientOIDC(),
            'state': state,
            'nonce': nonce,
            'auth_url': 'https://test_auth_url_string?state=' + state + '&nonce=' + nonce,
            'redirect': 'https://test_redirect_string'}


def get_oauth_session_row(account, state=None, session=None):
    if state:
        result = session.query(models.OAuthRequest).filter_by(account=account, state=state).all()  # pylint: disable=no-member
    else:
        result = session.query(models.OAuthRequest).filter_by(account=account).all()  # pylint: disable=no-member
    return result


def get_token_row(access_token, account=None, session=None):
    if account:
        result = session.query(models.Token).filter_by(account=account, token=access_token).all()  # pylint: disable=no-member
    else:
        result = session.query(models.Token).filter_by(token=access_token).all()  # pylint: disable=no-member
    return result


class MockADMINClientISSOIDC(MagicMock):
    # pylint: disable=unused-argument
    client_secret = 'topsecret_nr1'
    @classmethod
    def do_any(cls, request=None, request_args=None, response=None):
        oidc_tokens = EXCHANGED_TOKEN_DICT.copy()
        oidc_tokens['scope'] = request_args['scope']
        oidc_tokens['audience'] = request_args['audience']
        oidc_tokens['id_token'] = {'sub': request_args['client_id'], 'iss': 'https://test_issuer/'}
        # we need to passs the full dict in the access_token key again in order to have  a chance to bypas the token validation method
        access_token = encode_access_token([oidc_tokens['access_token'], oidc_tokens['scope'],
                                           oidc_tokens['audience'], request_args['client_id'], 'https://test_issuer/'])
        oidc_tokens['access_token'] = access_token
        return oidc_tokens

    @classmethod
    def construct_AuthorizationRequest(cls, request_args=None):
        return None

    @classmethod
    def parse_response(cls, AuthorizationResponse, info=None, sformat="urlencoded"):
        return None


class MockResponse(object):
    def __init__(self, json_data):
        self.json_data = json_data

    def json(self):
        return self.json_data


class MockClientOIDC(MagicMock):
    # pylint: disable=unused-argument
    @classmethod
    def do_access_token_request(cls, state=None, request_args={}, authn_method="client_secret_basic"):
        if request_args['code'] == 'wrongcode':
            return {'error': 'Unknown AuthZ code provided'}
        else:
            return NEW_TOKEN_DICT

    @classmethod
    def construct_AuthorizationRequest(cls, request_args=None):
        return None

    @classmethod
    def parse_response(cls, AuthorizationResponse, info=None, sformat="urlencoded"):
        return None

    client_secret = 'topsecret_nr1'
    @classmethod
    def do_any(cls, Message, endpoint=None, state=None, request_args=None, authn_method=None):
        oidc_tokens = EXCHANGED_TOKEN_DICT.copy()
        oidc_token_dict = dencode_access_token(request_args['subject_token'])
        user_sub = oidc_token_dict['identity'].split(',')[0].split('=')[1]
        user_issuer = oidc_token_dict['identity'].split(',')[1].split('=')[1]
        oidc_tokens['scope'] = request_args['scope']
        oidc_tokens['audience'] = request_args['audience']
        oidc_tokens['id_token'] = {'sub': user_sub, 'iss': user_issuer}
        # we need to passs the full dict in the access_token key again in order to have  a chance to bypas the token validation method
        access_token = encode_access_token([oidc_tokens['access_token'], oidc_tokens['scope'],
                                           oidc_tokens['audience'], user_sub, user_issuer])
        oidc_tokens['access_token'] = access_token
        return MockResponse(oidc_tokens)


class MockADMINClientOtherISSOIDC(MagicMock):
    # pylint: disable=unused-argument
    client_secret = 'topsecret_nr2'
    @classmethod
    def do_any(cls, request=None, request_args=None, response=None):
        oidc_tokens = EXCHANGED_TOKEN_DICT.copy()
        oidc_tokens['scope'] = request_args['scope']
        oidc_tokens['audience'] = request_args['audience']
        oidc_tokens['id_token'] = {'sub': request_args['client_id'], 'iss': 'https://test_other_issuer/'}
        # we need to passs the full dict in the access_token key again in order to have  a chance to bypas the token validation method
        access_token = encode_access_token([oidc_tokens['access_token'], oidc_tokens['scope'],
                                           oidc_tokens['audience'], request_args['client_id'], 'https://test_other_issuer/'])
        oidc_tokens['access_token'] = access_token
        return oidc_tokens

    @classmethod
    def construct_AuthorizationRequest(cls, request_args=None):
        return None

    @classmethod
    def parse_response(cls, AuthorizationResponse, info=None, sformat="urlencoded"):
        return None


class TestAuthCoreAPIoidc(unittest.TestCase):

    """ OIDC Core API Testing: Testing creation of authorization URL for Rucio Client,
        token request, token exchange, admin token request, finding token for an account.
        TO-DO tests for: exchange_token_oidc, get_token_for_account_operation, get_admin_token_oidc

        setUp function (below) runs first (nose does this automatically)

    """
    # pylint: disable=unused-argument

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

        self.db_session = get_session()
        self.accountstring = 'test_' + rndstr()
        self.accountstring = self.accountstring.lower()
        self.account = InternalAccount(self.accountstring, **self.vo)
        self.adminaccountstring = 'admin_' + rndstr()[:-1]  # Too long to use full string
        print("ADMIN ACOUNT STRING: ", self.adminaccountstring)
        self.adminaccountstring = self.adminaccountstring.lower()
        self.adminaccount = InternalAccount(self.adminaccountstring, **self.vo)
        self.adminaccSUB = str('adminSUB' + rndstr()).lower()
        self.adminaccSUB_otherISS = str('adminSUB_otherISS' + rndstr()).lower()
        self.adminClientSUB = str('adminclientSUB' + rndstr()).lower()
        self.adminClientSUB_otherISS = str('adminclientSUB_otherISS' + rndstr()).lower()
        try:
            add_account(self.account, AccountType.USER, 'rucio@email.com', session=self.db_session)
        except Duplicate:
            pass
        try:
            add_account(self.adminaccount, AccountType.SERVICE, 'rucio@email.com', session=self.db_session)
        except Duplicate:
            pass

        try:
            add_account_identity('SUB=knownsub, ISS=https://test_issuer/', IdentityType.OIDC, self.account, 'rucio_test@test.com', session=self.db_session)
            add_account_identity('SUB=%s, ISS=https://test_issuer/' % self.adminaccSUB, IdentityType.OIDC, self.adminaccount, 'rucio_test@test.com', session=self.db_session)
            add_account_identity('SUB=%s, ISS=https://test_other_issuer/' % self.adminaccSUB_otherISS, IdentityType.OIDC, self.adminaccount, 'rucio_test@test.com', session=self.db_session)
            add_account_identity('SUB=%s, ISS=https://test_issuer/' % self.adminClientSUB, IdentityType.OIDC, self.adminaccount, 'rucio_test@test.com', session=self.db_session)
            add_account_identity('SUB=%s, ISS=https://test_other_issuer/' % self.adminClientSUB_otherISS, IdentityType.OIDC, self.adminaccount, 'rucio_test@test.com', session=self.db_session)
        except DatabaseException:
            pass

    def tearDown(self):
        self.db_session.remove()

    def get_auth_init_and_mock_response(self, code_response, account=None, polling=False, auto=True, session=None):
        """
        OIDC creates entry in oauth_requests table

        returns: auth_query_string (state=xxx&code=yyy
                 as would be returned from the IdP
                 after a successful authentication)

        """
        if not account:
            account = self.account
        try:

            kwargs = {'auth_scope': 'openid profile',
                      'audience': 'rucio',
                      'issuer': 'dummy_admin_iss_nickname',
                      'auto': auto,
                      'polling': polling,
                      'refresh_lifetime': 96,
                      'ip': None,
                      'webhome': 'https://rucio-test.cern.ch/ui'
                      }
            auth_url = get_auth_oidc(account, session=session, **kwargs)
            # get the state from the auth_url and add an arbitrary code value to the query string
            # to mimick a return of IdP with authz_code
            urlparsed = urlparse(auth_url)
            urlparams = parse_qs(urlparsed.query)
            if ('_polling' in auth_url) or (not polling and not auto):
                auth_url = redirect_auth_oidc(urlparsed.query, session=session)

            urlparsed = urlparse(auth_url)
            urlparams = parse_qs(urlparsed.query)
            state = urlparams["state"][0]
            nonce = urlparams["nonce"][0]
            auth_query_string = "state=" + state + "&code=" + code_response
            return {'state': state, 'nonce': nonce, 'auth_url': auth_url, 'auth_query_string': auth_query_string}
        except:
            print(traceback.format_exc())

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_auth_oidc_url(self, mock_clients, mock_oidc_client):
        """ OIDC Auth URL generation

            Runs the Test:

            - calling the respective function

            End:

            - checking the URL to be as expected
        """

        mock_oidc_client.side_effect = get_mock_oidc_client

        try:
            kwargs = {'auth_scope': 'openid profile',
                      'audience': 'rucio',
                      'issuer': 'dummy_admin_iss_nickname',
                      'auto': False,
                      'polling': False,
                      'refresh_lifetime': 96,
                      'ip': None,
                      'webhome': None}
            # testing classical CLI login init, expecting user to be
            # redirected via Rucio Auth server to the IdP issuer for login
            auth_url = get_auth_oidc(self.account, session=self.db_session, **kwargs)
            assert 'https://test_redirect_string/auth/oidc_redirect?' in auth_url and '_polling' not in auth_url

            # testing classical CLI login init, expecting user to be redirected
            # via Rucio Auth server to the IdP issuer for login and Rucio Client
            # to be polling the Rucio Auth server for token until done so
            kwargs['polling'] = True
            auth_url = get_auth_oidc(self.account, session=self.db_session, **kwargs)
            assert 'https://test_redirect_string/auth/oidc_redirect?' in auth_url and '_polling' in auth_url

            # testing classical CLI login init, with the Rucio Client being
            # trusted with IdP user credentials (auto = True). Rucio Client
            # gets directly the auth_url pointing it to the IdP
            kwargs['polling'] = False
            kwargs['auto'] = True
            auth_url = get_auth_oidc(self.account, session=self.db_session, **kwargs)
            assert 'https://test_auth_url_string' in auth_url

            # testing webui login URL (auto = True, polling = False)
            kwargs['webhome'] = 'https://back_to_rucio_ui_page'
            auth_url = get_auth_oidc(InternalAccount('webui', **self.vo), session=self.db_session, **kwargs)
            assert 'https://test_auth_url_string' in auth_url

        except:
            print(traceback.format_exc())

    def test_get_token_oidc_unknown_state(self):
        """ OIDC Token request with unknown state from IdP

            Runs the Test:

            - requesting token with parameters without coresponding
              DB entry (in oauth_Requests table)

            End:

            - checking the relevant exception to be thrown
        """
        try:
            auth_query_string = "state=" + rndstr() + "&code=" + rndstr()
            get_token_oidc(auth_query_string, session=self.db_session)
        except CannotAuthenticate:
            assert "could not keep track of responses from outstanding requests" in traceback.format_exc()

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_token_oidc_unknown_code(self, mock_clients, mock_oidc_client):
        """ OIDC Token request with unknown code from IdP

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        try:
            auth_init_response = self.get_auth_init_and_mock_response(code_response='wrongcode', session=self.db_session)
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
            assert oauth_session_row
            get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        except CannotAuthenticate:
            assert "Unknown AuthZ code provided" in traceback.format_exc()

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_token_oidc_unknown_nonce(self, mock_clients, mock_oidc_client):
        """ OIDC Token request with unknown nonce from IdP

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        try:
            auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
            assert oauth_session_row

            NEW_TOKEN_DICT['id_token']['nonce'] = 'wrongnonce'
            get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        except CannotAuthenticate:
            assert "This points to possible replay attack !" in traceback.format_exc()

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_token_oidc_unknown_account_identity(self, mock_clients, mock_oidc_client):
        """ OIDC Token request with unknown account identity in the token from IdP

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        try:
            auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
            assert oauth_session_row

            NEW_TOKEN_DICT['id_token'] = {'sub': 'unknownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
            get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        except CannotAuthenticate:
            assert "OIDC identity 'SUB=unknownsub, ISS=https://test_issuer/' of the '" + self.accountstring + "' account is unknown to Rucio." in traceback.format_exc()

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_token_oidc_unknown_webui_account_identity(self, mock_clients, mock_oidc_client):
        """ OIDC Token request with unknown webui identity in the token from IdP

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client

        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), account=InternalAccount('webui', **self.vo), session=self.db_session)
        # check if DB entry exists
        oauth_session_row = get_oauth_session_row(InternalAccount('webui', **self.vo), state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row

        NEW_TOKEN_DICT['id_token'] = {'sub': 'unknownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict['webhome'] is None
        assert token_dict['token'] is None

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_token_oidc_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access token - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert db_token

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_token_oidc_webui_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access token via webui 'account' - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking if the right token is saved in the DB and if it is present
              in the return dict of the get_token_oidc fucntion
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), account=InternalAccount('webui', **self.vo), session=self.db_session)
        oauth_session_row = get_oauth_session_row(InternalAccount('webui', **self.vo), state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        assert token_dict['webhome'] is not None
        assert token_dict['token'].token == access_token
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token, session=self.db_session)
        assert db_token

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_token_oidc_cli_polling_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access token while client is polling - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking if the token is in the DB and no token is being returned from the core function
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), polling=True, auto=False, session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        assert token_dict['polling'] is True
        assert 'token' not in token_dict
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token, session=self.db_session)
        assert db_token

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_token_oidc_cli_fetchcode_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access token, client receives fetchcode - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking if the token is in the DB and a fetchcode is being returned from the core function
            - fetching the token
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), polling=False, auto=False, session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        assert 'fetchcode' in token_dict
        assert 'token' not in token_dict
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token, session=self.db_session)
        assert db_token
        token = redirect_auth_oidc(token_dict['fetchcode'], fetchtoken=True, session=self.db_session)
        assert token == access_token

    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_access_and_refresh_tokens_oidc_success(self, mock_clients, mock_oidc_client):
        """ OIDC Request for access and refresh tokens - success

            Runs the Test:

            - getting the auth_query_string (mocking the IdP response)
              and with it the corresponding entry in the oauth_requests table
            - filling the right identity into the token (mocking the IdP response)
            - calling the get_token_oidc core function

            End:

            - checking the relevant exception to be thrown
        """
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        refresh_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['refresh_token'] = refresh_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert db_token
        for token in db_token:
            assert token.token == access_token
            assert token.refresh_token == refresh_token

    @patch('rucio.core.oidc.JWS')
    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_CLIENTS')
    def test_validate_and_save_external_token_success(self, mock_oidc_clients, mock_jwt_dict, mock_jws):
        """ OIDC validate externally provided token with correct audience, scope and issuer - success

            Runs the Test:

            - mocking the OIDC client, and token validation dictionary pretending
              the externally passed token is valid (time, issuer, audience, scope all as expected)
            - calling the validate_auth_token core function (which is being called
              e.g. when trying to validate tokens passed to rucio in the header of a request

            End:

            - checking if the external token has been saved in the DB

        """

        mock_oidc_clients.return_value = {'https://test_issuer/': MockClientOIDC()}
        token_validate_dict = {'account': self.account,
                               'identity': 'SUB=knownsub, ISS=https://test_issuer/',
                               'lifetime': datetime.utcfromtimestamp(time.time() + 60),
                               'audience': 'rucio',
                               'authz_scope': 'openid profile'}
        mock_jwt_dict.return_value = token_validate_dict

        # mocking the token response
        access_token = rndstr() + '.' + rndstr() + '.' + rndstr()
        # trying to validate a token that does not exist in the Rucio DB
        value = validate_auth_token(access_token, session=self.db_session)
        # checking if validation went OK (we bypassed it with the dictionary above)
        assert value == token_validate_dict
        # most importantly, check that the token was saved in Rucio DB
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert db_token
        for token in db_token:
            assert token.token == access_token

    @patch('rucio.core.oidc.JWS')
    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_CLIENTS')
    def test_validate_and_save_external_token_fail(self, mock_oidc_clients, mock_jwt_dict, mock_jws):
        """ OIDC validate externally provided token with correct audience, scope and issuer - failure

            Runs the Test:

            - mocking the OIDC client, and token validation dictionary pretending
              the externally passed token has invalid audience
            - calling the validate_auth_token core function (which is being called
              e.g. when trying to validate tokens passed to rucio in the header of a request

            End:

            - checking if the external token was not saved in the DB

        """

        mock_oidc_clients.return_value = {'https://test_issuer/': MockClientOIDC()}
        token_validate_dict = {'account': self.account,
                               'identity': 'SUB=knownsub, ISS=https://test_issuer/',
                               'lifetime': datetime.utcfromtimestamp(time.time() + 60),
                               'audience': 'unknown_audience',
                               'authz_scope': 'openid profile'}
        mock_jwt_dict.return_value = token_validate_dict

        # mocking the token response
        access_token = rndstr() + '.' + rndstr() + '.' + rndstr()
        # trying to validate a token that does not exist in the Rucio DB
        value = validate_auth_token(access_token, session=self.db_session)
        # checking if validation went OK (we bypassed it with the dictionary above)
        assert value is None
        # most importantly, check that the token was saved in Rucio DB
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert not db_token

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_1(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminON_useraccREQ_hasSUBtoken_NoFinalPreexistingToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a user account name
              - user HAS valid subject token
              - final token for FTS transfer with required scope and audience does NOT exist already

            Runs the Test:

                        - see actions below

            End:

            - checking that the final result has issuer same as user OIDC identity issuer of the subject token
            - checking that the final token belongs to the admin account
            - final token has the requested scope and audience claims in
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.account
        final_token_account = self.adminaccount
        req_admin = True
        # ---------------------------
        # giving a USER a subject token
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert db_token
        # ---------------------------
        # preparing the expected resulting token
        expected_access_token_strpart = rndstr()
        EXCHANGED_TOKEN_DICT['access_token'] = expected_access_token_strpart
        expected_access_token = encode_access_token([expected_access_token_strpart, req_scope, req_audience, self.adminClientSUB, 'https://test_issuer/'])
        # for  OIDC_ADMIN_CLIENTS in __get_admin_token_oidc we need to mock result of __get_rucio_oidc_clients
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert 'https://test_issuer/' in new_token_dict['identity']
        assert self.adminClientSUB in new_token_dict['identity']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # ---------------------------
        # Check that the resulting token is NOT same as original
        assert not token_dict['token'] == new_token_dict['token']
        # -----
        # check that result is as expected
        assert expected_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_2(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminON_useraccREQ_hasSUBtoken_HasPreexistingFinalToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a user account name
              - user HAS valid subject token
              - final token for FTS transfer with required scope and audience does exist already

            Runs the Test:

                        - see actions below

            End:

            - checking that the final result has issuer same as user OIDC identity issuer of the subject token
            - checking that the final token belongs to the admin account
            - final token has the requested scope and audience claims in and is the same as the preexisting one
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.account
        final_token_account = self.adminaccount
        final_token_issuer = 'https://test_issuer/'
        req_admin = True
        # ---------------------------
        # giving a USER a subject token
        mock_oidc_client.side_effect = get_mock_oidc_client
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), session=self.db_session)
        oauth_session_row = get_oauth_session_row(self.account, state=auth_init_response['state'], session=self.db_session)
        assert oauth_session_row
        # ---------------------------
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'], session=self.db_session)
        assert token_dict
        db_token = get_token_row(access_token, account=self.account, session=self.db_session)
        assert db_token
        # ---------------------------
        # giving the final token account PRE EXISTING FINAL token
        preexisting_access_token_strpart = rndstr()
        request_args = {'scope': req_scope,
                        'audience': req_audience,
                        'client_id': self.adminClientSUB,
                        'issuer': final_token_issuer,
                        'account': final_token_account,
                        'token': preexisting_access_token_strpart}
        expected_preexisting_access_token_object = create_preexisting_exchange_token(request_args, session=self.db_session)
        expected_preexisting_access_token = expected_preexisting_access_token_object.token
        db_token = get_token_row(expected_preexisting_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # preparing the expected resulting token
        not_expected_access_token_strpart = rndstr()
        EXCHANGED_TOKEN_DICT['access_token'] = not_expected_access_token_strpart
        not_expected_access_token = encode_access_token([not_expected_access_token_strpart, req_scope, req_audience, self.adminClientSUB, 'https://test_issuer/'])
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert 'https://test_issuer/' in new_token_dict['identity']
        # and that the SUB claim is as expected the admin client_id
        assert self.adminClientSUB in new_token_dict['identity']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # ---------------------------
        # check that the not expected token is not in the DB
        db_token = get_token_row(not_expected_access_token, session=self.db_session)
        assert not db_token
        # ---------------------------
        # Check that it has the expected token string
        assert expected_preexisting_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_3(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminON_useraccREQ_NOSUBtoken_NoFinalPreexistingToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a user account name
              - user DOES NOT HAVE valid subject token
              - final token for FTS transfer with required scope and audience does NOT exist apriori

            Runs the Test:

                        - see actions below

            End:

            - checking that the final result is NOne as the user has no valid OIDC token in the DB to start with !
        """
        # ---------------------------
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.account
        req_admin = True
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)

        # ---------------------------
        # Check if NO token has been received
        assert not new_token_dict

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_4(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminON_useraccREQ_NOSUBtoken_HasPreexistingFinalToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a user account name
              - user HAS NO valid subject token
              - final token for FTS transfer with required scope and audience does exist already

            Runs the Test:

                        - see actions below

            End:

            - checking that the final result is NOne as the user has no valid OIDC token in the DB to start with !
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.account
        final_token_account = self.adminaccount
        final_token_issuer_1 = 'https://test_issuer/'
        final_token_issuer_2 = 'https://test_other_issuer/'
        req_admin = True
        # -----------------------------
        # creating pre-existing token that is supposed to be picked up as final
        preexisting_access_token_strpart_1 = rndstr()
        preexisting_access_token_strpart_2 = rndstr()
        request_args = {'scope': req_scope,
                        'audience': req_audience,
                        'client_id': self.adminClientSUB,
                        'issuer': final_token_issuer_1,
                        'account': final_token_account,
                        'token': preexisting_access_token_strpart_1}
        expected_preexisting_access_token_object_1 = create_preexisting_exchange_token(request_args, session=self.db_session)
        request_args['issuer'] = final_token_issuer_2
        request_args['client_id'] = self.adminClientSUB_otherISS
        request_args['token'] = preexisting_access_token_strpart_2
        expected_preexisting_access_token_object_2 = create_preexisting_exchange_token(request_args, session=self.db_session)
        expected_preexisting_access_token_1 = expected_preexisting_access_token_object_1.token
        expected_preexisting_access_token_2 = expected_preexisting_access_token_object_2.token
        db_token = get_token_row(expected_preexisting_access_token_1, account=final_token_account, session=self.db_session)
        assert db_token
        db_token = get_token_row(expected_preexisting_access_token_2, account=final_token_account, session=self.db_session)
        assert db_token
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if NO token has been received
        assert not new_token_dict

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_5(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminON_adminaccREQ_NOSUBtoken_NoFinalPreexistingToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for admin account name
              - admin has a valid token AS NO valid subject token
              - final token for FTS transfer with required scope and audience does NOT exist apriori

            Runs the Test:
            - see actions below
            End:

            - checking that token was issued to the admin account of any of the OIDC admin clients
            - final token has the requested scope and audience claims in and is the same as the expected string
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.adminaccount
        final_token_account = self.adminaccount
        req_admin = True
        # ---------------------------
        # preparing the expected resulting token
        expected_access_token_strpart = rndstr()
        EXCHANGED_TOKEN_DICT['access_token'] = expected_access_token_strpart
        expected_access_token_1 = encode_access_token([expected_access_token_strpart, req_scope, req_audience, self.adminClientSUB, 'https://test_issuer/'])
        expected_access_token_2 = encode_access_token([expected_access_token_strpart, req_scope, req_audience, self.adminClientSUB_otherISS, 'https://test_other_issuer/'])
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer same as admin OIDC identity issuer of the subject token
        assert (('https://test_issuer/' in new_token_dict['identity']) and (self.adminClientSUB in new_token_dict['identity'])
                    or (('https://test_other_issuer/' in new_token_dict['identity']) and (self.adminClientSUB_otherISS in new_token_dict['identity'])))  # NOQA: W503
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert (expected_access_token_1 == new_token_dict['token']) or (expected_access_token_2 == new_token_dict['token'])

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_6(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminON_adminaccREQ_hasSUBtoken_NoFinalPreexistingToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a admin account name
              - has pre-existing token which does NOT have the same audience and scope
              - final token for FTS transfer with required scope and audience does NOT exist yet

            Runs the Test:

                        - see actions below

            End:

            - checking that the final token is NOT the same as the preexisting one apart of the issuer !
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.adminaccount
        final_token_account = self.adminaccount
        final_token_issuer_2 = 'https://test_other_issuer/'
        req_admin = True
        # -----------------------------
        # creating pre-existing token that is NOT supposed to be picked up as final
        preexisting_access_token_strpart_2 = rndstr()
        request_args = {'scope': EXPECTED_OIDC_SCOPE,
                        'audience': EXPECTED_OIDC_AUDIENCE,
                        'client_id': self.adminaccSUB_otherISS,
                        'issuer': final_token_issuer_2,
                        'account': final_token_account,
                        'token': preexisting_access_token_strpart_2}
        preexisting_access_token_object = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_access_token = preexisting_access_token_object.token
        db_token = get_token_row(preexisting_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # preparing the expected resulting token
        expected_access_token_strpart = rndstr()
        EXCHANGED_TOKEN_DICT['access_token'] = expected_access_token_strpart
        expected_access_token = encode_access_token([expected_access_token_strpart, req_scope, req_audience, self.adminClientSUB_otherISS, final_token_issuer_2])
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer and sub claim as expected
        assert ('https://test_other_issuer/' in new_token_dict['identity']) and (self.adminClientSUB_otherISS in new_token_dict['identity'])
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert expected_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_7(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminON_adminaccREQ_hasSUBtoken_HasPreexistingFinalToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a admin account name
              - has pre-existing token which does not have the same audience and scope
              - has final token for FTS using a different issuer (the challenging mode)

            Runs the Test:

                        - see actions below
            End:

            - checking that the final token is NOT the same as the preexisting one
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.adminaccount
        final_token_account = self.adminaccount
        final_token_issuer_1 = 'https://test_issuer/'
        final_token_issuer_2 = 'https://test_other_issuer/'
        req_admin = True
        # -----------------------------
        # creating pre-existing token that is supposed to be picked up as final
        preexisting_access_token_strpart_2 = rndstr()
        request_args = {'scope': EXPECTED_OIDC_SCOPE,
                        'audience': EXPECTED_OIDC_AUDIENCE,
                        'client_id': self.adminaccSUB_otherISS,
                        'issuer': final_token_issuer_2,
                        'account': final_token_account,
                        'token': preexisting_access_token_strpart_2}
        preexisting_access_token_object_2 = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_access_token = preexisting_access_token_object_2.token
        db_token = get_token_row(preexisting_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        preexisting_final_access_token_strpart_1 = rndstr()
        request_args = {'scope': req_scope,
                        'audience': req_audience,
                        'client_id': self.adminClientSUB,
                        'issuer': final_token_issuer_1,
                        'account': final_token_account,
                        'token': preexisting_final_access_token_strpart_1}
        preexisting_final_access_token_object_1 = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_final_access_token = preexisting_final_access_token_object_1.token
        db_token = get_token_row(preexisting_final_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer and sub claim as expected
        assert ('https://test_issuer/' in new_token_dict['identity']) and (self.adminClientSUB in new_token_dict['identity'])
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert preexisting_final_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_8(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminON_adminaccREQ_NOSUBtoken_HasPreexistingFinalToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a admin account name
              - has no pre-existing token which would have other than the expected audience and scopes audience and scope
              - has final token for FTS is present
            Runs the Test:

                        - see actions below
            End:

            - checking that the final token is the same as the preexisting one
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.adminaccount
        final_token_account = self.adminaccount
        final_token_issuer_2 = 'https://test_other_issuer/'
        req_admin = True
        # -----------------------------
        # creating pre-existing token that is supposed to be picked up as final
        preexisting_final_access_token_strpart_2 = rndstr()
        request_args = {'scope': req_scope,
                        'audience': req_audience,
                        'client_id': self.adminClientSUB_otherISS,
                        'issuer': final_token_issuer_2,
                        'account': final_token_account,
                        'token': preexisting_final_access_token_strpart_2}
        preexisting_final_access_token_object_2 = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_final_access_token = preexisting_final_access_token_object_2.token
        db_token = get_token_row(preexisting_final_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer and sub claim as expected
        assert ('https://test_other_issuer/' in new_token_dict['identity']) and (self.adminClientSUB_otherISS in new_token_dict['identity'])
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert preexisting_final_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_9(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminOFF_adminaccREQ_NOSUBtoken_NoFinalPreexistingToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for admin account name
              - admin has a valid token AS NO valid subject token
              - final token for FTS transfer with required scope and audience does NOT exist apriori

            Runs the Test:
            - see actions below
            End:

            - checking that token was issued to the admin account of any of the OIDC admin clients
            - final token has the requested scope and audience claims in and is the same as the expected string
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.adminaccount
        final_token_account = self.adminaccount
        req_admin = False
        # ---------------------------
        # preparing the expected resulting token
        expected_access_token_strpart = rndstr()
        EXCHANGED_TOKEN_DICT['access_token'] = expected_access_token_strpart
        expected_access_token_1 = encode_access_token([expected_access_token_strpart, req_scope, req_audience, self.adminClientSUB, 'https://test_issuer/'])
        expected_access_token_2 = encode_access_token([expected_access_token_strpart, req_scope, req_audience, self.adminClientSUB_otherISS, 'https://test_other_issuer/'])
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer same as admin OIDC identity issuer of the subject token
        assert (('https://test_issuer/' in new_token_dict['identity']) and (self.adminClientSUB in new_token_dict['identity'])
                    or (('https://test_other_issuer/' in new_token_dict['identity']) and (self.adminClientSUB_otherISS in new_token_dict['identity'])))  # NOQA: W503
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert (expected_access_token_1 == new_token_dict['token']) or (expected_access_token_2 == new_token_dict['token'])

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_10(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminOFF_adminaccREQ_hasSUBtoken_NoFinalPreexistingToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a admin account name
              - has pre-existing token which does NOT have the same audience and scope
              - final token for FTS transfer with required scope and audience does NOT exist yet

            Runs the Test:

                        - see actions below

            End:

            - checking that the final token is NOT the same as the preexisting one apart of the issuer !
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.adminaccount
        final_token_account = self.adminaccount
        final_token_issuer_2 = 'https://test_other_issuer/'
        req_admin = False
        # -----------------------------
        # creating pre-existing token that is NOT supposed to be picked up as final
        preexisting_access_token_strpart_2 = rndstr()
        request_args = {'scope': EXPECTED_OIDC_SCOPE,
                        'audience': EXPECTED_OIDC_AUDIENCE,
                        'client_id': self.adminaccSUB_otherISS,
                        'issuer': final_token_issuer_2,
                        'account': final_token_account,
                        'token': preexisting_access_token_strpart_2}
        preexisting_access_token_object = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_access_token = preexisting_access_token_object.token
        db_token = get_token_row(preexisting_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # preparing the expected resulting token
        expected_access_token_strpart = rndstr()
        EXCHANGED_TOKEN_DICT['access_token'] = expected_access_token_strpart
        expected_access_token = encode_access_token([expected_access_token_strpart, req_scope, req_audience, self.adminClientSUB_otherISS, final_token_issuer_2])
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer and sub claim as expected
        assert ('https://test_other_issuer/' in new_token_dict['identity']) and (self.adminClientSUB_otherISS in new_token_dict['identity'])
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert expected_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_11(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminOFF_adminaccREQ_hasSUBtoken_HasPreexistingFinalToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a admin account name
              - has pre-existing token which does not have the same audience and scope
              - has final token for FTS using a different issuer (the challenging mode)

            Runs the Test:

                        - see actions below
            End:

            - checking that the final token is the same as the preexisting final one
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.adminaccount
        final_token_account = self.adminaccount
        final_token_issuer_1 = 'https://test_issuer/'
        final_token_issuer_2 = 'https://test_other_issuer/'
        req_admin = False
        # -----------------------------
        # creating pre-existing token that is supposed to be picked up as final
        preexisting_access_token_strpart_2 = rndstr()
        request_args = {'scope': EXPECTED_OIDC_SCOPE,
                        'audience': EXPECTED_OIDC_AUDIENCE,
                        'client_id': self.adminaccSUB_otherISS,
                        'issuer': final_token_issuer_2,
                        'account': final_token_account,
                        'token': preexisting_access_token_strpart_2}
        preexisting_access_token_object_2 = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_access_token = preexisting_access_token_object_2.token
        db_token = get_token_row(preexisting_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        preexisting_final_access_token_strpart_1 = rndstr()
        request_args = {'scope': req_scope,
                        'audience': req_audience,
                        'client_id': self.adminClientSUB,
                        'issuer': final_token_issuer_1,
                        'account': final_token_account,
                        'token': preexisting_final_access_token_strpart_1}
        preexisting_final_access_token_object_1 = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_final_access_token = preexisting_final_access_token_object_1.token
        db_token = get_token_row(preexisting_final_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer and sub claim as expected
        assert ('https://test_issuer/' in new_token_dict['identity']) and (self.adminClientSUB in new_token_dict['identity'])
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert preexisting_final_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_12(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminOFF_adminaccREQ_NOSUBtoken_HasPreexistingFinalToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a admin account name
              - has no pre-existing token which would have other than the expected audience and scopes audience and scope
              - has final token for FTS is present
            Runs the Test:

                        - see actions below
            End:

            - checking that the final token is the same as the preexisting final one
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.adminaccount
        final_token_account = self.adminaccount
        final_token_issuer_2 = 'https://test_other_issuer/'
        req_admin = True
        # -----------------------------
        # creating pre-existing token that is supposed to be picked up as final
        preexisting_final_access_token_strpart_2 = rndstr()
        request_args = {'scope': req_scope,
                        'audience': req_audience,
                        'client_id': self.adminClientSUB_otherISS,
                        'issuer': final_token_issuer_2,
                        'account': final_token_account,
                        'token': preexisting_final_access_token_strpart_2}
        preexisting_final_access_token_object_2 = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_final_access_token = preexisting_final_access_token_object_2.token
        db_token = get_token_row(preexisting_final_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer and sub claim as expected
        assert ('https://test_other_issuer/' in new_token_dict['identity']) and (self.adminClientSUB_otherISS in new_token_dict['identity'])
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert preexisting_final_access_token == new_token_dict['token']

        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer and sub claim as expected
        assert ('https://test_other_issuer/' in new_token_dict['identity']) and (self.adminClientSUB_otherISS in new_token_dict['identity'])
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # Check that it has the expected token string
        assert preexisting_final_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_13(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminOFF_useraccREQ_hasSUBtoken_NoFinalPreexistingToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a user account name
              - user HAS valid subject token
              - final token for FTS transfer with required scope and audience does NOT exist already

            Runs the Test:

                        - see actions below

            End:

            - checking that the final result has issuer same as SUBtoken
            - checking that the final token belongs to user account
            - final token has the requested scope and audience claims in
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.account
        final_token_account = self.account
        final_token_issuer = 'https://test_issuer/'
        user_sub = 'knownsub'
        req_admin = False
        # ---------------------------
        # giving a USER a subject token - ned to bypass the usual auth grant flow
        # as that is not the purpose of this test
        preexisting_user_access_token_strpart = rndstr()
        request_args = {'scope': EXPECTED_OIDC_SCOPE,
                        'audience': EXPECTED_OIDC_AUDIENCE,
                        'client_id': user_sub,
                        'issuer': final_token_issuer,
                        'account': final_token_account,
                        'token': preexisting_user_access_token_strpart}
        preexisting_user_access_token_object = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_user_access_token = preexisting_user_access_token_object.token
        db_token = get_token_row(preexisting_user_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # preparing the expected resulting token
        expected_access_token_strpart = rndstr()
        EXCHANGED_TOKEN_DICT['access_token'] = expected_access_token_strpart
        expected_access_token = encode_access_token([expected_access_token_strpart, req_scope, req_audience, 'knownsub', 'https://test_issuer/'])
        # for  OIDC_ADMIN_CLIENTS in __get_admin_token_oidc we need to mock result of __get_rucio_oidc_clients
        MockAdminOIDCClients = {'https://test_other_issuer/': MockClientOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockClientOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        print('NEW TOKEN DICT ==', new_token_dict)
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert 'https://test_issuer/' in new_token_dict['identity']
        assert 'knownsub' in new_token_dict['identity']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_scope == new_token_dict['oidc_scope']
        # ---------------------------
        # Check hat the final result has issuer same as user OIDC identity issuer of the subject token
        assert req_audience == new_token_dict['audience']
        # ---------------------------
        # Check that the resulting token is NOT same as original
        assert not preexisting_user_access_token == new_token_dict['token']
        # -----
        # check that result is as expected
        assert expected_access_token == new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_14(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminOFF_useraccREQ_hasSUBtoken_HasPreexistingFinalToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a user account name
              - user HAS valid subject token
              - final token for FTS transfer with required scope and audience does exist already

            Runs the Test:

                        - see actions below

            End:

            - checking that the final result is the same as the pre-existing final token
        """
        # ---------------------------
        # setting conditions of the test
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.account
        final_token_account = self.account
        final_token_issuer = 'https://test_issuer/'
        user_sub = 'knownsub'
        req_admin = False
        # ---------------------------
        # giving a USER a subject token - ned to bypass the usual auth grant flow
        # as that is not the purpose of this test
        preexisting_user_access_token_strpart = rndstr()
        request_args = {'scope': EXPECTED_OIDC_SCOPE,
                        'audience': EXPECTED_OIDC_AUDIENCE,
                        'client_id': user_sub,
                        'issuer': final_token_issuer,
                        'account': final_token_account,
                        'token': preexisting_user_access_token_strpart}
        preexisting_user_access_token_object = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_user_access_token = preexisting_user_access_token_object.token
        db_token = get_token_row(preexisting_user_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        # giving a user a filen token
        final_access_token = rndstr()
        request_args = {'scope': req_scope,
                        'audience': req_audience,
                        'client_id': user_sub,
                        'issuer': final_token_issuer,
                        'account': final_token_account,
                        'token': final_access_token}
        preexisting_final_user_access_token_object = create_preexisting_exchange_token(request_args, session=self.db_session)
        preexisting_final_user_access_token = preexisting_final_user_access_token_object.token
        db_token = get_token_row(preexisting_final_user_access_token, account=final_token_account, session=self.db_session)
        assert db_token
        #
        # ---------------------------
        # preparing the expected resulting token
        expected_access_token_strpart = rndstr()
        EXCHANGED_TOKEN_DICT['access_token'] = expected_access_token_strpart
        hypothetical_exchange_access_token = encode_access_token([expected_access_token_strpart, req_scope, req_audience, 'knownsub', 'https://test_issuer/'])
        # for  OIDC_ADMIN_CLIENTS in __get_admin_token_oidc we need to mock result of __get_rucio_oidc_clients
        MockAdminOIDCClients = {'https://test_other_issuer/': MockClientOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockClientOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if token has been received
        assert new_token_dict
        # ---------------------------
        # Check of token being in DB under the expected account
        db_token = get_token_row(new_token_dict['token'], account=final_token_account, session=self.db_session)
        assert db_token
        assert 'https://test_issuer/' in new_token_dict['identity']
        assert 'knownsub' in new_token_dict['identity']
        assert req_scope == new_token_dict['oidc_scope']
        assert req_audience == new_token_dict['audience']
        assert preexisting_final_user_access_token == new_token_dict['token']
        assert hypothetical_exchange_access_token != new_token_dict['token']

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_15(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminOFF_useraccREQ_NOSUBtoken_NoFinalPreexistingToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a user account name
              - user DOES NOT HAVE valid subject token
              - final token for FTS transfer with required scope and audience does NOT exist apriori

            Runs the Test:

                        - see actions below

            End:

            - checking that the final result is NOne as the user has no valid OIDC token in the DB to start with !
        """
        # ---------------------------
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.account
        req_admin = False
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if NO token has been received
        assert not new_token_dict

    @patch('rucio.core.oidc.__get_rucio_jwt_dict')
    @patch('rucio.core.oidc.OIDC_ADMIN_CLIENTS')
    @patch('rucio.core.oidc.__get_init_oidc_client')
    @patch('rucio.core.oidc.__get_rucio_oidc_clients')
    def test_get_AT_for_account_operation_16(self, mock_clients, mock_oidc_client, admin_clients, validate_jwt_dict):
        """ Request for OIDC token for FTS transfer (adminOFF_useraccREQ_NOSUBtoken_HasPreexistingFinalToken)
           Setting initial conditions:
              - requesting Rucio Admin token
              - for a user account name
              - user HAS NO valid subject token
              - final token for FTS transfer with required scope and audience does exist already

            Runs the Test:

                        - see actions below

            End:

            - checking that the final result is None as the user has no valid OIDC token in the DB to start with !
        """
        # ---------------------------
        # setting conditions of the test
        req_scope = 'transfer_scope_' + rndstr() + ' some_other_scope' + rndstr()
        req_audience = 'transfer_audience_' + rndstr() + ' some_other_audience' + rndstr()
        req_account = self.account
        final_token_account = self.account
        final_token_issuer_1 = 'https://test_issuer/'
        final_token_issuer_2 = 'https://test_other_issuer/'
        req_admin = False
        # -----------------------------
        # creating pre-existing token that is supposed to be picked up as final
        preexisting_access_token_strpart_1 = rndstr()
        preexisting_access_token_strpart_2 = rndstr()
        request_args = {'scope': req_scope,
                        'audience': req_audience,
                        'client_id': 'knownsub',
                        'issuer': final_token_issuer_1,
                        'account': final_token_account,
                        'token': preexisting_access_token_strpart_1}
        expected_preexisting_access_token_object_1 = create_preexisting_exchange_token(request_args, session=self.db_session)
        request_args['issuer'] = final_token_issuer_2
        request_args['client_id'] = 'knownsub'
        request_args['token'] = preexisting_access_token_strpart_2
        expected_preexisting_access_token_object_2 = create_preexisting_exchange_token(request_args, session=self.db_session)
        expected_preexisting_access_token_1 = expected_preexisting_access_token_object_1.token
        expected_preexisting_access_token_2 = expected_preexisting_access_token_object_2.token
        db_token = get_token_row(expected_preexisting_access_token_1, account=final_token_account, session=self.db_session)
        assert db_token
        db_token = get_token_row(expected_preexisting_access_token_2, account=final_token_account, session=self.db_session)
        assert db_token
        # mocking additional objects
        MockAdminOIDCClients = {'https://test_other_issuer/': MockADMINClientOtherISSOIDC(client_id=self.adminClientSUB_otherISS),
                                'https://test_issuer/': MockADMINClientISSOIDC(client_id=self.adminClientSUB)}
        admin_clients.__getitem__.side_effect = MockAdminOIDCClients.__getitem__
        admin_clients.__iter__.side_effect = MockAdminOIDCClients.__iter__
        admin_clients.__contains__.side_effect = MockAdminOIDCClients.__contains__
        admin_clients.keys.side_effect = MockAdminOIDCClients.keys
        validate_jwt_dict.side_effect = validate_jwt
        mock_oidc_client.side_effect = get_mock_oidc_client
        # ---------------------------
        # ASKING FOR THE TOKEN
        new_token_dict = get_token_for_account_operation(req_account, req_audience=req_audience, req_scope=req_scope, admin=req_admin, session=self.db_session)
        # ---------------------------
        # Check if NO token has been received
        assert not new_token_dict
