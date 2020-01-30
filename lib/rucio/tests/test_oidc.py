# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Jaroslav Guenther, <jaroslav.guenther@cern.ch>, 2019

from __future__ import print_function

import traceback

from mock import MagicMock, patch
from nose.tools import assert_true, assert_false
from oic import rndstr
from rucio.api.account import add_account
from rucio.core.identity import add_account_identity
from rucio.common.exception import Duplicate
from rucio.common.types import InternalAccount
from rucio.db.sqla.constants import IdentityType
from rucio.core.oidc import get_auth_oidc, get_token_oidc
from rucio.core.authentication import redirect_auth_oidc
from rucio.common.exception import (CannotAuthenticate, DatabaseException)
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session

try:
    # Python 2
    from urlparse import urlparse, parse_qs
except ImportError:
    # Python 3
    from urllib.parse import urlparse, parse_qs

NEW_TOKEN_DICT = {'access_token': 'eyJ3bG...',
                  'expires_in': 3599,
                  'id_token': {'sub': 'abcdefg23', 'iss': 'https://test_auth_url_string/', 'nonce': 'mynonce'},
                  'scope': 'openid profile',
                  'token_type': 'Bearer',
                  'audience': 'rucio'}


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


def get_mock_oidc_client(**kwargs):
    # issuer_id = kwargs.get('issuer_id', None)
    # redirect_to = kwargs.get('redirect_to', None)
    state = kwargs.get('state', None)
    nonce = kwargs.get('nonce', None)
    # scope = kwargs.get('scope', None)
    # audience = kwargs.get('audience', None)
    # first_init = kwargs.get('first_init', None)

    return {'client': MockClientOIDC(),
            'state': state,
            'nonce': nonce,
            'auth_url': 'https://test_auth_url_string?state=' + state + '&nonce=' + nonce,
            'redirect': 'https://test_redirect_string'}


def get_oauth_session_row(accountstring, state=None):
    session = get_session()
    if state:
        result = session.query(models.OAuthRequest).filter_by(account=InternalAccount(accountstring), state=state).all()  # pylint: disable=no-member
    else:
        result = session.query(models.OAuthRequest).filter_by(account=InternalAccount(accountstring)).all()  # pylint: disable=no-member
    return result


def get_token_row(access_token, accountstring=None):
    session = get_session()
    if accountstring:
        result = session.query(models.Token).filter_by(account=InternalAccount(accountstring), token=access_token).all()  # pylint: disable=no-member
    else:
        result = session.query(models.Token).filter_by(token=access_token).all()  # pylint: disable=no-member
    return result


class TestAuthCoreAPIoidc():

    """ OIDC Core API Testing: Testing creation of authorization URL for Rucio Client,
        token request, token exchange, admin token request, finding token for an account.
        TO-DO tests for: exchange_token_oidc, get_token_for_account_operation, get_admin_token_oidc

        setUp function (below) runs first (nose does this automatically)

    """
    # pylint: disable=unused-argument
    def setUp(self):

        self.accountstring = 'test_' + rndstr()
        self.accountstring = self.accountstring.lower()
        try:
            add_account(self.accountstring, 'USER', 'rucio@email.com', 'root')
        except Duplicate:
            pass

        try:
            add_account_identity('SUB=knownsub, ISS=https://test_issuer/', IdentityType.OIDC, InternalAccount(self.accountstring), 'rucio_test@test.com')
        except DatabaseException:
            pass

    def get_auth_init_and_mock_response(self, code_response, account=None, polling=False, auto=True):
        """
        OIDC creates entry in oauth_requests table

        returns: auth_query_string (state=xxx&code=yyy
                 as would be returned from the IdP
                 after a successful authentication)

        """
        if not account:
            account = self.accountstring
        try:

            kwargs = {'auth_scope': 'openid profile',
                      'audience': 'rucio',
                      'issuer': 'dummy_admin_iss_nickname',
                      'auto': auto,
                      'polling': polling,
                      'refresh_lifetime': 96,
                      'ip': None,
                      'webhome': 'https://rucio-test.cern.ch/ui'}
            auth_url = get_auth_oidc(InternalAccount(account), **kwargs)
            # get the state from the auth_url and add an arbitrary code value to the query string
            # to mimick a return of IdP with authz_code
            urlparsed = urlparse(auth_url)
            urlparams = parse_qs(urlparsed.query)
            if ('_polling' in auth_url) or (not polling and not auto):
                auth_url = redirect_auth_oidc(urlparsed.query)

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
            auth_url = get_auth_oidc(InternalAccount(self.accountstring), **kwargs)
            assert_true('https://test_redirect_string/auth/oidc_redirect?' in auth_url and '_polling' not in auth_url)

            # testing classical CLI login init, expecting user to be redirected
            # via Rucio Auth server to the IdP issuer for login and Rucio Client
            # to be polling the Rucio Auth server for token until done so
            kwargs['polling'] = True
            auth_url = get_auth_oidc(InternalAccount(self.accountstring), **kwargs)
            assert_true('https://test_redirect_string/auth/oidc_redirect?' in auth_url and '_polling' in auth_url)

            # testing classical CLI login init, with the Rucio Client being
            # trusted with IdP user credentials (auto = True). Rucio Client
            # gets directly the auth_url pointing it to the IdP
            kwargs['polling'] = False
            kwargs['auto'] = True
            auth_url = get_auth_oidc(InternalAccount(self.accountstring), **kwargs)
            assert_true('https://test_auth_url_string' in auth_url)

            # testing webui login URL (auto = True, polling = False)
            kwargs['webhome'] = 'https://back_to_rucio_ui_page'
            auth_url = get_auth_oidc(InternalAccount('webui'), **kwargs)
            assert_true('https://test_auth_url_string' in auth_url)

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
            get_token_oidc(auth_query_string)
        except CannotAuthenticate:
            assert_true("could not keep track of responses from outstanding requests" in traceback.format_exc())

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
            auth_init_response = self.get_auth_init_and_mock_response(code_response='wrongcode')
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.accountstring, state=auth_init_response['state'])
            assert_false(not oauth_session_row)
            get_token_oidc(auth_init_response['auth_query_string'])
        except CannotAuthenticate:
            assert_true("Unknown AuthZ code provided" in traceback.format_exc())

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
            auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr())
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.accountstring, state=auth_init_response['state'])
            assert_false(not oauth_session_row)

            NEW_TOKEN_DICT['id_token']['nonce'] = 'wrongnonce'
            get_token_oidc(auth_init_response['auth_query_string'])
        except CannotAuthenticate:
            assert_true("This points to possible replay attack !" in traceback.format_exc())

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
            auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr())
            # check if DB entry exists
            oauth_session_row = get_oauth_session_row(self.accountstring, state=auth_init_response['state'])
            assert_false(not oauth_session_row)

            NEW_TOKEN_DICT['id_token'] = {'sub': 'unknownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
            get_token_oidc(auth_init_response['auth_query_string'])
        except CannotAuthenticate:
            assert_true("OIDC identity 'SUB=unknownsub, ISS=https://test_issuer/' of the '"
                        + self.accountstring + "' account is unknown to Rucio." in traceback.format_exc())  # NOQA: W503

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

        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), account='webui')
        # check if DB entry exists
        oauth_session_row = get_oauth_session_row('webui', state=auth_init_response['state'])
        assert_false(not oauth_session_row)

        NEW_TOKEN_DICT['id_token'] = {'sub': 'unknownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'])
        assert_true(token_dict['webhome'] is None)
        assert_true(token_dict['token'] is None)

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
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr())
        oauth_session_row = get_oauth_session_row(self.accountstring, state=auth_init_response['state'])
        assert_false(not oauth_session_row)
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'])
        assert_false(not token_dict)
        db_token = get_token_row(access_token, accountstring=self.accountstring)
        assert_false(not db_token)

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
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), account='webui')
        oauth_session_row = get_oauth_session_row('webui', state=auth_init_response['state'])
        assert_false(not oauth_session_row)
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'])
        assert_false(not token_dict)
        assert_true(token_dict['webhome'] is not None)
        assert_true(token_dict['token'].token == access_token)
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token)
        assert_false(not db_token)

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
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), polling=True, auto=False)
        oauth_session_row = get_oauth_session_row(self.accountstring, state=auth_init_response['state'])
        assert_false(not oauth_session_row)
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'])
        assert_false(not token_dict)
        assert_true(token_dict['polling'] is True)
        assert_true('token' not in token_dict)
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token)
        assert_false(not db_token)

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
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr(), polling=False, auto=False)
        oauth_session_row = get_oauth_session_row(self.accountstring, state=auth_init_response['state'])
        assert_false(not oauth_session_row)
        # mocking the token response
        access_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'])
        assert_false(not token_dict)
        assert_true('fetchcode' in token_dict)
        assert_true('token' not in token_dict)
        # not checking the account specifically as it may be that the
        # identity was registered for other accounts in previous tests
        db_token = get_token_row(access_token)
        assert_false(not db_token)
        token = redirect_auth_oidc(token_dict['fetchcode'], fetchtoken=True)
        assert_true(token == access_token)

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
        auth_init_response = self.get_auth_init_and_mock_response(code_response=rndstr())
        oauth_session_row = get_oauth_session_row(self.accountstring, state=auth_init_response['state'])
        assert_false(not oauth_session_row)
        # mocking the token response
        access_token = rndstr()
        refresh_token = rndstr()
        NEW_TOKEN_DICT['access_token'] = access_token
        NEW_TOKEN_DICT['refresh_token'] = refresh_token
        NEW_TOKEN_DICT['id_token'] = {'sub': 'knownsub', 'iss': 'https://test_issuer/', 'nonce': auth_init_response['nonce']}
        token_dict = get_token_oidc(auth_init_response['auth_query_string'])
        assert_false(not token_dict)
        db_token = get_token_row(access_token, accountstring=self.accountstring)
        assert_false(not db_token)
        for token in db_token:
            assert_true(token.token == access_token)
            assert_true(token.refresh_token == refresh_token)
