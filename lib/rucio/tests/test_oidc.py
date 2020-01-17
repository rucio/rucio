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
from nose.tools import assert_true
from oic import rndstr
from rucio.api.account import add_account, del_account
from rucio.common.exception import Duplicate
from rucio.common.types import InternalAccount
from rucio.core.oidc import get_auth_oidc


NEW_TOKEN_DICT = {'access_token': '',
                  'expires_in': 3599,
                  'id_token': '',
                  'refresh_token': '',
                  'scope': 'openid profile',
                  'token_type': 'Bearer',
                  'audience': 'rucio'}


class MockClientOIDC(MagicMock):

    @classmethod
    def do_access_token_refresh(cls, state=None):
        NEW_TOKEN_DICT['access_token'] = rndstr()
        NEW_TOKEN_DICT['refresh_token'] = state
        return NEW_TOKEN_DICT

    @classmethod
    def construct_AuthorizationRequest(cls, request_args=None):
        return None

    @classmethod
    def parse_response(cls, AuthorizationResponse, info=None, sformat="urlencoded"):
        return None


def side_effect(**kwargs):
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
            'auth_url': 'https://test_auth_url_string',
            'redirect': 'https://test_redirect_string'}


class TestAuthCoreAPIoidc():

    """ OIDC Core API Testing: Testing creatino of authorization URL for Rucio Client,
        token request, token exchange, admin token request, finding account token.

        setUp function (below) runs first (nose does this automatically)

    """

    def setUp(self):

        self.accountstring = 'test_' + rndstr()
        self.accountstring = self.accountstring.lower()
        try:
            add_account(self.accountstring, 'USER', 'rucio@email.com', 'root')
        except Duplicate:
            pass

    @patch('rucio.core.oidc.get_init_oidc_client')
    @patch('rucio.core.oidc.get_rucio_oidc_clients')
    def test_get_auth_oidc_url(self, mock_clients, mock_oidc_client):

        """ OIDC Auth URL generation

            Runs the Test:

            - calling the respective function

            End:

            - checking the URL to be as expected
        """

        mock_oidc_client.side_effect = side_effect

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
            assert_true(auth_url == 'https://test_auth_url_string')

            # testing webui login URL (auto = True, polling = False)
            kwargs['webhome'] = 'https://back_to_rucio_ui_page'
            auth_url = get_auth_oidc(InternalAccount('webui'), **kwargs)
            assert_true(auth_url == 'https://test_auth_url_string')

        except:
            print(traceback.format_exc())

        del_account(self.accountstring, 'root')
