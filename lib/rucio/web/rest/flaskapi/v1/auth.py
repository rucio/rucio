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

import base64
import json
import logging
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from flask import Flask, Blueprint, request, Response, redirect, render_template
from werkzeug.datastructures import Headers

from rucio.api.authentication import get_auth_token_user_pass, get_auth_token_gss, get_auth_token_x509, \
    get_auth_token_ssh, get_ssh_challenge_token, validate_auth_token, get_auth_oidc, redirect_auth_oidc, \
    get_token_oidc, refresh_cli_auth_token, get_auth_token_saml
from rucio.common.config import config_get
from rucio.common.exception import AccessDenied, IdentityError, IdentityNotFound, CannotAuthenticate, CannotAuthorize
from rucio.common.extra import import_extras
from rucio.common.utils import date_to_str
from rucio.core.authentication import strip_x509_proxy_attributes
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, error_headers, \
    extract_vo, generate_http_error_flask, ErrorHandlingMethodView, get_account_from_verified_identity

if TYPE_CHECKING:
    from typing import Optional, Union
    from rucio.web.rest.flaskapi.v1.common import HeadersType

EXTRA_MODULES = import_extras(['onelogin'])

if EXTRA_MODULES['onelogin']:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # pylint: disable=import-error
    from rucio.web.ui.flask.common.utils import prepare_saml_request


class UserPass(ErrorHandlingMethodView):
    """
    Authenticate a Rucio account temporarily via username and password.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token, X-Rucio-Auth-Token-Expires, X-Rucio-Auth-Account, X-Rucio-Auth-Accounts'
        return headers

    def options(self) -> tuple[str, int, "Optional[HeadersType]"]:
        """
        ---
        summary: UserPass Allow cross-site scripting
        description: UserPass Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
          404:
            description: Not found
        """

        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self) -> 'Union[Response, tuple[str, int, "Optional[HeadersType]"]]':
        """
        ---
        summary: UserPass
        description: Authenticate a Rucio account temporarily via username and password.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Account
          in: header
          description: Account identifier as a string.
          schema:
            type: string
          required: true
        - name: X-Rucio-Username
          in: header
          description: Username as a string.
          schema:
            type: string
          required: true
        - name: X-Rucio-Password
          in: header
          description: password as a text-plain string.
          schema:
            type: string
          required: true
        - name: X-Rucio-AppID
          in: header
          description: Application identifier as a string.
          schema:
            type: string
        - name: X-Forwarded-For
          in: header
          description: The forward ip address.
          schema:
            type: string
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
              Access-Control-Allow-Credentials:
                schema:
                  type: string
              Access-Control-Expose-Headers:
                schema:
                  type: string
              X-Rucio-Auth-Token:
                schema:
                  type: string
              X-Rucio-Auth-Token-Expires:
                schema:
                  type: string
              X-Rucio-Auth-Account:
                schema:
                  type: string
                description: The rucio account used for authentication
          206:
            description: Partial content containing X-Rucio-Auth-Accounts header
            headers:
              X-Rucio-Auth-Accounts:
                schema:
                  type: string
                description: The rucio accounts corresponding to the provided identity as a csv string

          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        username = request.headers.get('X-Rucio-Username', default=None)
        password = request.headers.get('X-Rucio-Password', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)
        if not username or not password:
            return generate_http_error_flask(401, CannotAuthenticate.__name__, 'Cannot authenticate without passing all required arguments', headers=headers)

        accounts: list[str] = []
        if not account:
            try:
                accounts = get_account_from_verified_identity(identity_key=username, id_type='USERPASS', password=password)
            except IdentityNotFound:
                return generate_http_error_flask(401, IdentityNotFound.__name__, 'Cannot authenticate. Username/Password pair does not exist.', headers=headers)
            except IdentityError:
                return generate_http_error_flask(401, IdentityError.__name__, 'Cannot authenticate. The identity does not exist.', headers=headers)
        else:
            accounts = [account]

        if len(accounts) > 1:
            account_names: list[str] = []
            for account in accounts:
                if isinstance(account, str):
                    account_names.append(account)
                else:
                    account_names.append(account.external)
            headers['X-Rucio-Auth-Accounts'] = ','.join(accounts)
            return json.dumps(account_names), 206, headers

        account = accounts[0]
        account_name = account if isinstance(account, str) else account.external
        try:
            result = get_auth_token_user_pass(account_name, username, password, appid, ip, vo=vo)
            if not result:
                return generate_http_error_flask(401, CannotAuthenticate.__name__, f'Cannot authenticate to account {account} with given credentials', headers=headers)
            headers['X-Rucio-Auth-Account'] = account_name
            headers['X-Rucio-Auth-Token'] = result['token']
            headers['X-Rucio-Auth-Token-Expires'] = date_to_str(result['expires_at'])
            return '', 200, headers
        except AccessDenied:
            return generate_http_error_flask(401, CannotAuthenticate.__name__, f'Cannot authenticate to account {account} with given credentials', headers=headers)


class OIDC(ErrorHandlingMethodView):
    """
    Requests a user specific Authorization URL (assigning a user session state,
    nonce, Rucio OIDC Client ID with the correct issuers authentication endpoint).
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        return headers

    def options(self):
        """
        ---
        summary: OIDC Allow cross-site scripting
        description: OIDC Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
          404:
            description: Not found
        """

        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: OIDC
        description: Authenticate a Rucio account via OIDC.
        tags:
          - Auth
        parameters:
        - name: HTTP_X_RUCIO_ACCOUNT
          in: header
          description: Account identifier as a string.
          schema:
            type: string
        - name: HTTP_X_RUCIO_CLIENT_AUTHORIZE_SCOPE
          in: header
          schema:
            type: string
        - name: HTTP_X_RUCIO_CLIENT_AUTHORIZE_AUDIENCE
          in: header
          schema:
            type: string
        - name: HTTP_X_RUCIO_CLIENT_AUTHORIZE_AUTO
          in: header
          schema:
            type: string
        - name: HTTP_X_RUCIO_CLIENT_AUTHORIZE_ISSUER
          in: header
          schema:
            type: string
        - name: HTTP_X_RUCIO_CLIENT_AUTHORIZE_POLLING
          in: header
          schema:
            type: string
        - name: HTTP_X_RUCIO_CLIENT_AUTHORIZE_REFRESH_LIFETIME
          in: header
          schema:
            type: string
        - name: X-Forwarded-For
          in: header
          schema:
            type: string
        responses:
          200:
            description: OK
            headers:
              X-Rucio-OIDC-Auth-URL:
                description: User & Rucio OIDC Client specific Authorization URL
                schema:
                  type: string
          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()

        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        vo = extract_vo(request.headers)
        account = request.environ.get('HTTP_X_RUCIO_ACCOUNT', 'webui')
        auth_scope = request.environ.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_SCOPE', "")
        audience = request.environ.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_AUDIENCE', "")
        auto = request.environ.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_AUTO', False)
        issuer = request.environ.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_ISSUER', None)
        polling = request.environ.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_POLLING', False)
        refresh_lifetime = request.environ.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_REFRESH_LIFETIME', None)
        auto = (auto == 'True' or auto == 'true')
        polling = (polling == 'True' or polling == 'true')
        if refresh_lifetime == 'None':
            refresh_lifetime = None
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)
        try:
            kwargs = {'auth_scope': auth_scope,
                      'audience': audience,
                      'issuer': issuer,
                      'auto': auto,
                      'polling': polling,
                      'refresh_lifetime': refresh_lifetime,
                      'ip': ip}
            result = get_auth_oidc(account, vo=vo, **kwargs)
        except AccessDenied:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot get authentication URL from Rucio Authentication Server for account {account}',
                headers=headers
            )

        if not result:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot get authentication URL from Rucio Authentication Server for account {account}',
                headers=headers
            )

        headers.set('X-Rucio-OIDC-Auth-URL', result)
        return '', 200, headers


class RedirectOIDC(ErrorHandlingMethodView):
    """
    Authenticate a Rucio account via
    an Identity Provider (XDC IAM as of June 2019).
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        return headers

    def options(self):
        """
        ---
        summary: RedirectOIDC Allow cross-site scripting
        description: RedirectOIDC Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream', 'text/html'])
    def get(self):
        """
        ---
        summary: RedirectOIDC
        description: Authenticate a Rucio account via RedirectOIDC.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Client-Fetch-Token
          in: header
          schema:
            type: string
        responses:
          200:
            description: OK
            headers:
              X-Rucio-Auth-Token:
                description: The authentication token
                schema:
                  type: string
              Content-Type:
                schema:
                  type: string
                  enum: ['application/octet-stream']
          303:
            description: Redirect
          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()

        # interaction with web browser - display response in html format
        headers.set('Content-Type', 'text/html')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        try:
            fetchtoken = (request.headers.get('X-Rucio-Client-Fetch-Token', default=None) == 'True')
            query_string = request.query_string.decode(encoding='utf-8')
            result = redirect_auth_oidc(query_string, fetchtoken)
        except AccessDenied:
            headers.extend(error_headers(CannotAuthenticate.__name__, 'Cannot authorize your access, please check your access credentials'))
            return render_template('auth_crash.html', crashtype='contact'), 401, headers
        except Exception as error:
            logging.exception("Internal Error")
            headers.extend(error_headers(error.__class__.__name__, str(error.args[0])))
            return render_template('auth_crash.html', crashtype='internal_error'), 500, headers

        if not result:
            headers.extend(error_headers(CannotAuthenticate.__name__, 'Cannot finalize your token request, no authorization content returned from the auth server'))
            return render_template('auth_crash.html', crashtype='no_result'), 401, headers

        if fetchtoken:
            # this is only a case of returning the final token to the Rucio Client polling
            # or requesting token after copy-pasting the Rucio code from the web page page
            headers.set('Content-Type', 'application/octet-stream')
            headers.set('X-Rucio-Auth-Token', result)
            return '', 200, headers
        else:
            response = redirect(result, code=303)
            response.headers.extend(headers)
            return response


class CodeOIDC(ErrorHandlingMethodView):
    """
    IdP redirects to this endpoint with the AuthZ code
    Rucio Auth server will request new token. This endpoint should be reached
    only if the request/ IdP login has been made through web browser. Then the response
    content will be in html (including the potential errors displayed).
    The token will be saved in the Rucio DB, but only Rucio code will
    be returned on the web page, or, in case of polling is True, successful
    operation is confirmed waiting for the Rucio client to get the token automatically.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        return headers

    def options(self):
        """
        ---
        summary: CodeOIDC Allow cross-site scripting
        description: CodeOIDC Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream', 'text/html'])
    def get(self):
        """
        ---
        summary: CodeOIDC
        description: Authenticate a Rucio account via CodeOIDC.
        tags:
          - Auth
        parameters:
        - name: X-Forwarded-For
          in: header
          schema:
            type: string
        responses:
          200:
            description: OK
          400:
            description: Invalid request
        """
        headers = self.get_headers()

        headers.set('Content-Type', 'text/html')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        query_string = request.query_string.decode(encoding='utf-8')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        try:
            result = get_token_oidc(query_string, ip)
        except AccessDenied:
            headers.extend(error_headers(CannotAuthenticate.__name__, 'Cannot authorize your access, please check your access credentials'))
            return render_template('auth_crash.html', crashtype='contact'), 401, headers
        except Exception as error:
            logging.exception("Internal Error")
            headers.extend(error_headers(error.__class__.__name__, str(error.args[0])))
            return render_template('auth_crash.html', crashtype='internal_error'), 500, headers

        if not result:
            headers.extend(error_headers(CannotAuthenticate.__name__, 'Cannot finalize your token request, no authorization content returned from the auth server'))
            return render_template('auth_crash.html', crashtype='no_result'), 401, headers

        if 'fetchcode' in result:
            return render_template('auth_granted.html', authcode=result['fetchcode']), 200, headers
        elif 'polling' in result and result['polling'] is True:
            return render_template('auth_granted.html', authcode='allok'), 200, headers
        else:
            headers.extend(error_headers('InvalidRequest', 'Cannot recognize and process your request'))
            return render_template('auth_crash.html', crashtype='bad_request'), 400, headers


class TokenOIDC(ErrorHandlingMethodView):
    """
    Authenticate a Rucio account temporarily via ID,
    access (eventually save new refresh token)
    received from an Identity Provider.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        return headers

    def options(self):
        """
        ---
        summary: TokenOIDC Allow cross-site scripting
        description: TokenOIDC Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: TokenOIDC
        description: Authenticate a Rucio account via TokenOIDC.
        tags:
          - Auth
        parameters:
        - name: X-Forwarded-For
          in: header
          schema:
            type: string
        responses:
          200:
            description: OK
            headers:
              X-Rucio-Auth-Token:
                description: The authentication token
                schema:
                  type: string
              X-Rucio-Auth-Token-Expires:
                description: The time when the token expires
                schema:
                  type: string
          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()

        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        query_string = request.query_string.decode(encoding='utf-8')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        try:
            result = get_token_oidc(query_string, ip)
        except AccessDenied:
            return generate_http_error_flask(401, CannotAuthorize.__name__, 'Cannot authorize token request.', headers=headers)

        if not result:
            return generate_http_error_flask(401, CannotAuthorize.__name__, 'Cannot authorize token request.', headers=headers)
        if 'token' in result and 'webhome' not in result:
            headers.set('X-Rucio-Auth-Token', result['token']['token'])
            headers.set('X-Rucio-Auth-Token-Expires', date_to_str(result['token']['expires_at']))
            return '', 200, headers
        elif 'webhome' in result:
            webhome = result['webhome']
            if webhome is None:
                headers.extend(error_headers(CannotAuthenticate.__name__, 'Cannot find your OIDC identity linked to any Rucio account'))
                headers.set('Content-Type', 'text/html')
                return render_template('auth_crash.html', crashtype='unknown_identity'), 401, headers
            # domain setting is necessary so that the token gets distributed also to the webui server
            domain = '.'.join(urlparse(webhome).netloc.split('.')[1:])
            response = redirect(webhome, code=303)
            response.headers.extend(headers)
            response.set_cookie('x-rucio-auth-token', value=result['token']['token'], domain=domain, path='/')
            response.set_cookie('rucio-auth-token-created-at', value=str(time.time()), domain=domain, path='/')
            # response.set_cookie('x-rucio-auth-token', value=result['token']['token'])
            # response.set_cookie('rucio-auth-token-created-at', value=str(time.time()))
            return response
        else:
            return '', 400, headers


class RefreshOIDC(ErrorHandlingMethodView):
    """
    For a presented and access token which has equivalent in Rucio DB
    (and also has refrech token in the Rucio DB) the class will attempt
    token refresh and return a user a new refreshed token. If the presented token
    is a result of a previous refresh happening in the last 10 min, the same token will be returned.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        headers.set('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        return headers

    def options(self):
        """
        ---
        summary: RefreshOIDC Allow cross-site scripting
        description: RefreshOIDC Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: RefreshOIDC
        description: Authenticate a Rucio account via RefreshOIDC.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Account
          in: header
          schema:
            type: string
          required: true
        - name: X-Rucio-Auth-Token
          in: header
          schema:
            type: string
          required: true
        responses:
          200:
            description: OK
            headers:
              X-Rucio-Auth-Token:
                description: The authentication token
                schema:
                  type: string
              X-Rucio-Auth-Token-Expires:
                description: The time when the token expires
                schema:
                  type: string
          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()

        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        token = request.headers.get('X-Rucio-Auth-Token', default=None)
        if token is None or account is None:
            return generate_http_error_flask(401, CannotAuthorize.__name__, 'Cannot authorize token request.', headers=headers)

        try:
            result = refresh_cli_auth_token(token, account, vo=vo)
        except AccessDenied:
            return generate_http_error_flask(401, CannotAuthorize.__name__, 'Cannot authorize token request.', headers=headers)

        if result is not None and len(result) > 1:
            headers.set('X-Rucio-Auth-Token', str(result[0]))
            headers.set('X-Rucio-Auth-Token-Expires', str(result[1]))
        else:
            headers.set('X-Rucio-Auth-Token', '')
            headers.set('X-Rucio-Auth-Token-Expires', '')
        return '', 200, headers


class GSS(ErrorHandlingMethodView):
    """
    Authenticate a Rucio account temporarily via a GSS token.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return headers

    def options(self):
        """
        ---
        summary: GSS Allow cross-site scripting
        description: GSS Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: GSS
        description: Authenticate a Rucio account via GSS.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Account
          in: header
          schema:
            type: string
          required: true
        - name: REMOTE_USER
          in: header
          schema:
            type: string
          required: true
        - name: X-Rucio-AppID
          in: header
          schema:
            type: string
        - name: X-Forwarded-For
          in: header
          schema:
            type: string
        responses:
          200:
            description: OK
            headers:
              X-Rucio-Auth-Token:
                description: The authentication token
                schema:
                  type: string
              X-Rucio-Auth-Token-Expires:
                description: The time when the token expires
                schema:
                  type: string
          401:
            description: Cannot authenticate
        """

        headers = self.get_headers()

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        gsscred = request.environ.get('REMOTE_USER')
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        try:
            result = get_auth_token_gss(account, gsscred, appid, ip, vo=vo)
        except AccessDenied:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot authenticate to account {account} with given credentials',
                headers=headers
            )

        if result is None:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot authenticate to account {account} with given credentials',
                headers=headers
            )

        headers['X-Rucio-Auth-Token'] = result['token']
        headers['X-Rucio-Auth-Token-Expires'] = date_to_str(result['expires_at'])
        return '', 200, headers


class x509(ErrorHandlingMethodView):
    """
    Authenticate a Rucio account temporarily via an x509 certificate.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token, X-Rucio-Auth-Token-Expires, X-Rucio-Auth-Account, X-Rucio-Auth-Accounts'
        return headers

    def options(self) -> tuple[str, int, "Optional[HeadersType]"]:
        """
        ---
        summary: x509 Allow cross-site scripting
        description: x509 Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self) -> 'Union[Response, tuple[str, int, "Optional[HeadersType]"]]':
        """
        ---
        summary: x509
        description: Authenticate a Rucio account via x509.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Account
          in: header
          schema:
            type: string
          required: true
        - name: X-Rucio-AppID
          in: header
          schema:
            type: string
        - name: X-Forwarded-For
          in: header
          schema:
            type: string
        - name: X-Rucio-Allow-Return-Multiple-Accounts
          in: header
          schema:
            type: boolean
          description: If set to true, a HTTP 206 response will be returned if the identity is associated with multiple accounts.
        responses:
          200:
            description: OK
            headers:
              X-Rucio-Auth-Token:
                description: The authentication token
                schema:
                  type: string
              X-Rucio-Auth-Token-Expires:
                description: The time when the token expires
                schema:
                  type: string
              X-Rucio-Auth-Account:
                description: The rucio account corresponding to the provided identity
                schema:
                  type: string
          206:
            description: Partial content containing X-Rucio-Auth-Accounts header
            headers:
              X-Rucio-Auth-Accounts:
                schema:
                  type: string
                description: The rucio accounts corresponding to the provided identity as a csv string
          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()
        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        dn = request.environ.get('SSL_CLIENT_S_DN')
        if not dn:
            return generate_http_error_flask(401, CannotAuthenticate.__name__, 'Cannot get DN', headers=headers)
        dn = strip_x509_proxy_attributes(dn)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)
        return_multiple_accounts = request.headers.get('X-Rucio-Allow-Return-Multiple-Accounts', default=None)

        accounts: list[str] = []
        if not account:
            try:
                accounts = get_account_from_verified_identity(identity_key=dn, id_type='X509')
            except IdentityError as e:
                return generate_http_error_flask(401, IdentityError.__name__, str(e), headers=headers)
        else:
            accounts = [account]

        if len(accounts) > 1:
            if return_multiple_accounts is None or return_multiple_accounts.lower() != 'true':
                return generate_http_error_flask(401, CannotAuthenticate.__name__, 'Multiple accounts associated with the provided identity', headers=headers)
            account_names: list[str] = []
            for account in accounts:
                if isinstance(account, str):
                    account_names.append(account)
                else:
                    account_names.append(account.external)
            headers['X-Rucio-Auth-Accounts'] = ','.join(accounts)
            return json.dumps(account_names), 206, headers
        account = accounts[0]
        account_name = account if isinstance(account, str) else account.external
        result = None
        try:
            result = get_auth_token_x509(account_name, dn, appid, ip, vo=vo)
        except AccessDenied:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot authenticate to account {account_name} with given credentials',
                headers=headers
            )
        except IdentityError as e:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=str(e),
                headers=headers
            )

        if not result:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot authenticate to account {account} with given credentials',
                headers=headers
            )
        headers['X-Rucio-Auth-Token'] = result['token']
        headers['X-Rucio-Auth-Token-Expires'] = date_to_str(result['expires_at'])
        headers['X-Rucio-Auth-Account'] = account
        return '', 200, headers


class SSH(ErrorHandlingMethodView):
    """
    Authenticate a Rucio account temporarily via SSH key exchange.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return headers

    def options(self):
        """
        ---
        summary: SSH Allow cross-site scripting
        description: SSH Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: SSH
        description: Authenticate a Rucio account via SSH.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Account
          in: header
          schema:
            type: string
          required: true
        - name: X-Rucio-SSH-Signature
          in: header
          schema:
            type: string
          required: true
        - name: X-Rucio-AppID
          in: header
          schema:
            type: string
        - name: X-Forwarded-For
          in: header
          schema:
            type: string
        responses:
          200:
            description: OK
            headers:
              X-Rucio-Auth-Token:
                description: The authentication token
                schema:
                  type: string
              X-Rucio-Auth-Token-Expires:
                description: The time when the token expires
                schema:
                  type: string
          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        signature = request.headers.get('X-Rucio-SSH-Signature', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        # decode the signature which must come in base64 encoded
        try:
            signature += '=' * ((4 - len(signature) % 4) % 4)  # adding required padding
            signature = base64.b64decode(signature)
        except TypeError:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot authenticate to account {account} with malformed signature',
                headers=headers
            )

        try:
            result = get_auth_token_ssh(account, signature, appid, ip, vo=vo)
        except AccessDenied:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot authenticate to account {account} with given credentials',
                headers=headers
            )

        if not result:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot authenticate to account {account} with given credentials',
                headers=headers
            )

        headers['X-Rucio-Auth-Token'] = result['token']
        headers['X-Rucio-Auth-Token-Expires'] = date_to_str(result['expires_at'])
        return '', 200, headers


class SSHChallengeToken(ErrorHandlingMethodView):
    """
    Request a challenge token for SSH authentication
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return headers

    def options(self):
        """
        ---
        summary: SSHChallengeToken Allow cross-site scripting
        description: SSHChallengeToken Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: SSHChallengeToken
        description: Authenticate a Rucio account via SSHChallengeToken.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Account
          in: header
          schema:
            type: string
          required: true
        - name: X-Rucio-AppID
          in: header
          schema:
            type: string
        - name: X-Forwarded-For
          in: header
          schema:
            type: string
        responses:
          200:
            description: OK
            headers:
              X-Rucio-SSH-Challenge-Token:
                description: The authentication token
                schema:
                  type: string
              X-Rucio-SSH-Challenge-Token-Expires:
                description: The time when the token expires
                schema:
                  type: string
          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        result = get_ssh_challenge_token(account, appid, ip, vo=vo)

        if not result:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg=f'Cannot generate challenge for account {account}',
                headers=headers
            )

        headers['X-Rucio-SSH-Challenge-Token'] = result['token']
        headers['X-Rucio-SSH-Challenge-Token-Expires'] = date_to_str(result['expires_at'])
        return '', 200, headers


class SAML(ErrorHandlingMethodView):
    """
    Authenticate a Rucio account temporarily via CERN SSO.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        headers.set('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        return headers

    def options(self):
        """
        ---
        summary: SAML Allow cross-site scripting
        description: SAML Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: SAML
        description: Authenticate a Rucio account via SAML.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Account
          in: header
          schema:
            type: string
          required: true
        - name: X-Rucio-AppID
          in: header
          schema:
            type: string
        - name: X-Forwarded-For
          in: header
          schema:
            type: string
        responses:
          200:
            description: OK
            headers:
              X-Rucio-Auth-Token:
                description: The authentication token
                schema:
                  type: string
              X-Rucio-Auth-Token-Expires:
                description: The time when the token expires
                schema:
                  type: string
              X-Rucio-SAML-Auth-URL:
                description: The time when the token expires
                schema:
                  type: string
          401:
            description: Cannot authenticate
        """
        headers = self.get_headers()

        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        if not EXTRA_MODULES['onelogin']:
            return "SAML not configured on the server side.", 400, headers

        saml_nameid = request.cookies.get('saml-nameid', default=None)
        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        if saml_nameid:
            try:
                result = get_auth_token_saml(account, saml_nameid, appid, ip, vo=vo)
            except AccessDenied:
                return generate_http_error_flask(
                    status_code=401,
                    exc=CannotAuthenticate.__name__,
                    exc_msg=f'Cannot authenticate to account {account} with given credentials',
                    headers=headers
                )

            if not result:
                return generate_http_error_flask(
                    status_code=401,
                    exc=CannotAuthenticate.__name__,
                    exc_msg=f'Cannot authenticate to account {account} with given credentials',
                    headers=headers
                )

            headers.set('X-Rucio-Auth-Token', result['token'])
            headers.set('X-Rucio-Auth-Token-Expires', date_to_str(result['expires_at']))
            return '', 200, headers

        # Path to the SAML config folder
        SAML_PATH = config_get('saml', 'config_path')

        req = prepare_saml_request(request.environ, dict(request.args.items(multi=False)))
        auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)

        headers.set('X-Rucio-SAML-Auth-URL', auth.login())
        return '', 200, headers

    def post(self):
        """
        ---
        summary: Post a SAML request
        description: Post a SAML request
        tags:
          - Auth
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
        """
        if not EXTRA_MODULES['onelogin']:
            return "SAML not configured on the server side.", 200, [('X-Rucio-Auth-Token', '')]

        SAML_PATH = config_get('saml', 'config_path')
        req = prepare_saml_request(request.environ, dict(request.args.items(multi=False)))
        auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)

        auth.process_response()
        errors = auth.get_errors()
        if not errors:
            if auth.is_authenticated():
                response = Response()
                response.set_cookie('saml-nameid', value=auth.get_nameid(), path='/')
                return response
        return '', 200


class Validate(ErrorHandlingMethodView):
    """
    Validate a Rucio Auth Token.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return headers

    def options(self):
        """
        ---
        summary: Validate Allow cross-site scripting
        description: Validate Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Auth
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
              Access-Control-Allow-Headers:
                schema:
                  type: string
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: Validate
        description: Validate a Rucio auth token.
        tags:
          - Auth
        parameters:
        - name: X-Rucio-Account
          in: header
          schema:
            type: string
          required: true
        responses:
          200:
            description: OK
          401:
            description: Cannot authenticate
        """

        headers = self.get_headers()

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        token = request.headers.get('X-Rucio-Auth-Token', default=None)

        result = validate_auth_token(token)
        if not result:
            return generate_http_error_flask(
                status_code=401,
                exc=CannotAuthenticate.__name__,
                exc_msg='Cannot authenticate with given credentials',
                headers=headers
            )

        return str(result), 200, headers


def blueprint():
    bp = Blueprint('auth', __name__, url_prefix='/auth')

    user_pass_view = UserPass.as_view('user_pass')
    bp.add_url_rule('/userpass', view_func=user_pass_view, methods=['get', 'options'])
    gss_view = GSS.as_view('gss')
    bp.add_url_rule('/gss', view_func=gss_view, methods=['get', 'options'])
    x509_view = x509.as_view('x509')
    bp.add_url_rule('/x509', view_func=x509_view, methods=['get', 'options'])
    bp.add_url_rule('/x509/webui', view_func=x509_view, methods=['get', 'options'])
    bp.add_url_rule('/x509_proxy', view_func=x509_view, methods=['get', 'options'])
    ssh_view = SSH.as_view('ssh')
    bp.add_url_rule('/ssh', view_func=ssh_view, methods=['get', 'options'])
    ssh_challenge_token_view = SSHChallengeToken.as_view('ssh_challenge_token')
    bp.add_url_rule('/ssh_challenge_token', view_func=ssh_challenge_token_view, methods=['get', 'options'])
    saml_view = SAML.as_view('saml')
    bp.add_url_rule('/saml', view_func=saml_view, methods=['get', 'post', 'options'])
    validate_view = Validate.as_view('validate')
    bp.add_url_rule('/validate', view_func=validate_view, methods=['get', 'options'])
    oidc_view = OIDC.as_view('oidc_view')
    bp.add_url_rule('/oidc', view_func=oidc_view, methods=['get', 'options'])
    token_oidc_view = TokenOIDC.as_view('token_oidc_view')
    bp.add_url_rule('/oidc_token', view_func=token_oidc_view, methods=['get', 'options'])
    code_oidc_view = CodeOIDC.as_view('code_oidc_view')
    bp.add_url_rule('/oidc_code', view_func=code_oidc_view, methods=['get', 'options'])
    redirect_oidc_view = RedirectOIDC.as_view('redirect_oidc_view')
    bp.add_url_rule('/oidc_redirect', view_func=redirect_oidc_view, methods=['get', 'options'])
    refresh_oidc_view = RefreshOIDC.as_view('refresh_oidc_view')
    bp.add_url_rule('/oidc_refresh', view_func=refresh_oidc_view, methods=['get', 'options'])

    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
