# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

import base64
import imp
import time
from re import search
from traceback import format_exc

from flask import Flask, Blueprint, request, Response, redirect
from flask.views import MethodView
from werkzeug.datastructures import Headers

from rucio.api.authentication import get_auth_token_user_pass, get_auth_token_gss, get_auth_token_x509, get_auth_token_ssh, get_ssh_challenge_token, validate_auth_token, get_auth_oidc, redirect_auth_oidc, get_token_oidc, refresh_cli_auth_token, \
    get_auth_token_saml
from rucio.common.config import config_get
from rucio.common.exception import AccessDenied, IdentityError, RucioException
from rucio.common.utils import date_to_str, urlparse
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask
from rucio.web.rest.utils import generate_http_error_flask

# Extra modules: Only imported if available
EXTRA_MODULES = {'onelogin': False}

for extra_module in EXTRA_MODULES:
    try:
        imp.find_module(extra_module)
        EXTRA_MODULES[extra_module] = True
    except ImportError:
        EXTRA_MODULES[extra_module] = False

if EXTRA_MODULES['onelogin']:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from web import cookies
    from rucio.web.ui.common.utils import prepare_saml_request


class UserPass(MethodView):
    """
    Authenticate a Rucio account temporarily via username and password.
    """

    def options(self):
        """
        Allow cross-site scripting. Explicit for Authentication.

        :resheader Access-Control-Allow-Origin:
        :resheader Access-Control-Allow-Headers:
        :resheader Access-Control-Allow-Methods:
        :resheader Access-Control-Allow-Credentials:
        :resheader Access-Control-Expose-Headers:
        :status 200: OK
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Authenticate a Rucio account temporarily via username and password.

        .. :quickref: UserPass; Authenticate with username/password

        :reqheader X-Rucio-VO: VO name as a string (Multi-VO Only)
        :reqheader X-Rucio-Account: Account identifier as a string.
        :reqheader X-Rucio-Username: Username as a string.
        :reqheader X-Rucio-Password: password as a text-plain string.
        :reqheader X-Rucio-AppID: Application identifier as a string.
        :resheader Access-Control-Allow-Origin:
        :resheader Access-Control-Allow-Headers:
        :resheader Access-Control-Allow-Methods:
        :resheader Access-Control-Allow-Credentials:
        :resheader Access-Control-Expose-Headers:
        :resheader X-Rucio-Auth-Token: The authentication token
        :status 200: Successfully authenticated
        :status 404: Invalid credentials
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = request.headers.get('X-Rucio-VO', default='def')
        account = request.headers.get('X-Rucio-Account', default=None)
        username = request.headers.get('X-Rucio-Username', default=None)
        password = request.headers.get('X-Rucio-Password', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        if not account or not username or not password:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate without passing all required arguments', headers=headers)

        try:
            result = get_auth_token_user_pass(account, username, password, appid, ip, vo=vo)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)

        headers['X-Rucio-Auth-Token'] = result.token
        headers['X-Rucio-Auth-Token-Expires'] = date_to_str(result.expired_at)
        return '', 200, headers


class OIDC(MethodView):
    """
    Requests a user specific Authorization URL (assigning a user session state,
    nonce, Rucio OIDC Client ID with the correct issuers authentication endpoint).
    """

    def options(self):
        """
        Allow cross-site scripting. Explicit for Authentication.

        :status 200: OK
        """
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """

        .. :quickref: OIDC; Authenticate with OIDC

        :status 200: OK
        :status 401: Unauthorized
        :resheader X-Rucio-OIDC-Auth-URL: User & Rucio OIDC Client specific Authorization URL
        """
        headers = Headers()

        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        vo = request.headers.get('X-Rucio-VO', default='def')
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
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get authentication URL from Rucio Authentication Server for account %(account)s' % locals(), headers=headers)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get authentication URL from Rucio Authentication Server for account %(account)s' % locals(), headers=headers)

        headers.set('X-Rucio-OIDC-Auth-URL', result)
        return '', 200, headers


class RedirectOIDC(MethodView):
    """
    Authenticate a Rucio account via
    an Identity Provider (XDC IAM as of June 2019).
    """

    def options(self):
        """
        Allow cross-site scripting. Explicit for Authentication.

        :status 200: OK
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream', 'text/html'])
    def get(self):
        """
        .. :quickref: OIDC;

        :status 200: OK
        :status 303: Redirect
        :status 401: Unauthorized
        :resheader X-Rucio-Auth-Token: The authentication token
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        # interaction with web browser - display response in html format
        headers.set('Content-Type', 'text/html')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        try:
            fetchtoken = (request.headers.get('X-Rucio-Client-Fetch-Token', default=None) == 'True')
            query_string = request.query_string.decode(encoding='utf-8')
            result = redirect_auth_oidc(query_string, fetchtoken)

            # FIXME: render auth template on error
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get authentication URL from Rucio Authentication Server for account %(account)s' % locals(), headers=headers)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get authentication URL from Rucio Authentication Server for account %(account)s' % locals(), headers=headers)
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


class CodeOIDC(MethodView):
    """
    IdP redirects to this endpoint with the AuthZ code
    Rucio Auth server will request new token. This endpoint should be reached
    only if the request/ IdP login has been made through web browser. Then the response
    content will be in html (including the potential errors displayed).
    The token will be saved in the Rucio DB, but only Rucio code will
    be returned on the web page, or, in case of polling is True, successful
    operation is confirmed waiting for the Rucio client to get the token automatically.
    """

    def options(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream', 'text/html'])
    def get(self):
        """
        .. :quickref: OIDC;

        :status 200: OK
        :status 401: Unauthorized
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        headers.set('Content-Type', 'text/html')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        query_string = request.query_string.decode(encoding='utf-8')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        try:
            result = get_token_oidc(query_string, ip)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get authentication code from Rucio Authentication Server for account %(account)s' % locals(), headers=headers)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get authentication code from Rucio Authentication Server for account %(account)s' % locals(), headers=headers)
        if 'fetchcode' in result:
            msg = 'Please copy-paste the following code to the open terminal session with Rucio Client in order to get your access token: <b>' + result['fetchcode'] + '</b>'
            return msg, 200, headers
        elif 'polling' in result and result['polling'] is True:
            return 'Rucio Client should now be able to fetch your token automatically.', 200, headers
        else:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get authentication code from Rucio Authentication Server for account %(account)s' % locals(), headers=headers)


class TokenOIDC(MethodView):
    """
    Authenticate a Rucio account temporarily via ID,
    access (eventually save new refresh token)
    received from an Identity Provider.
    """

    def options(self):
        """
        Allow cross-site scripting. Explicit for Authentication.

        :status 200: OK
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        .. :quickref: OIDC;

        :status 200: OK
        :status 401: Unauthorized
        :resheader X-Rucio-Auth-Token: The authentication token
        :resheader X-Rucio-Auth-Token-Expires: The time when the token expires
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        query_string = request.query_string.decode(encoding='utf-8')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        try:
            result = get_token_oidc(query_string, ip)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthorize', 'Cannot authorize token request.', headers=headers)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        if not result:
            return generate_http_error_flask(401, 'CannotAuthorize', 'Cannot authorize token request.', headers=headers)
        if 'token' in result and 'webhome' not in result:
            headers.set('X-Rucio-Auth-Token', result['token'].token)
            headers.set('X-Rucio-Auth-Token-Expires', date_to_str(result['token'].expired_at))
            return '', 200, headers
        elif 'webhome' in result:
            webhome = result['webhome']
            if webhome is None:
                return generate_http_error_flask(401, 'CannotAuthorize', 'Unknown identity.', headers=headers)
            # domain setting is necessary so that the token gets distributed also to the webui server
            domain = '.'.join(urlparse.urlparse(webhome).netloc.split('.')[1:])
            response = redirect(webhome, code=303)
            response.headers.extend(headers)
            response.set_cookie('x-rucio-auth-token', value=result['token'].token, domain=domain, path='/')
            response.set_cookie('rucio-auth-token-created-at', value=str(time.time()), domain=domain, path='/')
            return response
        else:
            return '', 400, headers


class RefreshOIDC(MethodView):
    """
    For a presented and access token which has equivalent in Rucio DB
    (and also has refrech token in the Rucio DB) the class will attempt
    token refresh and return a user a new refreshed token. If the presented token
    is a result of a previous refresh happening in the last 10 min, the same token will be returned.
    """

    def options(self):
        """
        Allow cross-site scripting. Explicit for Authentication.

        :status 200: OK
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        headers.set('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        .. :quickref: OIDC;

        :status 200: OK
        :status 401: Unauthorized
        :resheader X-Rucio-Auth-Token: The authentication token
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        headers.set('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')

        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        vo = request.headers.get('X-Rucio-VO', default='def')
        account = request.headers.get('X-Rucio-Account', default=None)
        token = request.headers.get('X-Rucio-Auth-Token', default=None)
        if token is None or account is None:
            return generate_http_error_flask(401, 'CannotAuthorize', 'Cannot authorize token request.', headers=headers)

        try:
            result = refresh_cli_auth_token(token, account, vo=vo)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthorize', 'Cannot authorize token request.', headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        if result is not None and len(result) > 1:
            headers.set('X-Rucio-Auth-Token', str(result[0]))
            headers.set('X-Rucio-Auth-Token-Expires', str(result[1]))
        else:
            headers.set('X-Rucio-Auth-Token', '')
            headers.set('X-Rucio-Auth-Token-Expires', '')
        return '', 200, headers


class GSS(MethodView):
    """
    Authenticate a Rucio account temporarily via a GSS token.
    """

    def options(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Authenticate a Rucio account temporarily via a GSS token.

        .. :quickref: GSS; Authenticate with GSS token

        :reqheader Rucio-VO: VO name as a string (Multi-VO only).
        :reqheader Rucio-Account: Account identifier as a string.
        :reqheader Rucio-AppID: Application identifier as a string.
        :reqheader SavedCredentials: Apache mod_auth_kerb SavedCredentials.
        :resheader Access-Control-Allow-Origin:
        :resheader Access-Control-Allow-Headers:
        :resheader Access-Control-Allow-Methods:
        :resheader Access-Control-Allow-Credentials:
        :resheader Access-Control-Expose-Headers:
        :resheader X-Rucio-Auth-Token: The authentication token
        :status 200: Successfully authenticated
        :status 404: Invalid credentials
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = request.headers.get('X-Rucio-VO', default='def')
        account = request.headers.get('X-Rucio-Account', default=None)
        gsscred = request.environ.get('REMOTE_USER')
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        try:
            result = get_auth_token_gss(account, gsscred, appid, ip, vo=vo)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)

        if result is None:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)

        headers['X-Rucio-Auth-Token'] = result.token
        headers['X-Rucio-Auth-Token-Expires'] = date_to_str(result.expired_at)
        return '', 200, headers


class x509(MethodView):
    """
    Authenticate a Rucio account temporarily via an x509 certificate.
    """

    def options(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Authenticate a Rucio account temporarily via an x509 certificate.

        .. :quickref: x509; Authenticate with x509 certificate.

        :reqheader Rucio-VO: VO name as a string (Multi-VO only).
        :reqheader Rucio-Account: Account identifier as a string.
        :reqheader Rucio-AppID: Application identifier as a string.
        :reqheader SSLStdEnv: Apache mod_ssl SSL Standard Env Variables.
        :resheader Access-Control-Allow-Origin:
        :resheader Access-Control-Allow-Headers:
        :resheader Access-Control-Allow-Methods:
        :resheader Access-Control-Allow-Credentials:
        :resheader Access-Control-Expose-Headers:
        :resheader X-Rucio-Auth-Token: The authentication token
        :status 200: Successfully authenticated
        :status 404: Invalid credentials
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = request.headers.get('X-Rucio-VO', default='def')
        account = request.headers.get('X-Rucio-Account', default=None)
        dn = request.environ.get('SSL_CLIENT_S_DN')
        if not dn:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get DN', headers=headers)
        if not dn.startswith('/'):
            dn = '/%s' % '/'.join(dn.split(',')[::-1])

        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        # If we get a valid proxy certificate we have to strip this postfix,
        # otherwise we would have to store the proxy DN in the database as well.
        # Alternative: use the SSL_CLIENT_I_DN, but that would require a separate
        # endpoint as you cannot programmatically decide, by examining the SSL variables,
        # if you got a proxy or regular certificate
        while True:
            if dn.endswith('/CN=limited proxy'):
                dn = dn[:-17]
            elif dn.endswith('/CN=proxy'):
                dn = dn[:-9]
            elif search('/CN=[0-9]*$', dn):
                dn = dn.rpartition('/')[0]
            else:
                break

        try:
            result = get_auth_token_x509(account, dn, appid, ip, vo=vo)
        except AccessDenied:
            print('Cannot Authenticate', account, dn, appid, ip, vo)
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)
        except IdentityError:
            print('Cannot Authenticate', account, dn, appid, ip, vo)
            return generate_http_error_flask(401, 'CannotAuthenticate', 'No default account set for %(dn)s' % locals(), headers=headers)

        if not result:
            print('Cannot Authenticate', account, dn, appid, ip, vo)
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)

        headers['X-Rucio-Auth-Token'] = result.token
        headers['X-Rucio-Auth-Token-Expires'] = date_to_str(result.expired_at)
        return '', 200, headers


class SSH(MethodView):
    """
    Authenticate a Rucio account temporarily via SSH key exchange.
    """

    def options(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Authenticate a Rucio account temporarily via SSH key exchange.

        .. :quickref: SSH; Authenticate with SSH key exchange.

        :reqheader Rucio-VO: VO name as a string (Multi-VO only).
        :reqheader Rucio-Account: Account identifier as a string.
        :reqheader Rucio-SSH-Signature: Response to server challenge signed with SSH private key as a base64 encoded string.
        :reqheader Rucio-AppID: Application identifier as a string.
        :resheader Access-Control-Allow-Origin:
        :resheader Access-Control-Allow-Headers:
        :resheader Access-Control-Allow-Methods:
        :resheader Access-Control-Allow-Credentials:
        :resheader Access-Control-Expose-Headers:
        :resheader X-Rucio-Auth-Token: The authentication token
        :status 200: Successfully authenticated
        :status 404: Invalid credentials
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = request.headers.get('X-Rucio-VO', default='def')
        account = request.headers.get('X-Rucio-Account', default=None)
        signature = request.headers.get('X-Rucio-SSH-Signature', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        # decode the signature which must come in base64 encoded
        try:
            signature = base64.b64decode(signature)
        except TypeError:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with malformed signature' % locals(), headers=headers)

        try:
            result = get_auth_token_ssh(account, signature, appid, ip, vo=vo)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)

        headers['X-Rucio-Auth-Token'] = result.token
        headers['X-Rucio-Auth-Token-Expires'] = date_to_str(result.expired_at)
        return '', 200, headers


class SSHChallengeToken(MethodView):
    """
    Request a challenge token for SSH authentication
    """

    def options(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Request a challenge token for SSH authentication

        .. :quickref: SSH; Request SSH Challenge Token

        :reqheader Rucio-VO: VO name as a string (Multi-VO only).
        :reqheader Rucio-Account: Account identifier as a string.
        :reqheader Rucio-AppID: Application identifier as a string.
        :resheader Access-Control-Allow-Origin:
        :resheader Access-Control-Allow-Headers:
        :resheader Access-Control-Allow-Methods:
        :resheader Access-Control-Allow-Credentials:
        :resheader Access-Control-Expose-Headers:
        :resheader X-Rucio-SSH-Challenge-Token: The SSH challenge token
        :resheader X-Rucio-SSH-Challenge-Token-Expires: The expiry time of the token
        :status 200: Successfully authenticated
        :status 404: Invalid credentials
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        vo = request.headers.get('X-Rucio-VO', default='def')
        account = request.headers.get('X-Rucio-Account', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        try:
            result = get_ssh_challenge_token(account, appid, ip, vo=vo)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
        except Exception as error:
            print(format_exc())
            return str(error), 500, headers

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot generate challenge for account %(account)s' % locals(), headers=headers)

        headers['X-Rucio-SSH-Challenge-Token'] = result.token
        headers['X-Rucio-SSH-Challenge-Token-Expires'] = date_to_str(result.expired_at)
        return '', 200, headers


class SAML(MethodView):
    """
    Authenticate a Rucio account temporarily via CERN SSO.
    """

    def options(self):
        """
        Allow cross-site scripting. Explicit for Authentication.

        :status 200: OK
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        headers.set('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        .. :quickref: SAML;

        :status 200: OK
        :status 401: Unauthorized
        :reqheader Rucio-VO: VO name as a string (Multi-VO only)
        :reqheader Rucio-Account: Account identifier as a string.
        :reqheader Rucio-Username: Username as a string.
        :reqheader Rucio-Password: Password as a string.
        :reqheader Rucio-AppID: Application identifier as a string.
        :resheader X-Rucio-SAML-Auth-URL: as a variable-length string header.
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        headers.set('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')

        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        if not EXTRA_MODULES['onelogin']:
            return "SAML not configured on the server side.", 400, headers

        saml_nameid = cookies().get('saml-nameid')
        vo = request.headers.get('X-Rucio-VO', default='def')
        account = request.headers.get('X-Rucio-Account', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        if saml_nameid:
            try:
                result = get_auth_token_saml(account, saml_nameid, appid, ip, vo=vo)
            except AccessDenied:
                return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)
            except RucioException as error:
                return generate_http_error_flask(500, error.__class__.__name__, error.args[0], headers=headers)
            except Exception as error:
                print(format_exc())
                return str(error), 500, headers

            if not result:
                return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)

            headers.set('X-Rucio-Auth-Token', result.token)
            headers.set('X-Rucio-Auth-Token-Expires', date_to_str(result.expired_at))
            return '', 200, headers

        # Path to the SAML config folder
        SAML_PATH = config_get('saml', 'config_path')

        req = prepare_saml_request(request.environ, dict(request.args.items(multi=False)))
        auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)

        headers.set('X-Rucio-SAML-Auth-URL', auth.login())
        return '', 200, headers

    def post(self):
        """
        .. :quickref: SAML;

        :status 200: OK
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


class Validate(MethodView):
    """
    Validate a Rucio Auth Token.
    """

    def options(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return '', 200, headers

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Validate a Rucio Auth Token.

        .. :quickref: Validate; Validate a Rucio Auth Token.

        :reqheader Rucio-Auth-Token: as a variable-length string.
        :status 406: Not Acceptable.
        :returns: Tuple(account name, token lifetime).
        """

        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        headers['Content-Type'] = 'application/octet-stream'
        headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers['Pragma'] = 'no-cache'

        token = request.headers.get('X-Rucio-Auth-Token', default=None)

        result = validate_auth_token(token)
        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals(), headers=headers)

        return str(result), 200, headers


def blueprint():
    bp = Blueprint('authentication', __name__, url_prefix='/auth')

    user_pass_view = UserPass.as_view('user_pass')
    bp.add_url_rule('/userpass', view_func=user_pass_view, methods=['get', 'options'])
    gss_view = GSS.as_view('gss')
    bp.add_url_rule('/gss', view_func=gss_view, methods=['get', 'options'])
    x509_view = x509.as_view('x509')
    bp.add_url_rule('/x509', view_func=x509_view, methods=['get', 'options'])
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
