#!/usr/bin/env python
# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2014
# - Yun-Pin Sun <yun-pin.sun@cern.ch>, 2012
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
import base64
from re import search
from traceback import format_exc

from rucio.api.authentication import get_auth_token_user_pass, get_auth_token_gss, get_auth_token_x509, get_auth_token_ssh, get_ssh_challenge_token, validate_auth_token
from rucio.common.exception import AccessDenied, IdentityError, RucioException
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask

from flask import Flask, Blueprint, request, Response
from flask.views import MethodView


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

        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return response

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Authenticate a Rucio account temporarily via username and password.

        .. :quickref: UserPass; Authenticate with username/password

        :reqheader X-Rucio-Account: Account identifier as a string.
        :reqheader X-Rucio-Username: Username as a string.
        :reqheader X-Rucio-Password: SHA1 hash of the password as a string.
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

        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

        account = request.environ.get('HTTP_X_RUCIO_ACCOUNT')
        username = request.environ.get('HTTP_X_RUCIO_USERNAME')
        password = request.environ.get('HTTP_X_RUCIO_PASSWORD')
        appid = request.environ.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = request.remote_addr

        print(account, username, password, appid)
        try:
            result = get_auth_token_user_pass(account, username, password, appid, ip)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        response.headers['X-Rucio-Auth-Token'] = result
        return response


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

        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return response

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Authenticate a Rucio account temporarily via a GSS token.

        .. :quickref: GSS; Authenticate with GSS token

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

        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

        account = request.environ.get('HTTP_X_RUCIO_ACCOUNT')
        gsscred = request.environ.get('REMOTE_USER')
        appid = request.environ.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = request.remote_addr

        try:
            result = get_auth_token_gss(account, gsscred, appid, ip)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        if result is None:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        else:
            response.headers('X-Rucio-Auth-Token', result)
            return str()

        return 'BadRequest', 400


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

        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return response

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Authenticate a Rucio account temporarily via an x509 certificate.

        .. :quickref: x509; Authenticate with x509 certificate.

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

        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

        account = request.environ.get('HTTP_X_RUCIO_ACCOUNT')
        dn = request.environ.get('SSL_CLIENT_S_DN')
        if not dn:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot get DN')
        if not dn.startswith('/'):
            dn = '/%s' % '/'.join(dn.split(',')[::-1])

        appid = request.environ.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = request.remote_addr

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
            result = get_auth_token_x509(account, dn, appid, ip)
        except AccessDenied:
            print('Cannot Authenticate', account, dn, appid, ip)
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        except IdentityError:
            print('Cannot Authenticate', account, dn, appid, ip)
            return generate_http_error_flask(401, 'CannotAuthenticate', 'No default account set for %(dn)s' % locals())

        if not result:
            print('Cannot Authenticate', account, dn, appid, ip)
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        response.headers['X-Rucio-Auth-Token'] = result
        response.set_data(str())
        return response


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

        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return response

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Authenticate a Rucio account temporarily via SSH key exchange.

        .. :quickref: SSH; Authenticate with SSH key exchange.

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

        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

        account = request.environ.get('HTTP_X_RUCIO_ACCOUNT')
        signature = request.environ.get('HTTP_X_RUCIO_SSH_SIGNATURE')
        appid = request.environ.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = request.remote_addr

        # decode the signature which must come in base64 encoded
        try:
            signature = base64.b64decode(signature)
        except Exception as error:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with malformed signature' % locals())

        try:
            result = get_auth_token_ssh(account, signature, appid, ip)
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        response.headers['X-Rucio-Auth-Token'] = result
        response.set_data(str())
        return response


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

        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return response

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Request a challenge token for SSH authentication

        .. :quickref: SSHChallengeToken; Request SSH Challenge Token

        :reqheader Rucio-Account: Account identifier as a string.
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

        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

        account = request.environ.get('HTTP_X_RUCIO_ACCOUNT')
        appid = request.environ.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = request.remote_addr

        try:
            result = get_ssh_challenge_token(account, appid, ip)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot generate challenge for account %(account)s' % locals())

        response.headers['X-Rucio-SSH-Challenge-Token'] = result
        response.set_data(str())
        return response


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

        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return response

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Validate a Rucio Auth Token.

        .. :quickref: Validate; Validate a Rucio Auth Token.

        :reqheader Rucio-Auth-Token: as a variable-length string.
        :status 406: Not Acceptable.
        :returns: Tuple(account name, token lifetime).
        """

        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

        token = request.environ.get('HTTP_X_RUCIO_AUTH_TOKEN')

        result = validate_auth_token(token)
        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        response.set_data(result)
        return response


bp = Blueprint('authentication', __name__)

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
validate_view = Validate.as_view('validate')
bp.add_url_rule('/validate', view_func=validate_view, methods=['get', 'options'])

application = Flask(__name__)
application.register_blueprint(bp)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/auth')
    return doc_app


if __name__ == "__main__":
    application.run()
