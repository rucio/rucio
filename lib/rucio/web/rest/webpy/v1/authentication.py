#!/usr/bin/env python
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Angelos Molfetas <Angelos.Molfetas@cern.ch>, 2012
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2017
# - Yun-Pin Sun <winter0128@gmail.com>, 2012-2013
# - Thomas Beermann <thomas.beermann@cern.ch>, 2013-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
import base64

from re import search
from traceback import format_exc

from web import application, ctx, OK, BadRequest, header, InternalError

from rucio.api.authentication import (get_auth_token_user_pass,
                                      get_auth_token_gss,
                                      get_auth_token_x509,
                                      get_auth_token_ssh,
                                      get_ssh_challenge_token,
                                      validate_auth_token)
from rucio.common.exception import AccessDenied, IdentityError, RucioException
from rucio.common.utils import generate_http_error, date_to_str
from rucio.web.rest.common import RucioController, check_accept_header_wrapper


URLS = (
    '/userpass', 'UserPass',
    '/gss', 'GSS',
    '/x509', 'x509',
    '/x509_proxy', 'x509',
    '/ssh', 'SSH',
    '/ssh_challenge_token', 'SSHChallengeToken',
    '/validate', 'Validate',
)


class UserPass(RucioController):
    """
    Authenticate a Rucio account temporarily via username and password.
    """

    def OPTIONS(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier as a string.
        :param Rucio-Username: Username as a string.
        :param Rucio-Password: SHA1 hash of the password as a string.
        :param Rucio-AppID: Application identifier as a string.
        :returns: "Rucio-Auth-Token" as a variable-length string header.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
        username = ctx.env.get('HTTP_X_RUCIO_USERNAME')
        password = ctx.env.get('HTTP_X_RUCIO_PASSWORD')
        appid = ctx.env.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip

        try:
            result = get_auth_token_user_pass(account, username, password, appid, ip)
        except AccessDenied:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        if not result:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        header('X-Rucio-Auth-Token', result.token)
        header('X-Rucio-Auth-Token-Expires', date_to_str(result.expired_at))
        return str()


class GSS(RucioController):
    """
    Authenticate a Rucio account temporarily via a GSS token.
    """

    def OPTIONS(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier as a string.
        :param Rucio-AppID: Application identifier as a string.
        :param SavedCredentials: Apache mod_auth_kerb SavedCredentials.
        :returns: "Rucio-Auth-Token" as a variable-length string header.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
        gsscred = ctx.env.get('REMOTE_USER')
        appid = ctx.env.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip

        try:
            result = get_auth_token_gss(account, gsscred, appid, ip)
        except AccessDenied:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        if result is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        else:
            header('X-Rucio-Auth-Token', result.token)
            header('X-Rucio-Auth-Token-Expires', date_to_str(result.expired_at))
            return str()

        raise BadRequest()


class x509(RucioController):
    """
    Authenticate a Rucio account temporarily via an x509 certificate.
    """

    def OPTIONS(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier as a string.
        :param Rucio-AppID: Application identifier as a string.
        :param SSLStdEnv: Apache mod_ssl SSL Standard Env Variables.
        :returns: "Rucio-Auth-Token" as a variable-length string header.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
        dn = ctx.env.get('SSL_CLIENT_S_DN')
        if not dn:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot get DN')
        if not dn.startswith('/'):
            dn = '/%s' % '/'.join(dn.split(',')[::-1])

        appid = ctx.env.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip

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
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        except IdentityError:
            print('Cannot Authenticate', account, dn, appid, ip)
            raise generate_http_error(401, 'CannotAuthenticate', 'No default account set for %(dn)s' % locals())

        if not result:
            print('Cannot Authenticate', account, dn, appid, ip)
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        header('X-Rucio-Auth-Token', result.token)
        header('X-Rucio-Auth-Token-Expires', date_to_str(result.expired_at))
        return str()


class SSH(RucioController):
    """
    Authenticate a Rucio account temporarily via SSH key exchange.
    """

    def OPTIONS(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier as a string.
        :param Rucio-SSH-Signature: Response to server challenge signed with SSH private key as a base64 encoded string.
        :param Rucio-AppID: Application identifier as a string.
        :returns: "Rucio-Auth-Token" as a variable-length string header.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
        signature = ctx.env.get('HTTP_X_RUCIO_SSH_SIGNATURE')
        appid = ctx.env.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip

        # decode the signature which must come in base64 encoded
        try:
            signature = base64.b64decode(signature)
        except:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with malformed signature' % locals())

        try:
            result = get_auth_token_ssh(account, signature, appid, ip)
        except AccessDenied:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        if not result:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        header('X-Rucio-Auth-Token', result.token)
        header('X-Rucio-Auth-Token-Expires', date_to_str(result.expired_at))
        return str()


class SSHChallengeToken(RucioController):
    """
    Request a challenge token for SSH authentication
    """

    def OPTIONS(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier as a string.
        :param Rucio-AppID: Application identifier as a string.
        :returns: "Rucio-Auth-Token" as a variable-length string header.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
        appid = ctx.env.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip

        try:
            result = get_ssh_challenge_token(account, appid, ip)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        if not result:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot generate challenge for account %(account)s' % locals())

        header('X-Rucio-SSH-Challenge-Token', result.token)
        header('X-Rucio-SSH-Challenge-Token-Expires', date_to_str(result.expired_at))
        return str()


class Validate(RucioController):
    """
    Validate a Rucio Auth Token.
    """

    def OPTIONS(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authentication.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable

        :param Rucio-Auth-Token: as a variable-length string.
        :returns: Tuple(account name, token lifetime).
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')

        result = validate_auth_token(token)
        if not result:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        return result


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
application = APP.wsgifunc()
