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
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
#
# PY3K COMPATIBLE

from __future__ import print_function
import base64
from os.path import dirname, join

from re import search
from traceback import format_exc

from web import application, ctx, OK, BadRequest, header, InternalError, seeother, template

from rucio.api.authentication import (get_auth_token_user_pass,
                                      get_auth_token_gss,
                                      get_auth_token_x509,
                                      get_auth_token_ssh,
                                      get_ssh_challenge_token,
                                      validate_auth_token,
                                      get_auth_OIDC,
                                      get_token_OIDC,
                                      redirect_auth_OIDC)
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
    '/OIDC', 'OIDC',
    '/OIDC_token', 'OIDC_token',
    '/OIDC_code', 'OIDC_code',
    '/OIDC_redirect', 'OIDC_redirect'
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


class OIDC(RucioController):
    """
    Requests a user specific Authorization URL (assigning a user session state,
    nonce, Rucio OIDC Client ID with the correct issuers authentication endpoint).
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
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier as a string.

        :returns: User & Rucio OIDC Client specific Authorization URL as a string.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
        auth_scope = ctx.env.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_SCOPE')
        audience = ctx.env.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_AUDIENCE')
        auto = ctx.env.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_AUTO')
        issuer = ctx.env.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_ISSUER')
        polling = ctx.env.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_POLLING')
        refresh_lifetime = ctx.env.get('HTTP_X_RUCIO_CLIENT_AUTHORIZE_REFRESH_LIFETIME')
        auto = (auto == 'True')
        polling = (polling == 'True')
        if refresh_lifetime == 'None':
            refresh_lifetime = None
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip
        try:
            kwargs = {'auth_scope': auth_scope,
                      'audience': audience,
                      'issuer': issuer,
                      'auto': auto,
                      'polling': polling,
                      'refresh_lifetime': refresh_lifetime,
                      'ip': ip}
            result = get_auth_OIDC(account, **kwargs)
        except AccessDenied:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot get authentication URL from Rucio Authentication Server for account %(account)s' % locals())
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        if not result:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot get authentication URL from Rucio Authentication Server for account %(account)s' % locals())

        header('X-Rucio-OIDC-Auth-URL', result)
        return str()


class OIDC_redirect(RucioController):
    """
    Authenticate a Rucio account via
    an Identity Provider (XDC IAM as of June 2019).
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
        raise OK

    @check_accept_header_wrapper(['application/octet-stream', 'text/html'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param QUERY_STRING: the URL query string itself

        :returns: "Rucio-Auth-Token" as a variable-length string header.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        # interaction with web browser - display response in html format
        header('Content-Type', 'text/html')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        query_string = ctx.env.get('QUERY_STRING')
        try:
            fetchtoken = ctx.env.get('HTTP_X_RUCIO_CLIENT_FETCH_TOKEN')
            fetchtoken = (fetchtoken == 'True')
            result = redirect_auth_OIDC(query_string, fetchtoken)

        except AccessDenied:
            render = template.render(join(dirname(__file__), 'templates/'))
            return render.auth_crash('contact')
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot contact the Rucio Authentication Server.')

        except RucioException as error:
            render = template.render(join(dirname(__file__), 'templates/'))
            return render.auth_crash('internal_error')
            raise generate_http_error(500, error.__class__.__name__, error.args[0])

        except Exception as error:
            print(format_exc())
            render = template.render(join(dirname(__file__), 'templates/'))
            return render.auth_crash('internal_error')
            raise InternalError(error)

        if not result:
            render = template.render(join(dirname(__file__), 'templates/'))
            return render.auth_crash('no_token')
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot contact the Rucio Authentication Server.')
        if fetchtoken:
            # this is only a case of returning the final token to the Rucio Client polling
            # or requesting token after copy-pasting the Rucio code from the web page page
            header('Content-Type', 'application/octet-stream')
            header('X-Rucio-Auth-Token', result)
            return str()
        else:
            raise seeother(result)


class OIDC_code(RucioController):
    """
    IdP redirects to this endpoing with the AuthZ code
    Rucio Auth server will request new token. This endpoint should be reached
    only if the request/ IdP login has been made through web browser. Then the response
    content will be in html (including the potential errors displayed).
    The token will be saved in the Rucio DB, but only Rucio code will
    be returned on the web page, or, in case of polling is True, successful
    operation is confirmed waiting for the Rucio client to get the token automatically.
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
        raise OK

    @check_accept_header_wrapper(['application/octet-stream', 'text/html'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param QUERY_STRING: the URL query string itself

        :returns: "Rucio-Auth-Token" as a variable-length string header.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        header('Content-Type', 'text/html')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        query_string = ctx.env.get('QUERY_STRING')
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip

        try:
            result = get_token_OIDC(query_string, ip)

        except AccessDenied:
            render = template.render(join(dirname(__file__), 'templates/'))
            return render.auth_crash('contact')
            raise generate_http_error(401, 'CannotAuthorize', 'Cannot authorize token request.')
        except RucioException as error:
            render = template.render(join(dirname(__file__), 'templates/'))
            return render.auth_crash('internal_error')
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            render = template.render(join(dirname(__file__), 'templates/'))
            return render.auth_crash('internal_error')
            raise InternalError(error)

        render = template.render(join(dirname(__file__), 'templates/'))
        if not result:
            return render.auth_crash('no_result')
            raise generate_http_error(401, 'CannotAuthorize', 'Cannot authorize token request.')
        if result[0] == 'fetchcode':
            authcode = result[1]
            return render.auth_granted(authcode)
        elif result[0] == 'polling':
            authcode = "allok"
            return render.auth_granted(authcode)
        else:
            return render.auth_crash('bad_request')
            raise BadRequest()


class OIDC_token(RucioController):
    """
    Authenticate a Rucio account temporarily via ID,
    access (eventually save new refresh token)
    received from an Identity Provider.
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
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param QUERY_STRING: the URL query string itself

        :returns: "Rucio-Auth-Token" as a variable-length string header.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        query_string = ctx.env.get('QUERY_STRING')
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip

        try:
            result = get_token_OIDC(query_string, ip)

        except AccessDenied:
            raise generate_http_error(401, 'CannotAuthorize', 'Cannot authorize token request.')
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        if not result:
            raise generate_http_error(401, 'CannotAuthorize', 'Cannot authorize token request.')
        if result[0] == 'token':
            header('X-Rucio-Auth-Token', result[1].token)
            header('X-Rucio-Auth-Token-Expires', date_to_str(result[1].expired_at))
            return str()
        else:
            raise BadRequest()


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
