#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2012
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

from re import search
from traceback import format_exc

from web import application, ctx, OK, BadRequest, header, InternalError

from rucio.api.authentication import get_auth_token_user_pass, get_auth_token_gss, get_auth_token_x509, validate_auth_token
from rucio.common.exception import AccessDenied, IdentityError, RucioException
from rucio.common.utils import generate_http_error
from rucio.web.rest.common import RucioController


urls = (
    '/userpass', 'UserPass',
    '/gss', 'GSS',
    '/x509', 'x509',
    '/x509_proxy', 'x509',
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
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

        if not result:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        header('X-Rucio-Auth-Token', result)
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
            header('X-Rucio-Auth-Token', result)
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
            print 'Cannot Authenticate', account, dn, appid, ip
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        except IdentityError:
            print 'Cannot Authenticate', account, dn, appid, ip
            raise generate_http_error(401, 'CannotAuthenticate', 'No default account set for %(dn)s' % locals())

        if not result:
            print 'Cannot Authenticate', account, dn, appid, ip
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())

        header('X-Rucio-Auth-Token', result)
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

    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

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

app = application(urls, globals())
application = app.wsgifunc()
