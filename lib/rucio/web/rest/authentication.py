#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2012

from re import search
from web import application, ctx, BadRequest, header

from rucio.api.authentication import get_auth_token_user_pass, get_auth_token_gss, get_auth_token_x509, validate_auth_token
from rucio.common.exception import AccessDenied
from rucio.common.utils import generate_http_error


urls = (
    '/userpass', 'UserPass',
    '/gss', 'GSS',
    '/x509', 'x509',
    '/x509_proxy', 'x509',
    '/validate', 'Validate',
)


class UserPass:
    """
    Authenticate a Rucio account temporarily via username and password.
    """

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
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        if result is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')
        else:
            header('X-Rucio-Auth-Token', result)
            return str()

        raise BadRequest()

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class GSS:
    """
    Authenticate a Rucio account temporarily via a GSS token.
    """

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
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        if result is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')
        else:
            header('X-Rucio-Auth-Token', result)
            return str()

        raise BadRequest()

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class x509:
    """
    Authenticate a Rucio account temporarily via an x509 certificate.
    """

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

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
        dn = ctx.env.get('SSL_CLIENT_S_DN')
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
        if dn.endswith('/CN=limited proxy'):
            dn = dn[:-17]
        if dn.endswith('/CN=proxy'):
            while dn.endswith('/CN=proxy'):
                dn = dn[:-9]
        elif search('/CN=[0-9]*$', dn):
            dn = dn.rpartition('/')[0]

        try:
            result = get_auth_token_x509(account, dn, appid, ip)
        except AccessDenied:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        if result is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')
        else:
            header('X-Rucio-Auth-Token', result)
            return str()

        raise BadRequest()

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Validate:
    """
    Validate a Rucio Auth Token.
    """

    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Auth-Token: as a variable-length string.
        :returns: Tuple(account name, token lifetime).
        """

        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')

        result = validate_auth_token(token)

        if result is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')
        else:
            return result

        raise BadRequest()

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
