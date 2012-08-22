#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011

import web

from rucio.api.authentication import get_auth_token_user_pass
from rucio.api.authentication import get_auth_token_gss
from rucio.api.authentication import get_auth_token_x509
from rucio.api.authentication import validate_auth_token
from rucio.common.exception import AccessDenied

urls = (
    '/userpass', 'UserPass',
    '/gss', 'GSS',
    '/x509', 'x509',
    '/x509_proxy', 'x509',
    '/validate', 'Validate',
    '/register_api_token', 'APITokens'
)


class UserPass:
    """Authenticate a Rucio account temporarily via username and password."""

    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier.
        :param Rucio-Username: Username as a string.
        :param Rucio-Password: SHA1 hash of the password as a string.
        :returns: "Rucio-Auth-Token" as an 32 character hex string header.
        """

        web.header('Content-Type', 'application/octet-stream')

        account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        username = web.ctx.env.get('HTTP_RUCIO_USERNAME')
        password = web.ctx.env.get('HTTP_RUCIO_PASSWORD')
        ip = web.ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = web.ctx.ip

        try:
            result = get_auth_token_user_pass(account, username, password, ip)
        except AccessDenied as e:
            exc = web.Unauthorized()
            exc.headers = {'Content-Type': 'text/html', 'ExceptionClass': 'AccessDenied', 'ExceptionMessage': e[0][0]}
            exc.data = e[0][0]
            raise web.Unauthorized()

        if result is None:
            raise web.Unauthorized()
        else:
            web.header('Rucio-Auth-Token', result)
            return str()

        raise web.BadRequest()

    def PUT(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


class GSS:
    """Authenticate a Rucio account temporarily via a GSS token."""

    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier.
        :param SavedCredentials: Apache mod_auth_kerb SavedCredentials.
        :returns: "Rucio-Auth-Token" as an 32 character hex string header.
        """

        web.header('Content-Type', 'application/octet-stream')

        account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        gsscred = web.ctx.env.get('REMOTE_USER')
        ip = web.ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = web.ctx.ip

        try:
            result = get_auth_token_gss(account, gsscred, ip)
        except AccessDenied as e:
            exc = web.Unauthorized()
            exc.headers = {'Content-Type': 'text/html', 'ExceptionClass': 'AccessDenied', 'ExceptionMessage': e[0][0]}
            raise exc

        if result is None:
            raise web.Unauthorized()
        else:
            web.header('Rucio-Auth-Token', result)
            return str()

        raise web.BadRequest()

    def PUT(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


class x509:
    """Authenticate a Rucio account temporarily via an x509 certificate."""

    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier.
        :param SSLStdEnv: Apache mod_ssl SSL Standard Env Variables.
        :returns: "Rucio-Auth-Token" as an 32 character hex string header.
        """

        web.header('Content-Type', 'application/octet-stream')
        account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        dn = web.ctx.env.get('SSL_CLIENT_S_DN')
        ip = web.ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = web.ctx.ip

        # If we get a valid proxy certificate we have to strip this postfix,
        # otherwise we would have to store the proxy DN in the database as well.
        # Alternative: use the SSL_CLIENT_I_DN, but that would require a separate
        # endpoint as you cannot programmatically decide, by examining the SSL variables,
        # if you got a proxy or regular certificate
        while dn.endswith('/CN=proxy'):
            dn = dn[:-9]

        try:
            result = get_auth_token_x509(account, dn, ip)
        except AccessDenied as e:
            exc = web.Unauthorized()
            exc.headers = {'Content-Type': 'text/html', 'ExceptionClass': 'AccessDenied', 'ExceptionMessage': e[0][0]}
            raise exc

        if result is None:
            raise web.Unauthorized()
        else:
            web.header('Rucio-Auth-Token', result)
            return str()

        raise web.BadRequest()

    def PUT(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


class Validate:
    """Validate a Rucio Auth Token"""

    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: Tuple(Account name, Expected current lifetime of the token).
        """

        web.header('Content-Type', 'application/octet-stream')

        token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        result = validate_auth_token(token)

        if result is None:
            raise web.Unauthorized()
        else:
            return result

        raise web.BadRequest()

    def PUT(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


class APITokens:
    """Authenticate a Rucio account for interaction with the API"""

    def GET(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def PUT(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

"""----------------------
   Web service startup
----------------------"""

app = web.application(urls, globals())
application = app.wsgifunc()
