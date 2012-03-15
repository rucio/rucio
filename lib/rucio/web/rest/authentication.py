#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import webb

from rucio.api.authentication import get_auth_token_user_pass
from rucio.api.authentication import get_auth_token_kerberos
from rucio.api.authentication import get_auth_token_x509
from rucio.api.authentication import validate_auth_token
from rucio.api.authentication import register_api_token
from rucio.api.authentication import validate_api_token

urls = (
    '/auth/userpass', 'UserPass',
    '/auth/kerberos', 'Kerberos',
    '/auth/x509', 'x509',
    '/auth/validate', 'Validate',
    '/auth/register_api_token', 'APITokens'
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

        result = get_auth_token_user_pass(account, username, password)
        if result is None:
            raise web.Unauthorized()
        else:
            web.header('Rucio-Auth-Token', result)
            return ""

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


class Kerberos:
    """Authenticate a Rucio account temporarily via a Kerberos token."""

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


class x509:
    """Authenticate a Rucio account temporarily via an x509 certificate."""

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


class Validate:
    """Validate a Rucio Auth Token"""

    def GET(self):

        """
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: Expected current lifetime of the token.
        """

        web.header('Content-Type', 'application/octet-stream')

        account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        result = validate_auth_token(account, token)
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

if __name__ == "__main__":
    web.wsgi.runwsgi = lambda func, addr=None: web.wsgi.runfcgi(func, addr)
    app.run()
