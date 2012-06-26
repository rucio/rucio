#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import web

from rucio.api.authentication import validate_auth_token
from rucio.api.identity import add_identity, add_account_identity

urls = (
    '/(.+)/userpass', 'UserPass',
    '/(.+)/x509', 'x509',
    '/(.+)/gss', 'GSS'
)


class UserPass:
    """ Manage a username/password identity for an account. """

    def GET(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def PUT(self, account):
        """
        Create a new identity and map it to an account.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            500 Internal Error

        :param Rucio-Auth-Token: as an 32 character hex string.
        :param Rucio-Username: the desired username.
        :param Rucio-Password: the desired password.
        :param account: the affected account via URL.
        """

        web.header('Content-Type', 'application/octet-stream')

        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise web.Unauthorized()

        username = web.ctx.env.get('HTTP_RUCIO_USERNAME')
        password = web.ctx.env.get('HTTP_RUCIO_PASSWORD')

        if username is None or password is None:
            raise web.BadRequest('Username and Password must be set.')

        try:
            add_identity(username, 'userpass', password)
        except Exception, e:
            # TODO: Proper rollback
            raise web.InternalError(e)

        try:
            add_account_identity(username, 'userpass', account)
        except Exception, e:
            # TODO: Proper rollback
            raise web.InternalError(e)

        raise web.Created()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


class x509:
    """ Manage an x509 identity for an account. """

    def GET(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def PUT(self, account):
        """
        Create a new identity and map it to an account.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            500 Internal Error

        :param Rucio-Auth-Token: as an 32 character hex string.
        :param SSLStdEnv: Apache mod_ssl SSL Standard Env Variables.
        :param account: the affected account via URL.
        """

        web.header('Content-Type', 'application/octet-stream')

        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise web.Unauthorized()

        dn = web.ctx.env.get('SSL_CLIENT_S_DN')

        try:
            add_identity(dn, 'x509')
        except Exception, e:
            # TODO: Proper rollback
            raise web.InternalError(e)

        try:
            add_account_identity(dn, 'x509', account)
        except Exception, e:
            # TODO: Proper rollback
            raise web.InternalError(e)

        raise web.Created()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


class GSS:
    """ Manage a GSS identity for an account. """

    def GET(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def PUT(self, account):
        """
        Create a new identity and map it to an account.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            500 Internal Error

        :param Rucio-Auth-Token: as an 32 character hex string.
        :param SavedCredentials: Apache mod_auth_kerb SavedCredentials.
        :param account: the affected account via URL.
        """

        web.header('Content-Type', 'application/octet-stream')

        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise web.Unauthorized()

        gsscred = web.ctx.env.get('REMOTE_USER')

        try:
            add_identity(gsscred, 'gss')
        except Exception, e:
            # TODO: Proper rollback
            raise web.InternalError(e)

        try:
            add_account_identity(gsscred, 'gss', account)
        except Exception, e:
            # TODO: Proper rollback
            raise web.InternalError(e)

        raise web.Created()

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
