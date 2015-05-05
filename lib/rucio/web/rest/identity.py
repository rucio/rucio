#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012, 2014-2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

import json

from traceback import format_exc

from web import application, ctx, BadRequest, Created, InternalError, loadhook

from rucio.api.identity import add_identity, add_account_identity, list_accounts_for_identity
from rucio.web.rest.common import rucio_loadhook, RucioController


urls = (
    '/(.+)/(.+)/accounts', 'Accounts',
    '/(.+)/userpass', 'UserPass',
    '/(.+)/x509', 'x509',
    '/(.+)/gss', 'GSS'
)


class UserPass(RucioController):
    """ Manage a username/password identity for an account. """

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
        username = ctx.env.get('HTTP_X_RUCIO_USERNAME')
        password = ctx.env.get('HTTP_X_RUCIO_PASSWORD')

        if username is None or password is None:
            raise BadRequest('Username and Password must be set.')

        try:
            add_identity(username, 'userpass', password)
        except Exception, e:
            # TODO: Proper rollback
            raise InternalError(e)

        try:
            add_account_identity(username, 'userpass', account)
        except Exception, e:
            # TODO: Proper rollback
            raise InternalError(e)

        raise Created()


class x509(RucioController):
    """ Manage an x509 identity for an account. """

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
        dn = ctx.env.get('SSL_CLIENT_S_DN')
        try:
            add_identity(dn, 'x509')
        except Exception, e:
            # TODO: Proper rollback
            raise InternalError(e)

        try:
            add_account_identity(dn, 'x509', account)
        except Exception, e:
            # TODO: Proper rollback
            raise InternalError(e)

        raise Created()


class GSS(RucioController):
    """ Manage a GSS identity for an account. """

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
        gsscred = ctx.env.get('REMOTE_USER')
        try:
            add_identity(gsscred, 'gss')
        except Exception, e:
            # TODO: Proper rollback
            raise InternalError(e)

        try:
            add_account_identity(gsscred, 'gss', account)
        except Exception, e:
            # TODO: Proper rollback
            raise InternalError(e)

        raise Created()


class Accounts(RucioController):
    """ Retrieve list of accounts mapped to an identity. """

    def GET(self, identity_key, type):
        """
        Return all identities mapped to an account.

        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            500 Internal Error

        :param account: Identity string.
        """

        try:
            return json.dumps(list_accounts_for_identity(identity_key, type))
        except Exception, e:
            print e
            print str(format_exc())
            raise InternalError(e)


"""----------------------
   Web service startup
   ----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(rucio_loadhook))
application = app.wsgifunc()
