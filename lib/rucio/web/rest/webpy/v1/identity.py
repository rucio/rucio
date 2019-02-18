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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
import json

from traceback import format_exc

from web import application, ctx, BadRequest, Created, InternalError, loadhook

from rucio.api.identity import (add_identity, add_account_identity,
                                list_accounts_for_identity)
from rucio.web.rest.common import rucio_loadhook, RucioController, check_accept_header_wrapper


URLS = (
    '/(.+)/(.+)/accounts', 'Accounts',
    '/(.+)/userpass', 'UserPass',
    '/(.+)/x509', 'X509',
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
        :param Rucio-Email: the desired email.
        :param account: the affected account via URL.
        """
        username = ctx.env.get('HTTP_X_RUCIO_USERNAME')
        password = ctx.env.get('HTTP_X_RUCIO_PASSWORD')
        email = ctx.env.get('HTTP_X_RUCIO_EMAIL')

        if username is None or password is None:
            raise BadRequest('Username and Password must be set.')

        try:
            add_identity(username, 'userpass', email, password)
        except Exception as error:
            raise InternalError(error)

        try:
            add_account_identity(username, 'userpass', account,
                                 email=email, password=password,
                                 issuer=ctx.env.get('issuer'))
        except Exception as error:
            raise InternalError(error)

        raise Created()


class X509(RucioController):
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
        :param Rucio-Email: the desired email.
        :param account: the affected account via URL.
        """
        dn = ctx.env.get('SSL_CLIENT_S_DN')
        email = ctx.env.get('HTTP_X_RUCIO_EMAIL')

        try:
            add_identity(dn, 'x509', email=email)
        except Exception as error:
            raise InternalError(error)

        try:
            add_account_identity(dn, 'x509', account,
                                 email=email, issuer=ctx.env.get('issuer'))
        except Exception as error:
            raise InternalError(error)

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
        :param Rucio-Email: the desired email.
        :param account: the affected account via URL.
        """
        gsscred = ctx.env.get('REMOTE_USER')
        email = ctx.env.get('HTTP_X_RUCIO_EMAIL')

        try:
            add_identity(gsscred, 'gss', email=email)
        except Exception as error:
            raise InternalError(error)

        try:
            add_account_identity(gsscred, 'gss', account,
                                 email=email, issuer=ctx.env.get('issuer'))
        except Exception as error:
            raise InternalError(error)

        raise Created()


class Accounts(RucioController):
    """ Retrieve list of accounts mAPPed to an identity. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, identity_key, type):
        """
        Return all identities mAPPed to an account.

        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            406 Not Acceptable
            500 Internal Error

        :param account: Identity string.
        """
        try:
            return json.dumps(list_accounts_for_identity(identity_key, type))
        except Exception as error:
            print(str(format_exc()))
            raise InternalError(error)


# ----------------------
#   Web service startup
# ----------------------

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
