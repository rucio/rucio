#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2020
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from json import dumps
from logging import getLogger, StreamHandler, DEBUG

from web import application, ctx, header, Created, InternalError, loadhook

from rucio.api.scope import add_scope, get_scopes, list_scopes
from rucio.common.exception import AccountNotFound, Duplicate, RucioException
from rucio.web.rest.common import rucio_loadhook, RucioController, check_accept_header_wrapper
from rucio.web.rest.utils import generate_http_error

LOGGER = getLogger("rucio.scope")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = (
    '/', 'Scope',
    '/(.+)/scopes', 'ScopesList',
)


class Scope(RucioController):
    """ create new rucio scopes. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self):
        """
        List all scopes.

        HTTP Success:
            200 Success
        HTTP Error:
            406 Not Acceptable
        """
        return dumps(list_scopes(vo=ctx.env.get('vo')))

    def POST(self, account, scope):
        """
        Creates scope with given scope name.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :params Rucio-Account: account belonging to the new scope.
        """
        try:
            add_scope(scope, account, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

        raise Created()


class ScopeList(RucioController):
    """ list scopes """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, account):
        """
        List all scopes for an account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: A list containing all scope names for an account.
        """
        header('Content-Type', 'application/json')
        try:
            scopes = get_scopes(account, vo=ctx.env.get('vo'))
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except Exception as error:
            raise InternalError(error)

        if not len(scopes):
            raise generate_http_error(404, 'ScopeNotFound', 'no scopes found for account ID \'%s\'' % account)

        return dumps(scopes)


# ----------------------
#   Web service startup
# ----------------------

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
if __name__ != "rucio.web.rest.scope":
    application = APP.wsgifunc()
