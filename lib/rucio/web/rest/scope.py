#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

import json
import logging
import web

from rucio.api import scope
from rucio.core.authentication import validate_auth_token
from rucio.common import exception as r_exception

logger = logging.getLogger("rucio.scope")
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)

urls = (
    '/(.+)/(.+)', 'Scope',
    '/(.+)', 'ScopeList',
)


class Scope:
    """ create new rucio scopes. """

    def GET(self):
        raise web.BadRequest()

    def PUT(self):
        raise web.BadRequest()

    def POST(self, accountName, scopeName):
        """ create scope with given scope name.

        HTTP Success:
            201 Created

        HTTP Error:
            500 Internal Error

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :params Rucio-Account: account belonging to the new scope.
        """

        web.header('Content-Type', 'application/octet-stream')

        auth_account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_account, auth_token)

        if auth is None:
            raise web.Unauthorized()

        try:
            scope.add_scope(scopeName, accountName)
        except r_exception.Duplicate, e:
            raise web.InternalError(e)
        except r_exception.NotFound, e:
            raise web.InternalError(e)
        except Exception, e:
            raise web.InternalError(e)

        raise web.Created()

    def DELETE(self):
        raise web.BadRequest()


class ScopeList:
    """ list scopes """

    def GET(self, accountName):
        """ list all scopes for an account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: A list containing all scope names for an account.
        """
        web.header('Content-Type', 'application/json')

        auth_account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_account, auth_token)

        if auth is None:
            raise web.Unauthorized()

        try:
            scopes = scope.get_scopes(accountName)
        except Exception, e:
            raise web.InternalError(e)

        if not scopes:
            raise web.InternalError('No scopes found for Account %s' % accountName)

        return json.dumps(scopes)

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
