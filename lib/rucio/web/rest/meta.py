#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, data, header, BadRequest, Created, InternalError, HTTPError, Unauthorized

from rucio.api.authentication import validate_auth_token
from rucio.api.meta import add_key, add_value, list_keys, list_values
from rucio.common.exception import Duplicate
from rucio.common.utils import generate_http_error


logger = getLogger("rucio.meta")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/(.+)/(.+)', 'Values',
        '/(.+)/', 'Values',
        '/(.+)', 'Meta',
        '/', 'Meta',)


class Meta:
    """ REST APIs for data identifier attribute keys. """

    def GET(self):

        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        return dumps(list_keys())

    def PUT(self):
        raise BadRequest()

    def POST(self, key):
        """ Create a new allowed key (value is NULL).

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

        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise Unauthorized()

        type, regexp = None, None
        json_data = data()
        try:
            params = json_data and loads(json_data)
            if params and 'type' in params:
                type = params['type']
            if params and 'regexp' in params:
                regexp = params['regexp']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_key(key=key, type=type, regexp=regexp, issuer=auth['account'])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def DELETE(self):
        raise BadRequest()


class Values:
    """ REST APIs for data identifier attribute values. """

    def GET(self, key):

        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')
        return dumps(list_values(key=key))

    def PUT(self):
        raise BadRequest()

    def POST(self, key, value):
        """ Create a new value for a key.

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

        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise Unauthorized()

        try:
            add_value(key=key, value=value, issuer=auth['account'])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def DELETE(self):
        raise BadRequest()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
