#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, data, header, input as web_input, websafe,\
    Created, InternalError, OK, BadRequest

from rucio.api.identifier import list_replicas, add_identifier, list_content, list_files
from rucio.core.authentication import validate_auth_token
from rucio.common.exception import DataIdentifierNotFound
from rucio.common.utils import generate_http_error

logger = getLogger("rucio.identifier.py")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/(.*)/(.*)/rses', 'Replicas',
    '/(.*)/(.*)/data_ids', 'Identifiers',
    '/(.*)/(.*)/files', 'Files',
    '/(.*)/(.*)', 'Identifiers',
)


class Identifiers:

    def POST(self, scope, name):
        """

        """
        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        json_data = data()
        try:
            sources = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter list')

        try:
            add_identifier(scope=scope, name=name, sources=sources, issuer=auth['account'])
        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)
        raise Created()

    def GET(self, scope, name):
        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')
        try:
            return dumps(list_content(scope=scope, name=name))
        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Replicas:

    def POST(self, scope, name):
        raise BadRequest()

    def GET(self, scope, name):
        """ list all replicas for a data_id.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionnary containing all replicas information.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            return dumps(list_replicas(scope=scope, name=name))
        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except Exception, e:
            print e
            raise InternalError(e)

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Files:

    def POST(self, scope, name):
        raise BadRequest()

    def GET(self, scope, name):
        """ list all replicas for a data_id.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionnary containing all replicas information.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            return dumps(list_files(scope=scope, name=name))
        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except Exception, e:
            print e
            raise InternalError(e)

    def PUT(self):
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
