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
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

from json import dumps, loads
from web import application, ctx, data, header, Created, InternalError, BadRequest

from rucio.api.authentication import validate_auth_token
from rucio.api.identifier import list_replicas, add_identifier, list_content, list_files, scope_list
from rucio.common.exception import ScopeNotFound, DataIdentifierNotFound
from rucio.common.utils import generate_http_error

urls = (
    '/(.*)/', 'Scope',
    '/(.*)/(.*)/rses', 'Replicas',
    '/(.*)/(.*)/files', 'Files',
    '/(.*)/(.*)/dids', 'Content',
    '/(.*)/(.*)', 'Identifiers',
)


class Scope:

    def GET(self, scope):
        """
        Return all data identifiers in the given scope.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found

        :param scope: The scope name.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            return dumps(scope_list(scope=scope))
        except ScopeNotFound, e:
            raise generate_http_error(404, 'ScopeNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Identifiers:

    def GET(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self, scope, did):
        """
        Create a new data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope: Create the data identifier within this scope.
        :param did: Create the data identifier with this name.
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
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_identifier(scope=scope, did=did, sources=sources, issuer=auth['account'])
        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except Exception, e:
            print e
            raise InternalError(e)
        raise Created()

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Content:

    def GET(self, scope, did):
        """
        Returns the contents of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope: The scope of the data identifier.
        :param did: The name of the data identifier.

        :returns: A list with the contents.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            return dumps(list_content(scope=scope, did=did))
        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Replicas:

    def POST(self, scope, did):
        raise BadRequest()

    def GET(self, scope, did):
        """
        List all replicas for a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionary containing all replicas information.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            return dumps(list_replicas(scope=scope, did=did))
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


class Files:

    def POST(self, scope, did):
        raise BadRequest()

    def GET(self, scope, did):
        """ List all replicas of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionary containing all replicas information.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            return dumps(list_files(scope=scope, did=did))
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


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
