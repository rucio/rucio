#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012


from json import dumps, loads
from traceback import format_exc
from web import application, ctx, data, header, BadRequest, Created, InternalError, OK

from rucio.api.authentication import validate_auth_token
from rucio.api.rse import add_rse, list_rses, del_rse, add_rse_attribute, list_rse_attributes, del_rse_attribute, add_file_replica
from rucio.common.exception import Duplicate, AccessDenied, RSENotFound, RucioException, InvalidObject
from rucio.common.utils import generate_http_error

urls = (
    '/(.+)/attr/', 'Attributes',
    '/(.+)/attr/(.+)', 'Attributes',
    '/(.+)/files/(.+)/(.+)', 'Files',
    '/', 'RSE',
    '/(.+)', 'RSE',
)


class RSE:
    """ Create, update, get and disable location. """

    def POST(self, rse):
        """ Create RSE with given location name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad request
            401 Unauthorized
            500 Internal Error

        """
        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        prefix, deterministic, volatile = None, True, False
        json_data = data()
        try:
            parameter = json_data and loads(json_data)
            if parameter and 'prefix' in parameter:
                prefix = parameter['prefix']
            if parameter and 'deterministic' in parameter:
                deterministic = parameter['deterministic']
            if parameter and 'volatile' in parameter:
                volatile = parameter['volatile']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            add_rse(rse, prefix=prefix, deterministic=deterministic, volatile=volatile, issuer=auth['account'])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except InvalidObject, e:
            raise generate_http_error(400, 'InvalidObject', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise Created()

    def GET(self):
        """ List all RSEs.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A list containing all RSEs.
        """

        header('Content-Type', 'application/json')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        return dumps(list_rses())

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self, rse):
        """ Disable RSE with given account name.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :param rse: RSE name.
        """

        header('Content-Type', 'application/octet-stream')

        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            del_rse(rse=rse, issuer=auth['account'])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e.args[0][0])
        except AccessDenied, e:
            print e
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])

        raise OK()


class Attributes:
    """ Create, update, get and disable RSE attribute."""

    def POST(self, rse, key):
        """ create rse with given RSE name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad request
            401 Unauthorized
            500 Internal Error

        :param rse: RSE name.
        :param key: Key attribute.

        """
        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        json_data = data()

        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            value = parameter['value']
        except KeyError, e:
            raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))

        try:
            add_rse_attribute(rse=rse, key=key, value=value, issuer=auth['account'])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def GET(self, rse):
        """ list all RSE attributes for a RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param rse: RSE name.

        :returns: A list containing all RSE attributes.
        """
        header('Content-Type', 'application/octet-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        return dumps(list_rse_attributes(rse))

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self, rse, key):
        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            del_rse_attribute(rse=rse, key=key, issuer=auth['account'])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        raise OK()


class Files:

    def POST(self, rse, scope, name):
        """
        Create a file replica at a given RSE.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param rse: The RSE name.
        :param scope: the name of the scope.
        :param name: the data identifier name.
        :param size: the size of the file.
        :param checksum: the checksum of the file.

        """
        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        json_data = data()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            size = parameter['size']
            checksum = parameter['checksum']
            dsn = parameter['dsn']
            pfn = parameter['pfn']
        except KeyError, e:
            if e.args[0] == 'size' or e.args[0] == 'checksum' or e.args[0] == 'dsn':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'Body must be a json dictionary')

        try:
            add_file_replica(rse=rse, scope=scope, name=name, size=size, checksum=checksum, pfn=pfn, dsn=dsn, issuer=auth['account'])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def GET(self):
        raise BadRequest()

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
