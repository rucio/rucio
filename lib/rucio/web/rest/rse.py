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
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013


from json import dumps, loads
from traceback import format_exc
from web import application, ctx, data, header, BadRequest, Created, InternalError, OK, input

from rucio.api.authentication import validate_auth_token
from rucio.api.rse import add_rse, list_rses, del_rse, add_rse_attribute, list_rse_attributes, del_rse_attribute, add_file_replica, add_protocol, get_protocols, del_protocols, update_protocols
from rucio.common.exception import Duplicate, AccessDenied, RSENotFound, RucioException, RSEOperationNotSupported, RSEProtocolNotSupported, InvalidObject
from rucio.common.utils import generate_http_error

urls = (
    '/(.+)/attr/(.+)', 'Attributes',
    '/(.+)/attr/', 'Attributes',
    '/(.+)/files/(.+)/(.+)', 'Files',
    '/(.+)/protocols/(.+)/(.+)/(.+)', 'Protocol',  # Updates (PUT) protocol attributes
    '/(.+)/protocols/(.+)/(.+)/(.+)', 'Protocol',  # delete (DELETE) a specific protocol
    '/(.+)/protocols/(.+)/(.+)', 'Protocol',  # delete (DELETE) all protocols with the same identifier and the same hostname
    '/(.+)/protocols/(.+)', 'Protocol',  # List (GET), create (POST), update (PUT), or delete (DELETE) a all protocols with the same identifier
    '/(.+)/protocols', 'Protocols',  # List all supported protocols (GET)
    '/(.+)', 'RSE',
    '/', 'RSE',
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

        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')

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
        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
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
        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
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
        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
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

        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        return dumps(list_rse_attributes(rse))

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self, rse, key):
        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
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

        """
        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')

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
            if 'md5' in parameter:
                md5 = parameter['md5']
            if 'adler32' in parameter:
                adler32 = parameter['adler32']
            dsn = parameter['dsn']
            pfn = parameter['pfn']
        except KeyError, e:
            if e.args[0] == 'size' or e.args[0] == 'dsn':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'Body must be a json dictionary')

        try:
            add_file_replica(rse=rse, scope=scope, name=name, size=size, md5=md5, adler32=adler32, pfn=pfn, dsn=dsn, issuer=auth['account'])
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


class Protocols:
    """ List supported protocols. """

    def POST(self, rse):
        """ Not supported. """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def GET(self, rse):
        """ List all supported protocols of the given RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Resource not Found
            500 InternalError

        :returns: A list containing all supported protocols and all their attributes.
        """
        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        p_list = None
        params = input()
        operation = params.operation if 'operation' in params.keys() else None
        default = params.default if 'default' in params.keys() else False
        try:
            p_list = get_protocols(rse, issuer=auth['account'], operation=operation, default=default)
        except RSEOperationNotSupported, e:
            raise generate_http_error(404, 'RSEOperationNotSupported', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RSEProtocolNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolNotSupported', e[0][0])
        except Exception, e:
            print e
            raise InternalError(e)
        return dumps(p_list)

    def PUT(self, rse):
        """ Not supported. """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self, rse):
        """ Not supported. """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Protocol:
    """ Create, Update, Read and delete a specific protocol. """

    def POST(self, rse, protocol):
        """
        Create a protocol for a given RSE.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad request
            401 Unauthorized
            404 Resource not Found
            409 Conflict
            500 Internal Error

        """
        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        json_data = data()

        try:
            parameters = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        # Fill defaults and check mandatory parameters
        parameters['protocol'] = protocol

        try:
            add_protocol(rse, issuer=auth['account'], data=parameters)
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
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

    def GET(self, rse, protocol):
        """ List all references of the provided RSE for the given protocol.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Resource not Found
            500 InternalError

        :returns: A list with detailed protocol information.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        p_list = None
        try:
            p_list = get_protocols(rse, issuer=auth['account'], protocol=protocol)
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RSEProtocolNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolNotSupported', e[0][0])
        except Exception, e:
            print e
            raise InternalError(e)
        return dumps(p_list)

    def PUT(self, rse, protocol, hostname=None, port=None):
        """
        Updates attributes of an existing protocol entry. Because protocol identifier, hostname,
        and port are used as unique identifier they are immutable.

        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Resource not Found
            500 InternalError
        """

        header('Content-Type', 'application/json')
        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        json_data = data()

        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            update_protocols(rse, issuer=auth['account'], protocol=protocol, hostname=hostname, port=port, data=parameter)
        except InvalidObject, e:
            raise generate_http_error(400, 'InvalidObject', e[0][0])
        except RSEProtocolNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolNotSupported', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise OK()

    def DELETE(self, rse, protocol, hostname=None, port=None):
        """
        Deletes a protocol entry for the provided RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Resource not Found
            500 InternalError
        """

        header('Content-Type', 'application/json')
        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            del_protocols(rse, issuer=auth['account'], protocol=protocol, hostname=hostname, port=port)
        except RSEProtocolNotSupported, e:
            raise generate_http_error(404, 'RSEProtocolNotSupported', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise OK()

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
