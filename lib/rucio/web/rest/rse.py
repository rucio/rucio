#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012


from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, data, header, BadRequest,\
    Created, InternalError, OK

from rucio.api.rse import add_rse, list_rses, del_rse, add_rse_tag,\
    list_rse_tags, add_file_replica
from rucio.common.exception import Duplicate, AccountNotFound, AccessDenied, RSENotFound
from rucio.common.utils import generate_http_error
from rucio.core.authentication import validate_auth_token

logger = getLogger("rucio.rse")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/', 'RSE',
    '/(.+)/tags', 'Tags',
    '/(.+)/files', 'Files',
)


class RSE:
    """ create, update, get and disable rucio location. """

    def POST(self):
        """ create rse with given location name.

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

        json_data = data()

        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            rseName = parameter['rse']
        except KeyError, e:
            if e.args[0] == 'rseName':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
                raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_rse(rse=rseName, issuer=auth['account'])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def GET(self):
        """ list all RSEs.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A list containing all RSEs.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        return dumps(list_rses())

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self, rseName):
        """ disable rse with given account name.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :param rseName: RSE name.
        """

        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            del_rse(rse=rseName, issuer=auth['account'])
        except AccountNotFound, e:
            raise generate_http_error(404, 'RSENotFound', e.args[0][0])

        raise OK()


class Tags:
    """ create, update, get and disable RSE tag."""

    def POST(self, rse):
        """ create rse with given RSE name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad request
            401 Unauthorized
            500 Internal Error

        :param rse: RSE name.

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
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        description = None
        try:
            tag = parameter['tag']
            if 'description' in tag:
                description = parameter['description']
        except KeyError, e:
            if e.args[0] == 'tag':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
                raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_rse_tag(rse=rse, tag=tag, description=description, issuer=auth['account'])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def GET(self, rse):
        """ list all RSE tags for a RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param rse: RSE name.

        :returns: A list containing all RSE tags.
        """
        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        return dumps(list_rse_tags(filters={'rse': rse}))

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self, rseName):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Files:
    def POST(self, rseName):
        """ create a file replica with given RSE name.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param rse: RSE name.

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
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            scope = parameter['scope']
            lfn = parameter['lfn']
        except KeyError, e:
            if e.args[0] == 'scope' or e.args[0] == 'lfn':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
                raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_file_replica(rse=rseName, scope=scope, lfn=lfn, issuer=auth['account'])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
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
