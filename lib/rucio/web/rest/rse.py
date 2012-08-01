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
                Created, InternalError, HTTPError, Unauthorized, OK

from rucio.api.rse import add_rse, list_rses, del_rse
from rucio.common.exception import Duplicate, AccountNotFound

from rucio.common.utils import generate_http_error
from rucio.core.authentication import validate_auth_token

logger = getLogger("rucio.rse")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)


urls = (
    '/', 'RSE',
)


class RSE:
    """ create, update, get and disable rucio location. """

    def POST(self):
        """ create rse with given location name.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param Rucio-Account: Location identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        """
        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise Unauthorized()

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
            status = '409 Conflict'
            headers = {'ExceptionClass': 'Duplicate', 'ExceptionMessage': e[0][0]}
            d = ' '.join(['Duplicate:', str(e)])
            raise HTTPError(status, headers=headers, data=d)
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def GET(self):
        """ list all rucio locations.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: A list containing all location names.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise Unauthorized()

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

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        """

        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise Unauthorized()

        try:
            del_rse(rse=rseName, who=auth['account'])
        except AccountNotFound, e:
            status = '404 Not Found'
            headers = {'ExceptionClass': 'RSENotFound', 'ExceptionMessage': e[0][0]}
            data = ' '.join(['RSENotFound:', str(e)])
            raise HTTPError(status, headers=headers, data=data)

        raise OK()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
