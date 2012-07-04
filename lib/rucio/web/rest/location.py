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


from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, header, BadRequest, Created, InternalError, HTTPError, Unauthorized

from rucio.api.location import add_location, list_locations
from rucio.common.exception import Duplicate
from rucio.core.authentication import validate_auth_token

logger = getLogger("rucio.location")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/(.+)', 'Location',
    '/', 'LocationList'
)


class Location:
    """ create, update, get and disable rucio location. """

    def PUT(self, Location):
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

        try:
            add_location(Location)
        except Duplicate, e:
            status = '409 Conflict'
            headers = {'ExceptionClass': 'Duplicate', 'ExceptionMessage': e[0][0]}
            data = ' '.join(['Duplicate:', str(e)])
            raise HTTPError(status, headers=headers, data=data)
        except Exception, e:
            raise InternalError(e)

        raise Created()


class LocationList:
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

        return dumps(list_locations())

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
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
