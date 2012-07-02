#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import json
import logging
import web

from rucio.api import location as location_api
from rucio.core.authentication import validate_auth_token
from rucio.common import exception as r_exception

logger = logging.getLogger("rucio.location")
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)

urls = (
    '/(.+)', 'Location',
    '/', 'LocationList'
)


class Location:
    """ create, update, get and disable rucio location. """

    def POST(self, Location):
        """ create rse with given location name.

        HTTP Success:
            201 Created

        HTTP Error:
            500 Internal Error

        :param Rucio-Account: Location identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        """

        web.header('Content-Type', 'application/octet-stream')

        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise web.Unauthorized()

        try:
            location_api.add_location(Location)
        except r_exception.Duplicate, e:
            raise web.InternalError(e)
        except Exception, e:
            raise web.InternalError(e)

        raise web.Created()


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

        web.header('Content-Type', 'application/json')

        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise web.Unauthorized()

        return json.dumps(location_api.list_locations())

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
