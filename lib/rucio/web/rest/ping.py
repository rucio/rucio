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
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, header

from rucio import version
from rucio.web.rest.common import RucioController

logger = getLogger("rucio.rucio")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/?$', 'Ping')


class Ping(RucioController):
    def GET(self):
        """
        .. http:get:: /ping

            Get server version information.

            **Example request**:

            .. sourcecode:: http

                GET /ping HTTP/1.1
                Host: rucio-server.com
                Accept: application/json

            **Example response**:

            .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: application/json

             {
               "version": "0.2.9"
              }

            :statuscode 200: no error
            :statuscode 500: InternalError
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        header('Content-Type', 'application/json')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        return dumps({"version": version.version_string()})


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
