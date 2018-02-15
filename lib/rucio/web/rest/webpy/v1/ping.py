#!/usr/bin/env python
''' Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
 - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
'''

from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, header

from rucio import version
from rucio.web.rest.common import RucioController

LOGGER = getLogger("rucio.rucio")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('/?$', 'Ping')


class Ping(RucioController):
    '''
    Ping class
    '''

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


# ----------------------
#   Web service startup
# ----------------------

APP = application(URLS, globals())
application = APP.wsgifunc()
