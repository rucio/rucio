#!/usr/bin/env python3
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, header

from rucio import version
from rucio.web.rest.common import RucioController, check_accept_header_wrapper

LOGGER = getLogger("rucio.rucio")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('/?$', 'Ping')


class Ping(RucioController):
    '''
    Ping class
    '''

    @check_accept_header_wrapper(['application/json'])
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
            :statuscode 406: Not Acceptable
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
