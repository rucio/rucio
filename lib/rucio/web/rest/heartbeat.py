#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015

import json

from logging import getLogger, StreamHandler, DEBUG

from web import application, ctx, loadhook, header

from rucio.api.heartbeat import list_heartbeats
from rucio.common.utils import APIEncoder
from rucio.web.rest.common import rucio_loadhook, RucioController, exception_wrAPPer


LOGGER = getLogger("rucio.heartbeat")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('', 'Heartbeat')


class Heartbeat(RucioController):
    """ REST API for Heartbeats. """

    @exception_wrAPPer
    def GET(self):
        """
        List all heartbeats.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
        """

        header('Content-Type', 'application/json')

        return json.dumps(list_heartbeats(issuer=ctx.env.get('issuer')),
                          cls=APIEncoder)

"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
