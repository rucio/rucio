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

from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from web import application, header, BadRequest

from rucio import version

logger = getLogger("rucio.rucio")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/', 'Ping',
    '', 'Ping'
)


class Ping:
    def GET(self):
        """ List server version information.

        HTTP Success:
            200 OK

        HTTP Error:
            500 InternalError

        :returns: A dictionary with the Rucio server information.
        """

        header('Content-Type', 'application/json')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        return dumps({"version": version.version_string()})

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
