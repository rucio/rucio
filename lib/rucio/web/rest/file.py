#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013

from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, header, BadRequest

from rucio.api.authentication import validate_auth_token
from rucio.api.file import list_file_replicas
from rucio.common.utils import generate_http_error

logger = getLogger("rucio.rest.file")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/(.*)/(.*)/rses', 'Replicas',
)


class Replicas:

    def POST(self):
        raise BadRequest()

    def GET(self, scope, lfn):
        """ List file replicas.

        :param scope: The scope of the file
        :param lfn: The name of the file

        :returns: (HTTP Success: 200)
        """
        header('Content-Type', 'application/json')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        return dumps(list_file_replicas(scope=scope, lfn=lfn))

    def PUT(self):
        raise BadRequest()

    def DELETE(self):
        raise BadRequest()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
