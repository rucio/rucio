#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import datetime
import logging
import json
import web

from rucio.api import rse
from rucio.core.authentication import validate_auth_token
from rucio.common import exception as r_exception

logger = logging.getLogger("rucio.rse")
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)

urls = (
    '/(.+)', 'RSE',
)


class RSE:
    """ create, update, get and disable rucio storage element. """

    def POST(self, RSEName):
        """ create rse with given rse name.

        HTTP Success:
            201 Created

        HTTP Error:
            500 Internal Error

        :param Rucio-Account: RSE identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        """

        web.header('Content-Type', 'application/octet-stream')

        auth_account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_account, auth_token)

        if auth is None:
            raise web.Unauthorized()

        try:
            rse.add_rse(RSEName)
        except r_exception.Duplicate, e:
            raise web.InternalError(e)
        except Exception, e:
            raise web.InternalError(e)

        raise web.Created()


"""----------------------
   Web service startup
----------------------"""

app = web.application(urls, globals())
application = app.wsgifunc()
