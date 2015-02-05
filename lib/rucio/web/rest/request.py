#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014-2015

import json

from logging import getLogger, StreamHandler, DEBUG

from web import application, ctx, loadhook, header

from rucio.api import request
from rucio.common.utils import generate_http_error, APIEncoder
from rucio.web.rest.common import rucio_loadhook, RucioController, exception_wrapper


logger = getLogger("rucio.request")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/(.+)/(.+)/(.+)', 'RequestGet',)


class RequestGet(RucioController):
    """ REST API to get requests. """

    @exception_wrapper
    def GET(self, scope, name, rse):
        """
        List request for given DID to a destination RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Request Not Found
        """

        header('Content-Type', 'application/json')

        try:
            return json.dumps(request.get_request_by_did(scope=scope,
                                                         name=name,
                                                         rse=rse,
                                                         issuer=ctx.env.get('issuer')),
                              cls=APIEncoder)
        except:
            raise generate_http_error(404, 'RequestNotFound', 'No request found for DID %s:%s at RSE %s' % (scope,
                                                                                                            name,
                                                                                                            rse))

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(rucio_loadhook))
application = app.wsgifunc()
