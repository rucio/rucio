#!/usr/bin/env python
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

import json

from logging import getLogger, StreamHandler, DEBUG

from web import application, ctx, loadhook, header

from rucio.api import request
from rucio.common.schema import SCOPE_NAME_REGEXP
from rucio.common.utils import generate_http_error, APIEncoder
from rucio.web.rest.common import rucio_loadhook, RucioController, exception_wrapper, check_accept_header_wrapper


LOGGER = getLogger("rucio.request")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('%s/(.+)' % SCOPE_NAME_REGEXP, 'RequestGet',)


class RequestGet(RucioController):
    """ REST API to get requests. """

    @exception_wrapper
    @check_accept_header_wrapper(['application/json'])
    def GET(self, scope, name, rse):
        """
        List request for given DID to a destination RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Request Not Found
            406 Not Acceptable
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

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
