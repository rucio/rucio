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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from web import (application, data, header, loadhook, ctx, Created)

from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error, parse_response
from rucio.api.importer import import_data
from rucio.web.rest.common import rucio_loadhook, RucioController

URLS = (
    '/', 'Import',
    '', 'Import'
)


class Import(RucioController):
    """ Import data into Rucio """

    def POST(self):
        """ Import data into Rucio.

        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad request
            401 Unauthorized
            404 Resource not Found
            500 InternalError
        """
        header('Content-Type', 'application/x-json-stream')
        json_data = data()
        try:
            data_to_import = json_data and parse_response(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            import_data(data=data_to_import, issuer=ctx.env.get('issuer'))
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])

        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
