#!/usr/bin/env python
# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc
from web import application, ctx, loadhook, header, InternalError

from rucio.api.did import list_archive_content
from rucio.common.schema import get_schema_value
from rucio.web.rest.common import rucio_loadhook, RucioController, check_accept_header_wrapper

LOGGER, SH = getLogger("rucio.meta"), StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('%s/files' % get_schema_value('SCOPE_NAME_REGEXP'), 'Archive')


class Archive(RucioController):
    """ REST APIs for archive. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """
        List archive content keys.

        HTTP Success:
            200 Success
        HTTP Error:
            406 Not Acceptable
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for file in list_archive_content(scope=scope, name=name, vo=ctx.env.get('vo')):
                yield dumps(file) + '\n'
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
