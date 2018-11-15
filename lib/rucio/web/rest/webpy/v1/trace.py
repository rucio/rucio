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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import print_function
import calendar
import datetime
import json
import traceback
import uuid

from web import application, ctx, data, header, InternalError, Created

from rucio.common.utils import generate_http_error
from rucio.core.trace import trace
from rucio.web.rest.common import RucioController

URLS = (
    '/', 'Trace',
)


class Trace(RucioController):

    def POST(self):

        header('Content-Type', 'application/octet-stream')
        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        try:
            payload = json.loads(data())

            # generate entry timestamp
            payload['traceTimeentry'] = datetime.datetime.utcnow()
            payload['traceTimeentryUnix'] = calendar.timegm(payload['traceTimeentry'].timetuple()) + payload['traceTimeentry'].microsecond / 1e6

            # guess client IP
            payload['traceIp'] = ctx.env.get('HTTP_X_FORWARDED_FOR')
            if payload['traceIp'] is None:
                payload['traceIp'] = ctx.ip  # quand meme, cela peut etre None aussi

            # generate unique ID
            payload['traceId'] = str(uuid.uuid4()).replace('-', '').lower()

            trace(payload=payload)

        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')
        except Exception as error:
            print(traceback.format_exc())
            raise InternalError(error)

        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
application = APP.wsgifunc()
