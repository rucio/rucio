#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2015-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2015-2018
# - Mario Lassnig <mario.lassnig>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

import json
import time
import traceback

from web import application, ctx, data, header, InternalError, Created

from rucio.core.nongrid_trace import trace
from rucio.web.rest.common import RucioController
from rucio.web.rest.utils import generate_http_error

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
            payload['timeentry'] = int(time.time())

            # guess client IP
            payload['ip'] = ctx.env.get('HTTP_X_FORWARDED_FOR')
            if payload['ip'] is None:
                payload['ip'] = ctx.ip  # quand meme, cela peut etre None aussi

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
