#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2015

import json
import time
import traceback

from web import application, ctx, data, header, InternalError, Created

from rucio.common.utils import generate_http_error
from rucio.core.nongrid_trace import trace
from rucio.web.rest.common import RucioController

urls = (
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
        except Exception, e:
            print traceback.format_exc()
            raise InternalError(e)

        raise Created()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
