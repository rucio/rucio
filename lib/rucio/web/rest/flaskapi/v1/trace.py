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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import print_function
import calendar
import datetime
import json
import traceback
import uuid

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.common.utils import generate_http_error_flask
from rucio.core.trace import trace
from rucio.web.rest.flaskapi.v1.common import after_request

URLS = (
    '/', 'Trace',
)


class Trace(MethodView):

    def post(self):
        """
        Trace endpoint used by the pilot and CLI clients to post data access information.

        .. :quickref: Trace; Send trace.

        :<json dict payload: Dictionary contain the trace information.
        :status 201: Created.
        :status 400: Cannot decode json data.
        :status 500: Internal Error.
        """
        try:
            payload = json.loads(request.data)

            # generate entry timestamp
            payload['traceTimeentry'] = datetime.datetime.utcnow()
            payload['traceTimeentryUnix'] = calendar.timegm(payload['traceTimeentry'].timetuple()) + payload['traceTimeentry'].microsecond / 1e6

            # guess client IP
            payload['ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
            if payload['ip'] is None:
                payload['ip'] = request.remote_addr

            # generate unique ID
            payload['traceId'] = str(uuid.uuid4()).replace('-', '').lower()

            trace(payload=payload)

        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')
        except Exception as error:
            print(traceback.format_exc())
            return error, 500

        return "Created", 201


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('trace', __name__)

trace_view = Trace.as_view('trace')
bp.add_url_rule('/', view_func=trace_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/traces')
    return doc_app


if __name__ == "__main__":
    application.run()
