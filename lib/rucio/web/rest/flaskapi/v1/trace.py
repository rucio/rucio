# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

import calendar
import datetime
import json
import traceback
import uuid

from flask import Flask, Blueprint, request
from flask.views import MethodView
from werkzeug.datastructures import Headers

from rucio.core.trace import trace
from rucio.web.rest.flaskapi.v1.common import response_headers
from rucio.web.rest.utils import generate_http_error_flask


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
        headers = Headers()
        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        try:
            payload = json.loads(request.data)

            # generate entry timestamp
            payload['traceTimeentry'] = datetime.datetime.utcnow()
            payload['traceTimeentryUnix'] = calendar.timegm(payload['traceTimeentry'].timetuple()) + payload['traceTimeentry'].microsecond / 1e6

            # guess client IP
            payload['traceIp'] = request.headers.get('X-Forwarded-For', default=request.remote_addr)

            # generate unique ID
            payload['traceId'] = str(uuid.uuid4()).replace('-', '').lower()

            trace(payload=payload)

        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list', headers=headers)
        except Exception as error:
            print(traceback.format_exc())
            return str(error), 500, headers

        return 'Created', 201, headers


def blueprint():
    bp = Blueprint('trace', __name__, url_prefix='/traces')

    trace_view = Trace.as_view('trace')
    bp.add_url_rule('/', view_func=trace_view, methods=['post', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
