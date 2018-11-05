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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2015-2018
# - Mario Lassnig <mario.lassnig>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import print_function
import json
import time
import traceback

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.common.utils import generate_http_error_flask
from rucio.core.nongrid_trace import trace
from rucio.web.rest.flaskapi.v1.common import after_request


class XAODTrace(MethodView):

    def post(self):
        """
        Trace endpoint used by the XAOD framework to post data access information.

        .. :quickref: XAODTrace; Send XAOD trace.

        :<json dict payload: Dictionary contain the trace information.
        :status 201: Created.
        :status 400: Cannot decode json data.
        :status 500: Internal Error.
        """
        try:
            payload = json.loads(request.data)

            # generate entry timestamp
            payload['timeentry'] = int(time.time())

            # guess client IP
            payload['ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
            if payload['ip'] is None:
                payload['ip'] = request.remote_addr

            trace(payload=payload)

        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json data')
        except Exception as error:
            print(traceback.format_exc())
            return error, 500

        return "Created", 201


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('nongrid_trace', __name__)

xaod_trace_view = XAODTrace.as_view('xaod_trace')
bp.add_url_rule('/', view_func=xaod_trace_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/nongrid_traces')
    return doc_app


if __name__ == "__main__":
    application.run()
