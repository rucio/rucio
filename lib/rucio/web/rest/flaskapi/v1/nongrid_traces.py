# -*- coding: utf-8 -*-
# Copyright 2015-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2015-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import time
from typing import TYPE_CHECKING

from flask import Flask, Blueprint, request
from werkzeug.datastructures import Headers

from rucio.core.nongrid_trace import trace
from rucio.web.rest.flaskapi.v1.common import response_headers, ErrorHandlingMethodView, json_parameters

if TYPE_CHECKING:
    from typing import Optional
    from rucio.web.rest.flaskapi.v1.common import HeadersType


class XAODTrace(ErrorHandlingMethodView):

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        return headers

    def post(self):
        """
        Trace endpoint used by the XAOD framework to post data access information.

        .. :quickref: XAODTrace; Send XAOD trace.

        :<json dict payload: Dictionary contain the trace information.
        :status 201: Created.
        :status 400: Cannot decode json data.
        """
        headers = self.get_headers()

        parameters = json_parameters()

        # generate entry timestamp
        parameters['timeentry'] = int(time.time())

        # guess client IP
        parameters['ip'] = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        trace(payload=parameters)

        return 'Created', 201, headers


def blueprint():
    bp = Blueprint('nongrid_traces', __name__, url_prefix='/nongrid_traces')

    xaod_trace_view = XAODTrace.as_view('xaod_trace')
    bp.add_url_rule('/', view_func=xaod_trace_view, methods=['post', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
