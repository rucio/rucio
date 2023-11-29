# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from typing import TYPE_CHECKING

from flask import Flask, Blueprint, jsonify, request
from werkzeug.datastructures import Headers

from rucio import version
from rucio.web.rest.flaskapi.v1.common import response_headers, check_accept_header_wrapper_flask, \
    ErrorHandlingMethodView

if TYPE_CHECKING:
    from typing import Optional
    from rucio.web.rest.flaskapi.v1.common import HeadersType


class Ping(ErrorHandlingMethodView):

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')
        return headers

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        ---
        summary: Ping
        description: Ping the server and get data about it.
        tags:
          - Ping
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    version:
                      description: The server version.
                      type: string
          406:
            description: Not acceptable
        """
        headers = self.get_headers()
        response = jsonify(version=version.version_string())
        response.headers.extend(headers)
        return response


def blueprint(standalone=False, with_doc=False):
    bp = Blueprint('ping', __name__, url_prefix='/' if standalone else '/ping')

    ping_view = Ping.as_view('ping')
    if not with_doc:
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('', view_func=ping_view, methods=['get', ])
    bp.add_url_rule('/', view_func=ping_view, methods=['get', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
