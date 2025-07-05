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

from json.decoder import JSONDecodeError
from typing import TYPE_CHECKING

from flask import Blueprint, Flask, Response, request
from werkzeug.datastructures import Headers

from rucio.gateway.trace import trace
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, generate_http_error_flask, response_headers

if TYPE_CHECKING:
    from typing import Optional

    from rucio.web.rest.flaskapi.v1.types import HeadersType


class Trace(ErrorHandlingMethodView):

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers.set('Content-Type', 'application/octet-stream')
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')
        return headers

    def post(self) -> Response:
        """
        ---
      summary: Trace
      description: "Trace endpoint used by the pilot and CLI clients to post data access information."
      tags:
        - Trace
      parameters:
      - name: X-Forwarded-For
        in: header
        schema:
          type: string
      requestBody:
      content:
      application/json:
        schema:
          oneOf:
            - type: object
              oneOf:
                ObjectSchema:
                  - requires: [eventType, clientState, account]
                  - description: "Touch one or more DIDs"
                UploadSchema:
                  - requires: [eventType, hostname, account, eventVersion, uuid, scope, dataset, remoteSite, filesize, protocol, transferStart]
                  - description: "Upload method"
                DownloadSchema:
                  - requires: [eventType, hostname, localSite, account, eventVersion, uuid, scope, filename, dataset, filesize, clientState, stateReason]
                  - description: "Download method"
                GetSchema:
                  - requires: [eventType, localSite, eventVersion, uuid, scope, filename, dataset]
                  - description: "Get method, mainly sent by pilots"
                PutSchema:
                  - requires: [eventType, localSite, eventVersion, uuid, scope, filename, dataset]
                  - description: "Put method, mainly sent by pilots"
                SpecialSchema:
                  - requires: [eventType, clientState, account]
                  - description: "A special schema to capture most unsupported eventTypes"
            - type: array
              items:
                type: object
                oneOf:
                  ObjectSchema:
                    - requires: [eventType, clientState, account]
                    - description: "Touch one or more DIDs"
                  UploadSchema:
                    - requires: [eventType, hostname, account, eventVersion, uuid, scope, dataset, remoteSite, filesize, protocol, transferStart]
                    - description: "Upload method"
                  DownloadSchema:
                    - requires: [eventType, hostname, localSite, account, eventVersion, uuid, scope, filename, dataset, filesize, clientState, stateReason]
                    - description: "Download method"
                  GetSchema:
                    - requires: [eventType, localSite, eventVersion, uuid, scope, filename, dataset]
                    - description: "Get method, mainly sent by pilots"
                  PutSchema:
                    - requires: [eventType, localSite, eventVersion, uuid, scope, filename, dataset]
                    - description: "Put method, mainly sent by pilots"
                  SpecialSchema:
                    - requires: [eventType, clientState, account]
                    - description: "A special schema to capture most unsupported eventTypes"
      responses:
        201:
          description: "OK"
        400:
          description: "Cannot decode json data."
    """
        headers = self.get_headers()
        parameters = request.data
        if parameters is None:
            err = "Invalid JSON data. Please provide a single trace as a JSON object or a list of trace objects."
            generate_http_error_flask(400, err)

        # Trace gateway handles all errors and sends them to a log - no need for any error checking
        trace_ip = request.headers.get("X-Forwarded-For", default=request.remote_addr)
        try:
            trace(request=parameters, trace_ip=trace_ip)
            return Response("Created", 201, headers)
        except JSONDecodeError as err:
            return generate_http_error_flask(400, err)


def blueprint() -> Blueprint:
    bp = Blueprint('traces', __name__, url_prefix='/traces')

    trace_view = Trace.as_view('trace')
    bp.add_url_rule('/', view_func=trace_view, methods=['post', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
