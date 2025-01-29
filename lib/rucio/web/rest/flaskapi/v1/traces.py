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


import calendar
import datetime
import json
import uuid
from typing import TYPE_CHECKING, Union

from flask import Blueprint, Flask, request
from werkzeug.datastructures import Headers

from rucio.core.trace import trace
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, response_headers

if TYPE_CHECKING:
    from typing import Optional

    from rucio.web.rest.flaskapi.v1.types import HeadersType


class Trace(ErrorHandlingMethodView):

    def __handle_payload_item(self, payload: dict) -> None:
        """
        Handles and processes a single trace payload item by adding various trace information.

        Args:
          payload (dict): The payload dictionary to be processed.

        Modifies:
          payload (dict): Adds the following keys to the payload:
            - 'traceTimeentry': The current UTC timestamp.
            - 'traceTimeentryUnix': The Unix timestamp with microsecond precision.
            - 'traceIp': The client's IP address, either from 'X-Forwarded-For' header or remote address.
            - 'traceId': A unique identifier for the trace, generated as a UUID without hyphens.

        Calls:
          trace(payload): A function to handle the processed payload.
        """
        # generate entry timestamp
        payload["traceTimeentry"] = datetime.datetime.utcnow()
        payload["traceTimeentryUnix"] = (
            calendar.timegm(payload["traceTimeentry"].timetuple())
            + payload["traceTimeentry"].microsecond / 1e6
        )

        # guess client IP
        payload["traceIp"] = request.headers.get(
            "X-Forwarded-For", default=request.remote_addr
        )

        # generate unique ID
        payload["traceId"] = str(uuid.uuid4()).replace("-", "").lower()
        trace(payload=payload)

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
        ---
        summary: Trace
        description: Trace endpoint used by the pilot and CLI clients to post data access information.
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
              description: A single trace object.
            - type: array
              items:
                type: object
              description: A list of trace objects.
        responses:
          201:
            description: OK
          400:
            description: Cannot decode json data.
        """
        headers = self.get_headers()
        req_body: str = request.get_data(as_text=True)
        payload: Union[list, dict, None] = json.loads(req_body) if req_body else None

        if payload is None:
            return (
                "Invalid JSON data. Please provide a single trace as a JSON object or a list of trace objects.",
                400,
                headers,
            )

        if isinstance(payload, list):
            for item in payload:
                self.__handle_payload_item(item)
        else:
            self.__handle_payload_item(payload)

        return "Created", 201, headers


def blueprint():
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
