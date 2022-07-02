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

import json

from flask import Flask, Blueprint, Response, request

from rucio.api.heartbeat import list_heartbeats, create_heartbeat
from rucio.common.utils import APIEncoder
from rucio.common.exception import UnsupportedValueType, UnsupportedKeyType, KeyNotFound, AccessDenied
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    ErrorHandlingMethodView, json_parameters, param_get, generate_http_error_flask


class Heartbeat(ErrorHandlingMethodView):
    """ REST API for Heartbeats. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        ---
        summary: List
        description: List all heartbeats.
        tags:
          - Heartbeat
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    description: List of tuples [('Executable', 'Hostname', ...), ...]
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
        """
        return Response(json.dumps(list_heartbeats(issuer=request.environ.get('issuer'), vo=request.environ.get('vo')), cls=APIEncoder), content_type='application/json')

    def post(self):
        """
        ---
        summary: Create
        tags:
          - Heartbeat
        requestBody:
          content:
            'application/json':
              shema:
                type: object
                required:
                - bytes
                properties:
                  executable:
                    description: Name of the executable.
                    type: string
                  hostname:
                    description: Name of the host.
                    type: string
                  pid:
                    description: UNIX Process ID as a number, e.g., 1234.
                    type: integer
                  older_than:
                    description: Ignore specified heartbeats older than specified nr of seconds.
                    type: integer
                  payload:
                    description: Payload identifier which can be further used to identify the work a certain thread is executing.
                    type: string
        responses:
          200:
            description: OK
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Key not found.
        """
        parameters = json_parameters()
        try:
            create_heartbeat(
                executable=param_get(parameters, 'executable'),
                hostname=param_get(parameters, 'hostname'),
                pid=param_get(parameters, 'pid'),
                older_than=param_get(parameters, 'older_than', default=None),
                payload=param_get(parameters, 'payload', default=None),
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
            )
        except (UnsupportedValueType, UnsupportedKeyType) as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except KeyNotFound as error:
            return generate_http_error_flask(404, error)


def blueprint():
    bp = Blueprint('heartbeats', __name__, url_prefix='/heartbeats')

    heartbeat_view = Heartbeat.as_view('heartbeat')
    bp.add_url_rule('', view_func=heartbeat_view, methods=['get', 'post'])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
