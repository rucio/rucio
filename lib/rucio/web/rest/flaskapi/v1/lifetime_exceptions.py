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

from json import dumps

from flask import Flask, Blueprint, Response, request

from rucio.api.lifetime_exception import list_exceptions, add_exception, update_exception
from rucio.common.exception import LifetimeExceptionNotFound, UnsupportedOperation, InvalidObject, AccessDenied, \
    LifetimeExceptionDuplicate
from rucio.common.utils import APIEncoder
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class LifetimeException(ErrorHandlingMethodView):
    """ REST APIs for Lifetime Model exception. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: List Exceptions
        description: Retrieves all exceptions.
        tags:
            - Lifetime Exceptions
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: One exception per line.
                  type: array
                  items:
                    description: A lifetime exception
                    type: object
                    properties:
                      id:
                        description: The id of the lifetime exception.
                        type: string
                      scope:
                        description: The scope associated with the lifetime exception.
                        type: string
                      name:
                        description: The name of the lifetime exception.
                        type: string
                      did_type:
                        description: The type of the did.
                        type: string
                        enum: ['F', 'D', 'C', 'A', 'X', 'Y', 'Z']
                      account:
                        description: The account accociated with the lifetime exception.
                        type: string
                      pattern:
                        description: The patter of the lifetime exception.
                        type: string
                      comments:
                        description: The comments of the lifetime exception.
                        type: string
                      state:
                        description: The state of the lifetime exception.
                        type: string
                        enum: ['A', 'R', 'W']
                      created_at:
                        description: The datetime the lifetime exception was created.
                        type: string
                      expires_at:
                        description: The datetime the lifetime exception expires.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Lifetime exception not found
          406:
            description: Not acceptable
        """
        try:
            def generate(vo):
                for exception in list_exceptions(vo=vo):
                    yield dumps(exception, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self):
        """
        ---
        summary: Create Exception
        description: Creates a Lifetime Exception.
        tags:
            - Lifetime Exceptions
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  dids:
                    description: List of dids associated with the lifetime exception.
                    type: array
                    items:
                      description: A did
                      type: object
                      properties:
                        name:
                          description: The name of the did.
                          type: string
                  pattern:
                    description: The pattern of the lifetime exception.
                    type: string
                  comments:
                    description: The comment for the lifetime exception.
                    type: string
                  expires_at:
                    description: The expiration date for the lifetime exception.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  description: The exception id.
                  type: string
          401:
            description: Invalid Auth Token
          400:
            description: Cannot decode json parameter list.
          409:
            description: Lifetime exception already exists.
        """
        parameters = json_parameters()
        try:
            exception_id = add_exception(
                dids=param_get(parameters, 'dids', default=[]),
                account=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
                pattern=param_get(parameters, 'pattern', default=None),
                comments=param_get(parameters, 'comments', default=None),
                expires_at=param_get(parameters, 'expires_at', default=None),
            )
        except InvalidObject as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except LifetimeExceptionDuplicate as error:
            return generate_http_error_flask(409, error)

        return Response(dumps(exception_id), status=201, content_type="application/json")


class LifetimeExceptionId(ErrorHandlingMethodView):
    """ REST APIs for Lifetime Model exception. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, exception_id):
        """
        ---
        summary: Get Exception
        description: Get a single Lifetime Exception.
        tags:
            - Lifetime Exceptions
        parameters:
        - name: exception_id
          in: path
          description: The id of the lifetime exception.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: List of lifetime exceptions associated with the id.
                  type: array
                  items:
                    description: A lifetime exception
                    type: object
                    properties:
                      id:
                        description: The id of the lifetime exception.
                        type: string
                      scope:
                        description: The scope associated with the lifetime exception.
                        type: string
                      name:
                        description: The name of the lifetime exception.
                        type: string
                      did_type:
                        description: The type of the did.
                        type: string
                        enum: ['F', 'D', 'C', 'A', 'X', 'Y', 'Z']
                      account:
                        description: The account associated with the lifetime exception.
                        type: string
                      pattern:
                        description: The patter of the lifetime exception.
                        type: string
                      comments:
                        description: The comments of the lifetime exception.
                        type: string
                      state:
                        description: The state of the lifetime exception.
                        type: string
                        enum: ['A', 'R', 'W']
                      created_at:
                        description: The datetime the lifetime exception was created.
                        type: string
                      expires_at:
                        description: The datetime the lifetime exception expires.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Lifetime exception not found
          406:
            description: Not acceptable
        """
        try:
            def generate(vo):
                for exception in list_exceptions(exception_id, vo=vo):
                    yield dumps(exception, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, error)

    def put(self, exception_id):
        """
        ---
        summary: Approve/Reject exception
        description: Approve/Reject a Lifetime Exception.
        tags:
            - Lifetime Exceptions
        parameters:
        - name: exception_id
          in: path
          description: The id of the Lifetime Exception.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  state:
                    description: The new state for the Lifetime Exception.
                    type: string
                    enum: ['A', 'R']
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: Invalid Auth Token
          404:
            description: Lifetime Exception not found
          400:
            description: Cannot decode json parameter list.
        """
        parameters = json_parameters()
        state = param_get(parameters, 'state', default=None)

        try:
            update_exception(exception_id=exception_id, state=state, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except UnsupportedOperation as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201


def blueprint():
    bp = Blueprint('lifetime_exceptions', __name__, url_prefix='/lifetime_exceptions')

    lifetime_exception_view = LifetimeException.as_view('lifetime_exception')
    bp.add_url_rule('/', view_func=lifetime_exception_view, methods=['get', 'post'])
    lifetime_exception_id_view = LifetimeExceptionId.as_view('lifetime_exception_id')
    bp.add_url_rule('/<exception_id>', view_func=lifetime_exception_id_view, methods=['get', 'put'])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
