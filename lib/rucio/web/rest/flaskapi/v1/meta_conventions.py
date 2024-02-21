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

from flask import Flask, request, jsonify

from rucio.api.meta_conventions import add_key, add_value, list_keys, list_values
from rucio.common.exception import Duplicate, InvalidValueForKey, KeyNotFound, UnsupportedValueType, UnsupportedKeyType
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, response_headers, \
    generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class MetaConventions(ErrorHandlingMethodView):
    """ REST APIs for managing data identifier attribute metadata key formats. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        ---
        summary: List all data identifier keys.
        tags:
            - Meta
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  descripton: List of all DID keys.
                  items:
                    type: string
                    description: Data Itentifier key
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
        """
        return jsonify(list_keys())

    def post(self, key):
        """
        ---
        summary: Create key
        description: Creates a new allowed key (value is NULL).
        tags:
            - Meta
        parameters:
        - name: key
          in: path
          description: The name of the key.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  key_type:
                    description: The key tpye.
                    type: string
                  value_type:
                    description: The value type.
                    type: string
                  value_regexp:
                    description: The value regexpression.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          400:
            description: Cannot decode json parameter list / Unsupported value type.
          401:
            description: Invalid Auth Token.
          409:
            description: Key already exists.
        """
        parameters = json_parameters()

        try:
            add_key(
                key=key,
                key_type=param_get(parameters, 'key_type', default=None),
                value_type=param_get(parameters, 'value_type', default=None),
                value_regexp=param_get(parameters, 'value_regexp', default=None),
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
            )
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except (UnsupportedValueType, UnsupportedKeyType) as error:
            return generate_http_error_flask(400, error)

        return 'Created', 201


class Values(ErrorHandlingMethodView):
    """ REST APIs for data identifier attribute values. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, key):
        """
        ---
        summary: Get value for key
        description: List all values for a key.
        tags:
            - Meta
        parameters:
        - name: key
          in: path
          description: The reference key.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: List of all key values.
                  type: array
                  items:
                    type: string
                    description: A value associated with a key.
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
        """
        return jsonify(list_values(key=key))

    def post(self, key):
        """
        ---
        summary: Create value for key
        description: Creates a new value for a key.
        tags:
            - Meta
        parameters:
        - name: key
          in: path
          description: The reference key.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - value
                properties:
                  value:
                    description: The new value associated with a key.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          400:
            description: Cannot decode json parameter list / Invalid value for key.
          401:
            description: Invalid Auth Token
          404:
            description: Key not found
          409:
            description: Value already exists.
        """
        parameters = json_parameters()
        value = param_get(parameters, 'value')

        try:
            add_value(key=key, value=value, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except InvalidValueForKey as error:
            return generate_http_error_flask(400, error)
        except KeyNotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201


def blueprint():
    bp = AuthenticatedBlueprint('meta_conventions', __name__, url_prefix='/meta_conventions')

    meta_view = MetaConventions.as_view('meta_conventions')
    bp.add_url_rule('/', view_func=meta_view, methods=['get', ])
    bp.add_url_rule('/<key>', view_func=meta_view, methods=['post', ])
    values_view = Values.as_view('values')
    bp.add_url_rule('/<key>/', view_func=values_view, methods=['get', 'post'])

    bp.after_request(response_headers)
    return bp


def blueprint_legacy():
    # TODO: Remove in 38.0
    bp = AuthenticatedBlueprint('meta', __name__, url_prefix='/meta')

    meta_view = MetaConventions.as_view('meta')
    bp.add_url_rule('/', view_func=meta_view, methods=['get', ])
    bp.add_url_rule('/<key>', view_func=meta_view, methods=['post', ])
    values_view = Values.as_view('values')
    bp.add_url_rule('/<key>/', view_func=values_view, methods=['get', 'post'])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)

    doc_app.register_blueprint(blueprint())
    doc_app.register_blueprint(blueprint_legacy())

    return doc_app
