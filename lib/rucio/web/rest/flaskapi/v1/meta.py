# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2021
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from flask import Flask, Blueprint, request, jsonify

from rucio.api.meta import add_key, add_value, list_keys, list_values
from rucio.common.exception import Duplicate, InvalidValueForKey, KeyNotFound, UnsupportedValueType, UnsupportedKeyType
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, request_auth_env, response_headers, \
    generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class Meta(ErrorHandlingMethodView):
    """ REST APIs for data identifier attribute keys. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        List all data identifier keys.

        .. :quickref: Meta; List all keys.

        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :returns: List of all DID keys.
        """
        return jsonify(list_keys())

    def post(self, key):
        """
        Create a new allowed key (value is NULL).

        .. :quickref: Meta; Create new key.

        :<json dict parameter: Dictionary with 'value_type', 'value_regexp' and 'key_type'.
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 400: Unsupported Value Type.
        :status 401: Invalid Auth Token.
        :status 409: Key already exists.
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
        List all values for a key.

        .. :quickref: Values; List all key values.

        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :returns: List of all key values.
        """
        return jsonify(list_values(key=key))

    def post(self, key):
        """
        Create a new value for a key.

        .. :quickref: Values; Create new value.

        :<json dict parameter: Dictionary with 'value'.
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 400: Invalid Value For Key.
        :status 401: Invalid Auth Token.
        :status 404: Key Not Found.
        :status 409: Value already exists.
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
    bp = Blueprint('meta', __name__, url_prefix='/meta')

    meta_view = Meta.as_view('meta')
    bp.add_url_rule('/', view_func=meta_view, methods=['get', ])
    bp.add_url_rule('/<key>', view_func=meta_view, methods=['post', ])
    values_view = Values.as_view('values')
    bp.add_url_rule('/<key>/', view_func=values_view, methods=['get', 'post'])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
