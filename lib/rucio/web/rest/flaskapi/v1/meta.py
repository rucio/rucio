# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from json import loads
from traceback import format_exc

from flask import Flask, Blueprint, request, jsonify
from flask.views import MethodView

from rucio.api.meta import add_key, add_value, list_keys, list_values
from rucio.common.exception import Duplicate, InvalidValueForKey, KeyNotFound, UnsupportedValueType, RucioException, UnsupportedKeyType
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask


class Meta(MethodView):
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
        :status 500: Internal Error.
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
        :status 500: Internal Error.
        """
        json_data = request.data.decode()
        try:
            params = json_data and loads(json_data)
            if params and 'value_type' in params:
                value_type = params['value_type']
            if params and 'value_regexp' in params:
                value_regexp = params['value_regexp']
            if params and 'key_type' in params:
                key_type = params['key_type']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_key(key=key, key_type=key_type, value_type=value_type, value_regexp=value_regexp, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except UnsupportedValueType as error:
            return generate_http_error_flask(400, 'UnsupportedValueType', error.args[0])
        except UnsupportedKeyType as error:
            return generate_http_error_flask(400, 'UnsupportedKeyType', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return 'Created', 201


class Values(MethodView):
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
        :status 500: Internal Error.
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
        :status 500: Internal Error.
        """
        json_data = request.data
        try:
            params = loads(json_data)
            value = params['value']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_value(key=key, value=value, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except InvalidValueForKey as error:
            return generate_http_error_flask(400, 'InvalidValueForKey', error.args[0])
        except KeyNotFound as error:
            return generate_http_error_flask(404, 'KeyNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

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
