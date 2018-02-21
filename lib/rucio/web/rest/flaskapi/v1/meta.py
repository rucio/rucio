#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012, 2018
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017


from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG
from flask import Flask, Blueprint, request, Response
from flask.views import MethodView

from rucio.api.meta import add_key, add_value, list_keys, list_values
from rucio.common.exception import Duplicate, InvalidValueForKey, KeyNotFound, UnsupportedValueType, RucioException
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import before_request, after_request


LOGGER = getLogger("rucio.meta")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('/(.+)/(.+)', 'Values',
        '/(.+)/', 'Values',
        '/(.+)', 'Meta',
        '/', 'Meta',)


class Meta(MethodView):
    """ REST APIs for data identifier attribute keys. """

    def get(self):
        """
        List all data identifier keys.

        .. :quickref: Meta; List all keys.

        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        :returns: List of all DID keys.
        """
        return Response(dumps(list_keys()), content_type="application/json")

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
        json_data = request.data
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
            add_key(key=key, key_type=key_type, value_type=value_type, value_regexp=value_regexp, issuer=request.environ.get('issuer'))
        except Duplicate, e:
            return generate_http_error_flask(409, 'Duplicate', e[0][0])
        except UnsupportedValueType, e:
            return generate_http_error_flask(400, 'UnsupportedValueType', e[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            return e, 500

        return "Created", 201


class Values(MethodView):
    """ REST APIs for data identifier attribute values. """

    def get(self, key):
        """
        List all values for a key.

        .. :quickref: Values; List all key values.

        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        :returns: List of all key values.
        """
        return Response(dumps(list_values(key=key)), content_type="application/json")

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
            add_value(key=key, value=value, issuer=request.environ.get('issuer'))
        except Duplicate, e:
            return generate_http_error_flask(409, 'Duplicate', e[0][0])
        except InvalidValueForKey, e:
            return generate_http_error_flask(400, 'InvalidValueForKey', e[0][0])
        except KeyNotFound, e:
            return generate_http_error_flask(404, 'KeyNotFound', e[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            return e, 500

        return "Created", 201


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('meta', __name__)

meta_view = Meta.as_view('meta')
bp.add_url_rule('/', view_func=meta_view, methods=['get', ])
bp.add_url_rule('/<key>', view_func=meta_view, methods=['post', ])
values_view = Values.as_view('values')
bp.add_url_rule('/<key>/', view_func=values_view, methods=['get', 'post'])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/meta')
    return doc_app


if __name__ == "__main__":
    application.run()
