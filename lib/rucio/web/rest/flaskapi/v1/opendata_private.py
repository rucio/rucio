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

from flask import Flask, request

from rucio.common.exception import OpenDataDataIdentifierAlreadyExists, OpenDataDataIdentifierNotFound
from rucio.common.utils import render_json
from rucio.gateway import opendata
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, \
    generate_http_error_flask, json_parameters, param_get, parse_scope_name, response_headers, try_stream


class OpenDataPrivateView(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(["application/json"])
    def get(self):
        print(f"OpenDataPrivateView.get() called")
        try:
            limit = request.args.get("limit", default=None)
            offset = request.args.get("offset", default=None)
            state = request.args.get("state", default=None)
            print(f"limit: {limit}, offset: {offset}, state: {state}")
            result = opendata.list_opendata_dids(limit=limit, offset=offset, state=state)
            print(f"result: {result}")
            return try_stream(result)
        except ValueError as error:
            return generate_http_error_flask(400, error)


class OpenDataPrivateDIDsView(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self, scope: str, name: str):
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo"))
            state = request.args.get("state", default=None)
            result = opendata.get_opendata_did(scope=scope, name=name, state=state, vo=request.environ.get("vo"))
            result = render_json(**result)
            return result
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except OpenDataDataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self, scope: str, name: str):
        print(f"OpenDataPrivateDIDsView.post() called")
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo"))
            opendata.add_opendata_did(scope=scope, name=name, vo=request.environ.get("vo"))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (OpenDataDataIdentifierNotFound, OpenDataDataIdentifierAlreadyExists) as error:
            return generate_http_error_flask(404, error)

        return "Created", 201

    def put(self, scope: str, name: str):
        print(f"OpenDataPrivateDIDsView.put() called")
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo"))
            parameters = json_parameters()
            state = param_get(parameters, 'state', default=None)
            opendata_json = param_get(parameters, 'opendata_json', default=None)
            opendata.update_opendata_did(scope=scope, name=name, state=state, opendata_json=opendata_json,
                                         vo=request.environ.get("vo"))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        return "", 200

    def delete(self, scope: str, name: str):
        print(f"OpenDataPrivateDIDsView.delete() called")
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo"))
            opendata.delete_opendata_did(scope=scope, name=name, vo=request.environ.get("vo"))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        # Handle open data exception

        return "", 200


def blueprint():
    bp = AuthenticatedBlueprint("opendata_private", __name__, url_prefix="/opendata-private")

    opendata_private_view = OpenDataPrivateView.as_view("opendata")
    bp.add_url_rule("", view_func=opendata_private_view, methods=["get"])

    opendata_private_did_view = OpenDataPrivateDIDsView.as_view("opendata_did")
    bp.add_url_rule("/<scope>/<name>", view_func=opendata_private_did_view, methods=["get", "post", "put", "delete"])

    bp.after_request(response_headers)

    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
