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

from flask import Blueprint, Flask, Response, request

from rucio.common.exception import OpenDataDataIdentifierAlreadyExists, OpenDataDataIdentifierNotFound
from rucio.common.utils import render_json
from rucio.gateway import opendata
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, json_parameters, param_get, parse_scope_name, response_headers


class OpenDataView(ErrorHandlingMethodView):
    @staticmethod
    def get_helper(public: bool) -> "Response":
        """
        Helper function to list Open Data DIDs. To be used by both authenticated and unauthenticated views.
        """
        try:
            state = request.args.get("state", default=None) if not public else "PUBLIC"

            limit = request.args.get("limit", default=None)
            offset = request.args.get("offset", default=None)
            result = opendata.list_opendata_dids(limit=limit, offset=offset, state=state)
            result = render_json(**result)
            return Response(result, status=200, mimetype='application/json')
        except ValueError as error:
            return generate_http_error_flask(400, error)

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self) -> "Response":
        return self.get_helper(public=False)


class OpenDataDIDsView(ErrorHandlingMethodView):

    @staticmethod
    def get_helper(*, scope: str, name: str, public: bool) -> "Response":
        """
        Helper function to get Open Data DID information. To be used by both authenticated and unauthenticated views.
        """
        try:
            vo = request.environ.get("vo") if not public else "def"
            state = request.args.get("state", default=None) if not public else "PUBLIC"

            scope, name = parse_scope_name(f"{scope}/{name}", vo=vo)
            files_flag = request.args.get("files", default="1").lower() == "1"
            meta_flag = request.args.get("meta", default="0").lower() == "1"
            doi_flag = request.args.get("doi", default="1").lower() == "1"
            result = opendata.get_opendata_did(scope=scope, name=name, vo=vo,
                                               state=state,
                                               files=files_flag, meta=meta_flag, doi=doi_flag)
            result = render_json(**result)
            return Response(result, status=200, mimetype='application/json')
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except OpenDataDataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self, scope: str, name: str) -> "Response":
        return self.get_helper(scope=scope, name=name, public=False)

    def post(self, scope: str, name: str) -> "Response":
        vo = request.environ.get("vo")
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", vo=vo)
            opendata.add_opendata_did(scope=scope, name=name, vo=vo)
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (OpenDataDataIdentifierNotFound, OpenDataDataIdentifierAlreadyExists) as error:
            return generate_http_error_flask(404, error)

        return Response(status=201, mimetype='application/json')

    def put(self, scope: str, name: str) -> "Response":
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo"))
            parameters = json_parameters()
            state = param_get(parameters, 'state', default=None)
            meta = param_get(parameters, 'meta', default=None)
            doi = param_get(parameters, 'doi', default=None)
            opendata.update_opendata_did(scope=scope,
                                         name=name,
                                         state=state,
                                         meta=meta,
                                         doi=doi,
                                         vo=request.environ.get("vo"),
                                         )
        except Exception as error:
            return generate_http_error_flask(400, error)

        return Response(status=200, mimetype='application/json')

    def delete(self, scope: str, name: str) -> "Response":
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo"))
            opendata.delete_opendata_did(scope=scope, name=name, vo=request.environ.get("vo"))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        # Handle open data exception
        return Response(status=204, mimetype='application/json')


def blueprint() -> "Blueprint":
    bp = AuthenticatedBlueprint("opendata", __name__, url_prefix="/opendata")

    opendata_view = OpenDataView.as_view("opendata")
    bp.add_url_rule("", view_func=opendata_view, methods=["get"])

    opendata_did_view = OpenDataDIDsView.as_view("opendata_did")
    bp.add_url_rule("/<scope>/<name>", view_func=opendata_did_view, methods=["get", "post", "put", "delete"])

    bp.after_request(response_headers)

    return bp


def make_doc() -> "Flask":
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
