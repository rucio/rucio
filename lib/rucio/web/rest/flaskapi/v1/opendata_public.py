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

from rucio.common.exception import OpenDataDataIdentifierNotFound
from rucio.common.utils import render_json
from rucio.gateway import opendata
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, parse_scope_name, response_headers, try_stream


class OpenDataPublicView(ErrorHandlingMethodView):
    # @check_accept_header_wrapper_flask(['application/x-json-stream'])
    @check_accept_header_wrapper_flask(["application/json"])
    def get(self) -> "Response":
        print(f"OpenDataPrivateView.get() called")
        try:
            limit = request.args.get("limit", default=None)
            offset = request.args.get("offset", default=None)
            print(f"limit: {limit}, offset: {offset}")
            result = opendata.list_opendata_dids(limit=limit, offset=offset, state="P")
            # return try_stream(render_json(result))
            result = render_json(result)
            return Response(result, content_type="application/json")
        except ValueError as error:
            return generate_http_error_flask(400, error)


class OpenDataPublicDIDsView(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self, scope: str, name: str) -> "Response":
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo"))
            result = opendata.get_opendata_did(scope=scope, name=name, state="P", vo=request.environ.get("vo"))
            return Response(render_json(**result), content_type="application/json")
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except OpenDataDataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


def blueprint() -> "Blueprint":
    bp = Blueprint("opendata_public", __name__, url_prefix="/opendata")

    opendata_public_view = OpenDataPublicView.as_view("opendata")
    bp.add_url_rule("", view_func=opendata_public_view, methods=["get"])

    opendata_private_did_view = OpenDataPublicDIDsView.as_view("opendata_did")
    bp.add_url_rule("/<scope>/<name>", view_func=opendata_private_did_view, methods=["get"])

    bp.after_request(response_headers)

    return bp


def make_doc() -> "Flask":
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
