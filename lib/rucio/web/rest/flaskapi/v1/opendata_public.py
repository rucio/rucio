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

from flask import Blueprint, Flask, Response

from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, response_headers
from rucio.web.rest.flaskapi.v1.opendata import OpenDataDIDsView, OpenDataView


class OpenDataPublicView(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self) -> "Response":
        return OpenDataView.get_helper(public=True)


class OpenDataPublicDIDsView(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self, scope: str, name: str) -> "Response":
        return OpenDataDIDsView.get_helper(scope=scope, name=name, public=True)


def blueprint() -> "Blueprint":
    bp = Blueprint("opendata_public", __name__, url_prefix="/public/opendata")

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
