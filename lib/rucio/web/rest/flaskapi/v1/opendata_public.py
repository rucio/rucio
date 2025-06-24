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
        """
        ---
        summary: List Opendata DIDs marked as public
        description: "Retrieves a list of public Opendata Data Identifiers (DIDs). Supports optional query parameters for pagination."
        tags:
          - Opendata
        parameters:
          - name: limit
            in: query
            description: "Maximum number of results to return."
            schema:
              type: integer
            required: false
            style: form
          - name: offset
            in: query
            description: "Number of items to skip before starting to collect the result set."
            schema:
              type: integer
            required: false
            style: form
        responses:
          200:
            description: "Successful retrieval of the list of Opendata DIDs."
            content:
              application/json:
                schema:
                  type: object
          401:
            description: "Access denied: Invalid authentication."
          400:
            description: "Invalid request or query parameters."
        """
        return OpenDataView.get_helper(public=True)


class OpenDataPublicDIDsView(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self, scope: str, name: str) -> "Response":
        """
        ---
        summary: Get Opendata DID Information for public Opendata DIDs
        description: "Retrieves detailed Opendata information for the given scope and name. Only works for public opendata DIDs. Supports optional query parameters to control the inclusion of files, metadata, and DOI information."
        Tags:
          - Opendata
        parameters:
          - name: scope
            in: path
            description: "The scope of the data identifier."
            schema:
              type: string
            required: true
            style: simple
          - name: name
            in: path
            description: "The name of the data identifier."
            schema:
              type: string
            required: true
            style: simple
          - name: files
            in: query
            description: "Whether to include the list of files. '1' to include, '0' to exclude. Default is '0'."
            schema:
              type: string
              enum: ['0', '1']
            required: false
            style: form
          - name: meta
            in: query
            description: "Whether to include metadata. '1' to include, '0' to exclude. Default is '0'."
            schema:
              type: string
              enum: ['0', '1']
            required: false
            style: form
          - name: doi
            in: query
            description: "Whether to include the Digital Object Identifier (DOI). '1' to include, '0' to exclude. Default is '1'."
            schema:
              type: string
              enum: ['0', '1']
            required: false
            style: form
        responses:
          200:
            description: "Successful retrieval of Opendata DID information."
            content:
              application/json:
                schema:
                  type: object
          401:
            description: "Access denied: Invalid authentication."
          404:
            description: "Data Identifier not found."
          400:
            description: "Invalid request or input parameters."
        """

        return OpenDataDIDsView.get_helper(scope=scope, name=name, public=True)


def blueprint() -> "Blueprint":
    bp = Blueprint("opendata_public", __name__, url_prefix="/opendata/public")

    opendata_public_view = OpenDataPublicView.as_view("opendata")
    bp.add_url_rule("/dids", view_func=opendata_public_view, methods=["get"])

    opendata_private_did_view = OpenDataPublicDIDsView.as_view("opendata_did")
    bp.add_url_rule("/dids/<scope>/<name>", view_func=opendata_private_did_view, methods=["get"])

    bp.after_request(response_headers)

    return bp


def make_doc() -> "Flask":
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
