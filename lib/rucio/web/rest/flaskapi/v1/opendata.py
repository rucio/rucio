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

from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccessDenied, DataIdentifierNotFound, OpenDataDataIdentifierAlreadyExists, OpenDataDataIdentifierNotFound
from rucio.common.utils import render_json
from rucio.core.opendata import validate_opendata_did_state
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
            if state is not None:
                state = validate_opendata_did_state(state)

            limit = request.args.get("limit", default=None, type=int)  # type: ignore
            offset = request.args.get("offset", default=None, type=int)  # type: ignore
            result = opendata.list_opendata_dids(limit=limit, offset=offset, state=state)
            result = render_json(**result)
            return Response(result, status=200, mimetype='application/json')
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except Exception as error:
            return generate_http_error_flask(400, error)

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self) -> "Response":
        """
        ---
        summary: List Opendata DIDs
        description: "Retrieves a list of Opendata Data Identifiers (DIDs). Supports optional query parameters for pagination and filtering by state."
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
          - name: state
            in: query
            description: "Filter DIDs by their state (e.g., 'PUBLIC')."
            schema:
              type: string
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
        return self.get_helper(public=False)


class OpenDataDIDsView(ErrorHandlingMethodView):

    @staticmethod
    def get_helper(*, scope: str, name: str, public: bool) -> "Response":
        """
        Helper function to get Open Data DID information. To be used by both authenticated and unauthenticated views.
        """
        try:
            vo = request.environ.get("vo", DEFAULT_VO) if not public else DEFAULT_VO
            state = request.args.get("state", default=None) if not public else "public"
            if state is not None:
                state = validate_opendata_did_state(state)

            scope, name = parse_scope_name(f"{scope}/{name}", vo=vo)
            include_files = request.args.get("files", default="0").lower() == "1"
            include_metadata = request.args.get("meta", default="0").lower() == "1"
            include_doi = request.args.get("doi", default="1").lower() == "1"
            result = opendata.get_opendata_did(scope=scope, name=name, vo=vo,
                                               state=state,
                                               include_files=include_files,
                                               include_metadata=include_metadata,
                                               include_doi=include_doi,
                                               )

            result = render_json(**result)
            return Response(result, status=200, mimetype='application/json')
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except OpenDataDataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except Exception as error:
            return generate_http_error_flask(400, error)

    @check_accept_header_wrapper_flask(["application/json"])
    def get(self, scope: str, name: str) -> "Response":
        """
        ---
        summary: Get Opendata DID Information
        description: "Retrieves detailed Opendata information for the given scope and name. Supports optional query parameters to control the inclusion of files, metadata, and DOI information."
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
          - name: state
            in: query
            description: "Optional state filter for the data identifier."
            schema:
              type: string
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
        return self.get_helper(scope=scope, name=name, public=False)

    def post(self, scope: str, name: str) -> "Response":
        """
        ---
        summary: Register Opendata DID
        description: "Registers an existing DID as Opendata."
        tags:
          - Opendata
        parameters:
          - name: scope
            in: path
            description: "The scope of the data identifier to be registered."
            schema:
              type: string
            required: true
            style: simple
          - name: name
            in: path
            description: "The name of the data identifier to be registered."
            schema:
              type: string
            required: true
            style: simple
        responses:
          201:
            description: "Opendata DID successfully registered."
            content:
              application/json:
                schema:
                  type: string
                  enum: []
          400:
            description: "Invalid input: The provided scope/name is not valid."
          401:
            description: "Access denied: Invalid authentication."
          404:
            description: "Data Identifier not found."
          409:
            description: "Data Identifier already exists in the Opendata catalog."
        """
        vo = request.environ.get("vo", DEFAULT_VO)
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", vo=vo)
            opendata.add_opendata_did(scope=scope, name=name, vo=vo)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except OpenDataDataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, error)
        except Exception as error:
            return generate_http_error_flask(400, error)

        return Response(status=201, mimetype='application/json')

    def put(self, scope: str, name: str) -> "Response":
        """
        ---
        summary: Update Opendata DID
        description: "Updates the properties of an existing Opendata DID."
        tags:
          - Opendata
        parameters:
          - name: scope
            in: path
            description: "The scope of the data identifier to be updated."
            schema:
              type: string
            required: true
            style: simple
          - name: name
            in: path
            description: "The name of the data identifier to be updated."
            schema:
              type: string
            required: true
            style: simple
          - name: body
            in: body
            description: "JSON object containing the fields to update: 'state', 'meta', and/or 'doi'."
            required: false
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    state:
                      type: string
                      description: "New state for the DID."
                      enum: ["draft", "public", "suspended"]
                    meta:
                      type: object
                      description: "New metadata dictionary for the DID. Supports arbitrary JSON objects."
                      example: {"key": "value", "another_key": "another_value"}
                    doi:
                      type: string
                      description: "Digital Object Identifier (DOI) for the DID.
                      example: '10.1234/abcd.efgh'."
        responses:
          200:
            description: "Opendata DID successfully updated."
            content:
              application/json:
                schema:
                  type: string
                  enum: []
          400:
            description: "Invalid input or update parameters."
          401:
            description: "Access denied: Invalid authentication."
          404:
            description: "Data Identifier not found."
        """
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo", DEFAULT_VO))
            parameters = json_parameters()
            state = param_get(parameters, 'state', default=None)
            meta = param_get(parameters, 'meta', default=None)
            doi = param_get(parameters, 'doi', default=None)
            opendata.update_opendata_did(scope=scope,
                                         name=name,
                                         state=state,
                                         meta=meta,
                                         doi=doi,
                                         vo=request.environ.get("vo", DEFAULT_VO),
                                         )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except OpenDataDataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except Exception as error:
            return generate_http_error_flask(400, error)

        return Response(status=200, mimetype='application/json')

    def delete(self, scope: str, name: str) -> "Response":
        """
        ---
        summary: Delete Opendata DID
        description: "Deletes an entry in the Opendata catalog."
        tags:
          - Opendata
        parameters:
          - name: scope
            in: path
            description: "The scope of the data identifier to be deleted."
            schema:
              type: string
            required: true
            style: simple
          - name: name
            in: path
            description: "The name of the data identifier to be deleted."
            schema:
              type: string
            required: true
            style: simple
        responses:
          204:
            description: "Opendata DID successfully deleted. No content is returned."
          400:
            description: "Invalid input: The provided scope/name is not valid."
          401:
            description: "Access denied: Invalid authentication."
          404:
            description: "Data Identifier not found."
        """
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo", DEFAULT_VO))
            opendata.delete_opendata_did(scope=scope, name=name, vo=request.environ.get("vo", DEFAULT_VO))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except OpenDataDataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except Exception as error:
            return generate_http_error_flask(400, error)
        return Response(status=204, mimetype='application/json')


def blueprint() -> "Blueprint":
    bp = AuthenticatedBlueprint("opendata", __name__, url_prefix="/opendata")

    opendata_view = OpenDataView.as_view("opendata")
    bp.add_url_rule("/dids", view_func=opendata_view, methods=["get"])

    opendata_did_view = OpenDataDIDsView.as_view("opendata_did")
    bp.add_url_rule("/dids/<scope>/<name>", view_func=opendata_did_view, methods=["get", "post", "put", "delete"])

    bp.after_request(response_headers)

    return bp


def make_doc() -> "Flask":
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
