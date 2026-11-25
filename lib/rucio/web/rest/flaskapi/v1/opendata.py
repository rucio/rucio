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

from rucio.common.constants import DEFAULT_VO, HTTPMethod
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
        summary: List Open Data DIDs
        description: "Retrieves a list of Open Data DIDs. Supports optional query parameters for pagination and filtering by state."
        tags:
          - Open Data
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
            description: "Successful retrieval of the list of Open Data DIDs."
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - total
                    - offset
                    - dids
                  properties:
                    total:
                      type: integer
                      description: "Total number of matching DIDs."
                    offset:
                      type: integer
                      description: "Offset used for pagination."
                    dids:
                      type: array
                      items:
                        type: object
                        required:
                          - scope
                          - name
                          - state
                          - created_at
                          - updated_at
                        properties:
                          scope:
                            type: string
                          name:
                            type: string
                          state:
                            type: string
                            enum: [DRAFT, PUBLIC, SUSPENDED]
                          created_at:
                            type: string
                          updated_at:
                            type: string
                example:
                  total: 1
                  offset: 0
                  dids:
                    - scope: demo
                      name: demo-1
                      state: PUBLIC
                      created_at: "Mon, 19 Oct 2026 09:00:00 UTC"
                      updated_at: "Mon, 19 Oct 2026 10:00:00 UTC"
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
            include_record_id = request.args.get("record_id", default="1").lower() == "1"
            include_download_urls = request.args.get("download_urls", default="0").lower() == "1"
            result = opendata.get_opendata_did(scope=scope, name=name, vo=vo,
                                               state=state,
                                               include_files=include_files,
                                               include_metadata=include_metadata,
                                               include_doi=include_doi,
                                               include_record_id=include_record_id,
                                               include_download_urls=include_download_urls,
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
        summary: Get Open Data DID Information
        description: "Retrieves detailed Open Data information for the given scope and name. Supports optional query parameters to control the inclusion of files, metadata, and DOI information."
        tags:
          - Open Data
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
          - name: record_id
            in: query
            description: "Whether to include the record ID. '1' to include, '0' to exclude. Default is '1'."
            schema:
              type: string
              enum: ['0', '1']
            required: false
            style: form
          - name: download_urls
            in: query
            description: "Whether to include download URLs for the files. '1' to include, '0' to exclude. Default is '0'."
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
            description: "Successful retrieval of Open Data DID information. Additional fields are included depending on the query parameters."
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - scope
                    - name
                    - state
                    - created_at
                    - updated_at
                  properties:
                    scope:
                      type: string
                    name:
                      type: string
                    state:
                      type: string
                      enum: [DRAFT, PUBLIC, SUSPENDED]
                    created_at:
                      type: string
                    updated_at:
                      type: string
                    doi:
                      type: string
                      nullable: true
                    record_id:
                      type: integer
                      nullable: true
                    rule:
                      type: string
                      nullable: true
                    meta:
                      type: object
                      description: "Included when meta=1."
                      additionalProperties: true
                    files:
                      type: array
                      description: "Included when files=1."
                      items:
                        type: object
                        properties:
                          scope:
                            type: string
                          name:
                            type: string
                          bytes:
                            type: integer
                            nullable: true
                          adler32:
                            type: string
                            nullable: true
                          uris:
                            type: array
                            items:
                              type: string
                          download_urls:
                            type: array
                            description: "Included when download_urls=1 and files=1."
                            items:
                              type: string
                    files_summary:
                      type: object
                      description: "Included when files=1."
                      properties:
                        length:
                          type: integer
                        bytes:
                          type: integer
                        extensions:
                          type: array
                          items:
                            type: string
                        replicas_missing:
                          type: integer
                        request_cache_hit:
                          type: boolean
                        request_time_elapsed_millis:
                          type: number
                examples:
                  default:
                    summary: "Default response"
                    value:
                      scope: demo
                      name: demo-1
                      state: PUBLIC
                      created_at: "Mon, 19 Oct 2026 09:00:00 UTC"
                      updated_at: "Mon, 19 Oct 2026 10:00:00 UTC"
                      doi: null
                      record_id: null
                      rule: null
                  with_files_and_metadata:
                    summary: "Response with files and metadata"
                    description: "Example response when files=1 and meta=1."
                    value:
                      scope: demo
                      name: demo-1
                      state: PUBLIC
                      created_at: "Mon, 19 Oct 2026 09:00:00 UTC"
                      updated_at: "Mon, 19 Oct 2026 10:00:00 UTC"
                      doi: null
                      record_id: null
                      rule: null
                      meta:
                        title: "Example Open Data dataset"
                      files:
                        - scope: demo
                          name: example.root
                          bytes: 1024
                          adler32: "00000001"
                          uris:
                            - "https://storage.example.org/data/example.root"
                      files_summary:
                        length: 1
                        bytes: 1024
                        extensions:
                          - root
                        replicas_missing: 0
                        request_cache_hit: false
                        request_time_elapsed_millis: 12.5
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
        summary: Register Open Data DID
        description: "Registers an existing DID as Open Data."
        tags:
          - Open Data
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
            description: "Open Data DID successfully registered. No response body is returned."
          400:
            description: "Invalid input: The provided scope/name is not valid."
          401:
            description: "Access denied: Invalid authentication."
          404:
            description: "Data Identifier not found."
          409:
            description: "Data Identifier already exists in the Open Data catalog."
        """
        vo = request.environ.get("vo", DEFAULT_VO)
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", vo=vo)
            opendata.add_opendata_did(scope=scope, issuer=request.environ['issuer'], name=name, vo=vo)
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
        summary: Update Open Data DID
        description: "Updates the properties of an existing Open Data DID."
        tags:
          - Open Data
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
                      description: "New state for the DID."
                      $ref: "#/components/schemas/OpenDataDIDState"
                    meta:
                      type: object
                      description: "New metadata dictionary for the DID. Supports arbitrary JSON objects."
                      example: {"key": "value", "another_key": "another_value"}
                    doi:
                      type: string
                      description: "Digital Object Identifier (DOI) for the DID.
                      example: '10.1234/abcd.efgh'."
                    record_id:
                      type: integer
                      description: "Record ID for the DID."
                      example: 123456
        responses:
          200:
            description: "Open Data DID successfully updated. The response contains the fields affected by the update."
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - scope
                    - name
                  properties:
                    scope:
                      type: string
                    name:
                      type: string
                    state_old:
                      type: string
                      enum: [DRAFT, PUBLIC, SUSPENDED]
                    state_new:
                      type: string
                      enum: [DRAFT, PUBLIC, SUSPENDED]
                    meta_new:
                      type: object
                      additionalProperties: true
                    doi_old:
                      type: string
                      nullable: true
                    doi_new:
                      type: string
                    record_id_old:
                      type: integer
                      nullable: true
                    record_id_new:
                      type: integer
                    rule:
                      type: string
                    comments:
                      type: string
                example:
                  scope: demo
                  name: demo-1
                  state_old: DRAFT
                  state_new: PUBLIC
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
            record_id = param_get(parameters, 'record_id', default=None)
            if record_id is not None:
                record_id = int(record_id)
            result = opendata.update_opendata_did(
                scope=scope,
                name=name,
                state=state,
                meta=meta,
                doi=doi,
                record_id=record_id,
                issuer=request.environ['issuer'],
                vo=request.environ.get("vo", DEFAULT_VO),
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except OpenDataDataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except Exception as error:
            return generate_http_error_flask(400, error)

        return Response(status=200, mimetype='application/json', response=render_json(**result))

    def delete(self, scope: str, name: str) -> "Response":
        """
        ---
        summary: Delete Open Data DID
        description: "Deletes an entry in the Open Data catalog."
        tags:
          - Open Data
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
            description: "Open Data DID successfully deleted. No content is returned."
          400:
            description: "Invalid input: The provided scope/name is not valid."
          401:
            description: "Access denied: Invalid authentication."
          404:
            description: "Data Identifier not found."
        """
        try:
            scope, name = parse_scope_name(f"{scope}/{name}", request.environ.get("vo", DEFAULT_VO))
            opendata.delete_opendata_did(scope=scope, name=name, issuer=request.environ['issuer'], vo=request.environ.get("vo", DEFAULT_VO))
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
    bp.add_url_rule("/dids", view_func=opendata_view, methods=[HTTPMethod.GET.value])

    opendata_did_view = OpenDataDIDsView.as_view("opendata_did")
    bp.add_url_rule("/dids/<scope>/<name>", view_func=opendata_did_view,
                    methods=[HTTPMethod.GET.value, HTTPMethod.POST.value, HTTPMethod.PUT.value, HTTPMethod.DELETE.value])

    bp.after_request(response_headers)

    return bp


def make_doc() -> "Flask":
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
