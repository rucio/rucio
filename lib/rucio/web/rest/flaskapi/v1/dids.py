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

import ast
from json import dumps

from flask import Flask, Response, request

from rucio.common.exception import (
    AccessDenied,
    DatabaseException,
    DataIdentifierAlreadyExists,
    DataIdentifierNotFound,
    DuplicateContent,
    FileAlreadyExists,
    FileConsistencyMismatch,
    InvalidMetadata,
    InvalidObject,
    InvalidPath,
    InvalidValueForKey,
    KeyNotFound,
    RSENotFound,
    RuleNotFound,
    ScopeNotFound,
    UnsupportedMetadataPlugin,
    UnsupportedOperation,
    UnsupportedStatus,
)
from rucio.common.utils import APIEncoder, parse_response, render_json
from rucio.db.sqla.constants import DIDType
from rucio.gateway.did import (
    add_did,
    add_did_to_followed,
    add_dids,
    attach_dids,
    attach_dids_to_dids,
    bulk_list_files,
    create_did_sample,
    delete_metadata,
    detach_dids,
    get_dataset_by_guid,
    get_did,
    get_metadata,
    get_metadata_bulk,
    get_users_following_did,
    list_content,
    list_content_history,
    list_dids,
    list_files,
    list_new_dids,
    list_parent_dids,
    remove_did_from_followed,
    resurrect,
    scope_list,
    set_dids_metadata_bulk,
    set_metadata,
    set_metadata_bulk,
    set_status,
)
from rucio.gateway.rule import list_associated_replication_rules_for_file, list_replication_rules
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, json_list, json_parameters, json_parse, param_get, parse_scope_name, response_headers, try_stream


class Scope(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope):
        """
        ---
        summary: Get Data Identifier
        description: "Return all data identifiers in the given scope."
        tags:
          - Data Identifiers
        parameters:
        - name: scope
          in: path
          description: "The scope."
          required: true
          schema:
            type: string
          style: simple
        - name: name
          in: query
          description: "The name of the data identifier (DID)."
          required: false
          schema:
            type: string
        - name: recursive
          in: query
          description: "If true, retrieves child identifiers recursively for non-file types."
          required: false
          schema:
            type: boolean
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "Line-separated dictionary of DIDs."
                  type: array
                  items:
                    type: object
                    description: "Data identifier"
                    properties:
                      scope:
                        type: string
                        description: "The scope of the DID."
                      name:
                        type: string
                        description: "The name of the DID."
                      type:
                        type: string
                        description: "The type of the DID."
                        enum: ['F', 'D', 'C', 'A', 'X', 'Y', 'Z']
                      parent:
                        type: string
                        description: "The parent of the DID."
                      level:
                        type: integer
                        description: "The level of the DID."
          401:
            description: "Invalid Auth Token"
          404:
            description: "No DIDs found"
          406:
            description: "Not acceptable"
        """
        try:
            def generate(name, recursive, vo):
                for did in scope_list(scope=scope, name=name, recursive=recursive, vo=vo):
                    yield render_json(**did) + '\n'

            recursive = request.args.get('recursive', 'false').lower() in ['true', '1']

            return try_stream(
                generate(
                    name=request.args.get('name', default=None),
                    recursive=recursive,
                    vo=request.environ['vo']
                )
            )
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class Search(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope):
        """
        ---
        summary: List Data identifier
        description: "List all data identifiers in a scope which match a given metadata."
        tags:
          - Data Identifiers
        parameters:
        - name: scope
          in: path
          description: "The scope of the data identifiers."
          schema:
            type: string
          style: simple
        - name: type
          in: query
          description: "The DID type to search for."
          schema:
            type: string
            enum: ['all', 'collection', 'container', 'dataset', 'file']
            default: 'collection'
        - name: limit
          in: query
          description: "The maximum number of DIDs returned."
          schema:
            type: integer
        - name: long
          in: query
          description: "Provides a longer output, otherwise just prints names."
          schema:
            type: boolean
            default: false
        - name: recursive
          in: query
          description: "Recursively list chilred."
          schema:
            type: boolean
        - name: created_before
          in: query
          description: "Date string in RFC-1123 format where the creation date was earlier."
          schema:
            type: string
        - name: created_after
          in: query
          description: "Date string in RFC-1123 format where the creation date was later."
          schema:
            type: string
        - name: length
          in: query
          description: "Exact number of attached DIDs."
          schema:
            type: integer
        - name: length.gt
          in: query
          description: "Number of attached DIDs greater than."
          schema:
            type: integer
        - name: length.lt
          in: query
          description: "Number of attached DIDs less than."
          schema:
            type: integer
        - name: length.gte
          in: query
          description: "Number of attached DIDs greater than or equal to"
          schema:
            type: integer
        - name: length.lte
          in: query
          description: "Number of attached DIDs less than or equal to."
          schema:
            type: integer
        - name: name
          in: query
          description: "Name or pattern of a DID."
          schema:
            type: string
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "Line separated name of DIDs or dictionaries of DIDs for long option."
                  type: array
                  items:
                    type: object
                    description: "The name of a DID or a dictionarie of a DID for long option."
          401:
            description: "Invalid Auth Token"
          404:
            description: "Invalid key in filter."
          406:
            description: "Not acceptable"
          409:
            description: "Wrong DID type"
        """
        filters = request.args.get('filters', default=None)
        if filters is not None:
            filters = ast.literal_eval(filters)
        else:
            # backwards compatibility for created*, length* and name filters passed through as request args
            filters = {}
            for arg, value in request.args.copy().items():
                if arg not in ['type', 'limit', 'long', 'recursive']:
                    filters[arg] = value
            filters = [filters]

        did_type = request.args.get('type', default='collection')
        limit = request.args.get('limit', type=int, default=None)
        long = request.args.get('long', type=['True', '1'].__contains__, default=False)
        recursive = request.args.get('recursive', type='True'.__eq__, default=False)
        try:
            def generate(vo):
                for did in list_dids(scope=scope, filters=filters, did_type=did_type, limit=limit, long=long, recursive=recursive, vo=vo):
                    yield dumps(did) + '\n'
            return try_stream(generate(vo=request.environ['vo']))
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, error)
        except KeyNotFound as error:
            return generate_http_error_flask(404, error)


class BulkDIDS(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self):
        """
        ---
        summary: Add DIDs bulk
        description: "Add new DIDs in bulk."
        tags:
          - Data Identifiers
        requestBody:
          content:
            application/json:
              schema:
                type: array
                items:
                  description: "One DID to add."
                  type: object
                  required:
                    - scope
                    - name
                    - type
                  properties:
                    scope:
                      description: "The DID scope."
                      type: string
                    name:
                      description: "The DID name."
                      type: string
                    type:
                      description: "The type of the DID."
                      type: string
                      enum: ["F", "D", "C", "A", "X", "Y", "Z"]
                    account:
                      description: "The account associated with the DID."
                      type: string
                    statuses:
                      description: "The monotonic status"
                      type: string
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: "Invalid Auth Token"
          406:
            description: "Not acceptable"
          409:
            description: "DID already exists"
        """
        dids = json_list()
        try:
            add_dids(dids=dids, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except (DuplicateContent, DataIdentifierAlreadyExists, UnsupportedOperation) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        return 'Created', 201


class Attachments(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Attach DID to DID
        description: "Attaches a DID to another DID"
        tags:
          - Data Identifiers
        requestBody:
          content:
            'application/json':
              schema:
                oneOf:
                  - description: An array containing all DIDs. Duplicates are not ignored.
                    type: array
                    required:
                      - scope
                      - name
                      - dids
                    properties:
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      dids:
                        description: "The DIDs associated with the DID."
                        type: array
                        items:
                          type: object
                          description: "A DID."
                          required:
                            - scope
                            - name
                          properties:
                            scope:
                              description: "The scope of the DID."
                              type: string
                            name:
                              description: "The name of the DID."
                              type: string
                      rse_id:
                        description: "The rse id of the DID."
                        type: string
                  - type: object
                    required:
                      - attachments
                    properties:
                      ignore_duplicates:
                        description: "If duplicates should be ignored."
                        type: boolean
                        default: false
                      attachments:
                        description: "An array containing all DIDs. Duplicates are not ignored."
                        type: array
                        required:
                          - scope
                          - name
                          - dids
                        properties:
                          scope:
                            description: "The scope of the DID."
                            type: string
                          name:
                            description: "The name of the DID."
                            type: string
                          dids:
                            description: "The DIDs associated to the DID."
                            type: array
                            items:
                              type: object
                              description: "A DID."
                              required:
                                - scope
                                - name
                              properties:
                                scope:
                                  description: "The scope of the DID."
                                  type: string
                                name:
                                  description: "The name of the DID."
                                  type: string
                          rse_id:
                            description: "The rse id of the DID."
                            type: string
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          406:
            description: "Not acceptable"
        """
        parameters = json_parse((dict, list))
        if isinstance(parameters, list):
            attachments = parameters
            ignore_duplicate = False
        elif isinstance(parameters, dict):
            attachments = param_get(parameters, 'attachments')
            ignore_duplicate = param_get(parameters, 'ignore_duplicate', default=False)
        else:
            return generate_http_error_flask(406, exc="Invalid attachment format.")

        try:
            attach_dids_to_dids(attachments=attachments, ignore_duplicate=ignore_duplicate, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except (DuplicateContent, DataIdentifierAlreadyExists, UnsupportedOperation, FileAlreadyExists) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except FileConsistencyMismatch as error:
            return generate_http_error_flask(412, error)

        return 'Created', 201


class DIDs(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope_name):
        """
        ---
        summary: Get DID
        description: "Get a single data identifier."
        tags:
          - Data identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        - name: dynamic_depth
          in: query
          description: "The DID type at which to stop the dynamic length/size estimation"
          schema:
            type: string
            enum: ["FILE", "DATASET"]
        - name: dynamic
          in: query
          description: "Same as dynamic_depth = 'FILE'"
          deprecated: true
          schema:
            type: string
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  oneOf:
                  - description: "A single file DID."
                    type: object
                    properties:
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      type:
                        description: "The type of the string."
                        type: string
                      account:
                        description: "The associated account."
                        type: string
                      bytes:
                        description: "The size in bytes."
                        type: integer
                      length:
                        description: "The number of files. Corresponses to 1."
                        type: integer
                        enum: [1]
                      md5:
                        description: "md5 checksum."
                        type: string
                      adler32:
                        description: "adler32 checksum."
                        type: string
                  - description: "A single file DID."
                    type: object
                    properties:
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      type:
                        description: "The type of the string."
                        type: string
                      account:
                        description: "The associated account."
                        type: string
                      open:
                        description: "If the DID is write open."
                        type: boolean
                      monotonic:
                        description: "If the DID is monotonic."
                        type: boolean
                      expired_at:
                        description: "When the DID expired."
                        type: string
                      length:
                        description: "The number of associated DIDs."
                        type: number
                      bytes:
                        description: "The size in bytes."
                        type: number
          401:
            description: "Invalid Auth Token"
          404:
            description: "Scope not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])
            dynamic_depth = None
            if 'dynamic_depth' in request.args:
                orig = request.args['dynamic_depth'].upper()
                if orig == 'DATASET':
                    dynamic_depth = DIDType.DATASET
                elif orig == 'FILE':
                    dynamic_depth = DIDType.FILE
                else:
                    dynamic_depth = None
            elif 'dynamic' in request.args:
                dynamic_depth = DIDType.FILE
            did = get_did(scope=scope, name=name, dynamic_depth=dynamic_depth, vo=request.environ['vo'])
            return Response(render_json(**did), content_type='application/json')
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (ScopeNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)

    def post(self, scope_name):
        """
        ---
        summary: Create DID
        description: "Create a new data identifier."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - type
                properties:
                  type:
                    description: "The type of the DID."
                    type: string
                  statuses:
                    description: "The statuses of the DID."
                    type: string
                  meta:
                    description: "The meta of the DID."
                    type: string
                  rules:
                    description: "The rules associated with the DID."
                    type: array
                    items:
                      type: object
                      description: "A rule."
                  lifetime:
                    description: "The lifetime of the DID."
                    type: string
                  dids:
                    description: "The DIDs associated with the DID."
                    type: array
                    items:
                      type: object
                      description: "The DID associated with a DID."
                      properties:
                        scope:
                          description: "The scope of the DID."
                          type: string
                        name:
                          description: "The name of the DID."
                          type: string
                  rse:
                    description: "The rse associated with the DID."
                    type: string
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID or scope not found"
          409:
            description: "DID already exists"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        type_param = param_get(parameters, 'type')

        try:
            add_did(
                scope=scope,
                name=name,
                did_type=type_param,
                statuses=param_get(parameters, 'statuses', default={}),
                meta=param_get(parameters, 'meta', default={}),
                rules=param_get(parameters, 'rules', default=[]),
                lifetime=param_get(parameters, 'lifetime', default=None),
                dids=param_get(parameters, 'dids', default=[]),
                rse=param_get(parameters, 'rse', default=None),
                issuer=request.environ['issuer'],
                vo=request.environ['vo'],
            )
        except (InvalidObject, InvalidPath) as error:
            return generate_http_error_flask(400, error)
        except (DataIdentifierNotFound, ScopeNotFound) as error:
            return generate_http_error_flask(404, error)
        except (DuplicateContent, DataIdentifierAlreadyExists, UnsupportedOperation) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except DatabaseException as error:
            if 'DELETED_DIDS_PK violated' in str(error):
                return generate_http_error_flask(
                    status_code=406,
                    exc=error.__class__.__name__,
                    exc_msg=str('A deleted DID {} with scope {} is reused'.format(name, scope))
                )
            else:
                return generate_http_error_flask(406, error)

        return 'Created', 201

    def put(self, scope_name):
        """
        ---
        summary: Update DID
        description: "Update a DID."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                properties:
                  open:
                    description: "The open status"
                    type: boolean
        responses:
          200:
            description: "OK"
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          409:
            description: "Wrong status"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()

        try:
            set_status(scope=scope, name=name, issuer=request.environ['issuer'], vo=request.environ['vo'], **parameters)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except (UnsupportedStatus, UnsupportedOperation) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return '', 200


class Attachment(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get DID
        description: "Returns the contents of a data identifier."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "DID found"
            content:
              application/x-json-stream:
                schema:
                  description: "The contents of a DID. Items are line separated."
                  type: array
                  items:
                    type: object
                    required:
                      - scope
                      - name
                      - type
                      - bytes
                      - adler32
                      - md5
                    properties:
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      type:
                        description: "The type of the DID."
                        type: string
                      bytes:
                        description: "The size of the DID."
                        type: number
                      adler32:
                        description: "The adler32 checksum of the DID."
                        type: string
                      md5:
                        description: "The md5 checksum of the DID."
                        type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "Scope not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])

            def generate(vo):
                for did in list_content(scope=scope, name=name, vo=vo):
                    yield render_json(**did) + '\n'

            return try_stream(generate(vo=request.environ['vo']))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self, scope_name):
        """
        ---
        summary: Add DIDs to DID
        description: "Append data identifiers to data identifiers."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - dids
                properties:
                  rse:
                    description: "The name of the rse."
                    type: string
                  account:
                    description: "The account which attaches the DIDs."
                    type: string
                  dids:
                    description: "The DIDs to attach."
                    type: object
                    properties:
                      account:
                        description: "The account attaching the DID."
                        type: string
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
          409:
            description: "Already attached"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])
        except ValueError as error:
            return generate_http_error_flask(400, error)

        attachments = json_parameters()

        try:
            attach_dids(scope=scope, name=name, attachment=attachments, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except InvalidPath as error:
            return generate_http_error_flask(400, error)
        except (DataIdentifierNotFound, RSENotFound) as error:
            return generate_http_error_flask(404, error)
        except (DuplicateContent, UnsupportedOperation, FileAlreadyExists) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return 'Created', 201

    def delete(self, scope_name):
        """
        ---
        summary: Detach DIDs from DID
        description: "Detach data identifiers from data identifiers."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - dids
                properties:
                  dids:
                    description: "The DIDs to detach."
                    type: array
                    items:
                      type: object
                      properties:
                        scope:
                          description: "The scope of the DID."
                          type: string
                        name:
                          description: "The name of the DID."
                          type: string
        responses:
          200:
            description: "OK"
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        dids = param_get(parameters, 'dids')

        try:
            detach_dids(scope=scope, name=name, dids=dids, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return '', 200


class AttachmentHistory(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get history
        description: "Returns the content history of a data identifier."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "DID found"
            content:
              application/x-json-stream:
                schema:
                  description: "The DIDs with their information and history. Elements are separated by new line characters."
                  type: array
                  items:
                    type: object
                    description: "A single DID with history data."
                    properties:
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      type:
                        description: "The type of the DID."
                        type: string
                      bytes:
                        description: "The size of the DID in bytes."
                        type: integer
                      adler32:
                        description: "The abler32 sha checksum."
                        type: string
                      md5:
                        description: "The md5 checksum."
                        type: string
                      deleted_at:
                        description: "The deleted_at date time."
                        type: string
                      created_at:
                        description: "The created_at date time."
                        type: string
                      updated_at:
                        description: "The last time the DID was updated."
                        type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])

            def generate(vo):
                for did in list_content_history(scope=scope, name=name, vo=vo):
                    yield render_json(**did) + '\n'

            return try_stream(generate(vo=request.environ['vo']))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class Files(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get replicas
        description: "List all replicas for a DID."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        - name: long
          in: query
          description: "Flag to trigger long output."
          schema:
            type: object
          required: false
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  oneOf:
                    - description: "All replica information if `long` is defined."
                      type: array
                      items:
                        type: object
                        properties:
                          scope:
                            description: "The scope of the DID."
                            type: string
                          name:
                            description: "The name of the DID."
                            type: string
                          bytes:
                            description: "The size of the DID in bytes."
                            type: integer
                          guid:
                            description: "The guid of the DID."
                            type: string
                          events:
                            description: "The number of events of the DID."
                            type: integer
                          adler32:
                            description: "The adler32 checksum."
                            type: string
                          lumiblocknr:
                            description: "The lumi block nr. Only available if `long` is defined in the query."
                            type: integer
                    - description: "All replica information."
                      type: array
                      items:
                        type: object
                        properties:
                          scope:
                            description: "The scope of the DID."
                            type: string
                          name:
                            description: "The name of the DID."
                            type: string
                          bytes:
                            description: "The size of the DID in bytes."
                            type: integer
                          guid:
                            description: "The guid of the DID."
                            type: string
                          events:
                            description: "The number of events of the DID."
                            type: integer
                          adler32:
                            description: "The adler32 checksum."
                            type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
        """
        long = 'long' in request.args

        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])

            def generate(vo):
                for file in list_files(scope=scope, name=name, long=long, vo=vo):
                    yield dumps(file) + '\n'

            return try_stream(generate(vo=request.environ['vo']))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class BulkFiles(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """
        ---
        summary: List files bulk
        description: "List files in multiple DIDs"
        tags:
          - Data Identifiers
        requestBody:
          content:
            application/json:
              schema:
                type: array
                items:
                  description: "One DID to list files."
                  type: object
                  required:
                    - scope
                    - name
                  properties:
                    scope:
                      description: "The DID scope."
                      type: string
                    name:
                      description: "The DID name."
                      type: string
        responses:
          201:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "All collections file content."
                  type: array
                  items:
                    description: "Collections file content."
                    type: object
                    properties:
                      parent_scope:
                        description: "The scope of the parent DID."
                        type: string
                      parent_name:
                        description: "The name of the parent DID."
                        type: string
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      bytes:
                        description: "The size of the DID in bytes."
                        type: integer
                      guid:
                        description: "The guid of the DID."
                        type: string
                      events:
                        description: "The number of events of the DID."
                        type: integer
                      adler32:
                        description: "The adler32 checksum."
                        type: string
          401:
            description: "Invalid Auth Token"
        """
        parameters = json_parameters(parse_response)
        dids = param_get(parameters, 'dids', default=[])
        try:
            def generate(vo):
                for did in bulk_list_files(dids=dids, vo=vo):
                    yield render_json(**did) + '\n'

            return try_stream(generate(vo=request.environ['vo']))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        return 'Created', 201


class Parents(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get Parents
        description: "Lists all parents of the DID."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "The parents of the DID."
                  type: array
                  items:
                    type: object
                    description: "A parent of the DID."
                    properties:
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      type:
                        description: "The type of the DID."
                        type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])

            def generate(vo):
                for dataset in list_parent_dids(scope=scope, name=name, vo=vo):
                    yield render_json(**dataset) + "\n"

            return try_stream(generate(vo=request.environ['vo']))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class Meta(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope_name, key=None):
        """
        ---
        summary: Get metadata
        description: "Retrieve the metadata of a data identifier (DID)."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID (e.g., `scope:name`)."
          required: true
          style: simple
          schema:
            type: string
        - name: plugin
          in: query
          description: "The metadata plugin to use."
          required: false
          style: form
          schema:
            type: string
            default: DID_COLUMN
        responses:
          200:
            description: "OK – returns the metadata of the DID."
            content:
              application/json:
                schema:
                  type: object
                  description: "A JSON object containing all attributes of the DID."
                examples:
                  defaultPlugin:
                    summary: "Response produced by the default 'DID_COLUMN' plug-in"
                    value:
                      scope: "user"
                      name: "dataset_123"
                      did_type: "DATASET"
                      bytes: 123456789
                      length: 42
                      account: "root"
                      is_open: true
                      suppressed: false
                      created_at: "2025-05-20T12:16:58"
                      updated_at: "2025-05-20T12:17:27"
                      # ... rest DID fields
                  jsonPlugin:
                    summary: "Response produced by the 'JSON' plugin"
                    value:
                      custom_key1: "value1"
                      custom_key2: "value2"
                      # ... etc
          400:
            description: "Bad Request – invalid scope_name, or invalid metadata plugin specified."
          401:
            description: "Unauthorized – invalid Auth Token."
          404:
            description: "Not found – the specified DID does not exist."
          405:
            description: "Method Not Allowed – the 'key' parameter is not supported with GET."
          406:
            description: "Not Acceptable – the requested format is not supported."
        """
        # Flask injects the `key` keyword argument here because the blueprint registers
        # the generic `/meta` endpoint with `defaults={'key': None}`.  The GET endpoint is
        # intentionally *not* exposed as `/meta/<key>`—it always returns the complete
        # metadata record (optionally filtered by the `plugin` query parameter).  Hence,
        # a non‑None `key` should never reach this method today.  The following guard
        # defends against any future routing changes that might introduce
        # `/meta/<key>` for GET requests by explicitly rejecting such usage.
        if key is not None:
            return generate_http_error_flask(405,
                                             'MethodNotAllowed',
                                             'GET not allowing keys')

        vo = request.environ['vo']
        try:
            scope, name = parse_scope_name(scope_name, vo)
        except ValueError as error:
            return generate_http_error_flask(400, error)

        plugin = request.args.get('plugin', default='DID_COLUMN')
        try:
            meta = get_metadata(scope=scope, name=name, plugin=plugin, vo=vo)
            return Response(render_json(**meta), content_type='application/json')
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except UnsupportedMetadataPlugin as error:
            return generate_http_error_flask(400, error)

    def post(self, scope_name, key=None):
        """
        ---
        summary: Set or update metadata
        description: |
          Set metadata for a data identifier (DID). If a piece of metadata for a given key
          already exists, it will be handled according to the underlying metadata plugin
          in use. Certain plugins may disallow updating specific metadata keys.

          - **Single-key mode** (key provided in the path):
            The request body must contain a `value` field (e.g., `{"value": "some_value"}`).
          - **Multi-key mode** (no key in the path):
            The request body must contain a `meta` field with the dictionary containing
            multiple key-value pairs (e.g. `{"meta": {"k1": "v1", "k2": "v2"}}`).

          The optional `recursive` flag indicates whether the metadata should be applied
          recursively to child DIDs. Note that whether recursion is supported depends on
          the plugin configured for your system.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID (e.g., `scope:name`)."
          required: true
          style: simple
          schema:
            type: string
        - name: key
          in: path
          description: |
            The key parameter applies only to the `/meta/<key>` endpoint (**Single-key mode**)
            and defines which metadata key to set/update. If omitted (by calling just `/meta`
            without the extra path segment), it defaults to `None` and **Multi-key mode** is used.
          required: true
          style: simple
          schema:
            type: string
        requestBody:
          required: true
          content:
            application/json:
              schema:
                oneOf:
                  - type: object
                    description: "Schema for **Single-key mode** (`key` included in path)."
                    required:
                      - value
                    properties:
                      value:
                        description: "The metadata value to set for this key."
                        type: string
                      recursive:
                        description: "Whether to apply the update recursively to child DIDs."
                        type: boolean
                        default: false
                  - type: object
                    description: "Schema for **Multi-key mode** (`key` not included in path)."
                    required:
                      - meta
                    properties:
                      meta:
                        description: "A dictionary of multiple metadata keys and their values."
                        type: object
                      recursive:
                        description: "Whether to apply the update recursively to child DIDs."
                        type: boolean
                        default: false
              examples:
                singleKeyMode:
                  summary: "Setting a single metadata key"
                  value:
                    value: "my_metadata_value"
                    recursive: false
                multiKeyMode:
                  summary: "Setting multiple metadata keys at once"
                  value:
                    meta:
                      experiment: "ATLAS"
                      physics_group: "Higgs"
                      data_type: "RAW"
                    recursive: true
        responses:
          201:
            description: "Created – metadata was successfully set (or updated)."
            content:
              text/plain:
                schema:
                  type: string
                  enum: ["Created"]
          400:
            description: "Bad Request – invalid scope_name, or invalid key/value parameters."
          401:
            description: "Unauthorized – invalid Auth Token."
          404:
            description: "Not found – the specified DID does not exist."
        """
        vo = request.environ['vo']
        try:
            scope, name = parse_scope_name(scope_name, vo)
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()

        if key is not None:
            value = param_get(parameters, 'value')
            try:
                set_metadata(
                    scope=scope,
                    name=name,
                    key=key,
                    value=value,
                    issuer=request.environ['issuer'],
                    recursive=param_get(parameters, 'recursive', default=False),
                    vo=vo
                )
            except DataIdentifierNotFound as error:
                return generate_http_error_flask(404, error)
            except (KeyNotFound, InvalidMetadata, InvalidValueForKey) as error:
                return generate_http_error_flask(400, error)
            return 'Created', 201

        else:
            meta = param_get(parameters, 'meta')
            try:
                set_metadata_bulk(
                    scope=scope,
                    name=name,
                    meta=meta,
                    issuer=request.environ['issuer'],
                    recursive=param_get(parameters, 'recursive', default=False),
                    vo=vo,
                )
            except DataIdentifierNotFound as error:
                return generate_http_error_flask(404, error)
            except (KeyNotFound, InvalidMetadata, InvalidValueForKey) as error:
                return generate_http_error_flask(400, error)
            return "Created", 201

    def delete(self, scope_name, key=None):
        """
        ---
        summary: Delete metadata
        description: |
          Delete a specific metadata key from a data identifier (DID).
          This `key` must be provided via the query parameter `?key=...`.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID (e.g., `scope:name`)."
          required: true
          style: simple
          schema:
            type: string
        - name: key
          in: query
          description: "The metadata key to delete."
          required: true
          style: form
          schema:
            type: string
        responses:
          200:
            description: "OK – the metadata key was successfully removed."
            content:
              text/plain:
                schema:
                  type: string
                  enum: [""]
          400:
            description: "Bad Request – invalid scope_name."
          401:
            description: "Unauthorized – invalid Auth Token."
          404:
            description: >
              Not found – the specified DID or `key` does not exist, or no `key` query
              parameter provided.
          405:
            description: "Method Not Allowed – the 'key' parameter is not supported with DELETE."
          409:
            description: "Conflict – action not supported by the utilized metadata plugin."
        """
        # Flask injects the `key` keyword argument here because the blueprint registers the
        # generic `/meta` endpoint with `defaults={'key': None}`.  For DELETE requests the
        # API currently expects any metadata key to be supplied via the **query string**
        # (e.g. `...?key=myfield`), so a non‑None `key` coming from the path is impossible
        # today.  We still keep this guard as a defensive measure in case someone later
        # extends the routing to allow `/meta/<key>` for DELETE as well.
        if key is not None:
            return generate_http_error_flask(405,
                                             'MethodNotAllowed',
                                             'DELETE not allowing keys')

        vo = request.environ['vo']
        try:
            scope, name = parse_scope_name(scope_name, vo)
        except ValueError as error:
            return generate_http_error_flask(400, error)

        if 'key' not in request.args:
            return generate_http_error_flask(404, KeyNotFound.__name__, 'No key provided to remove')

        delete_key = request.args['key']
        try:
            delete_metadata(scope=scope, name=name, key=delete_key, vo=vo)
        except (KeyNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)
        except NotImplementedError as error:
            return generate_http_error_flask(409, error, 'Feature not in current database')

        return '', 200


class BulkDIDsMeta(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Add metadata bulk
        description: "Adds metadata in a bulk."
        tags:
          - Data Identifiers
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - dids
                properties:
                  dids:
                    description: "A list with all the DIDs and the metadata."
                    type: array
                    items:
                      description: "The DID and associated metadata."
                      type: object
                      properties:
                        scope:
                          description: "The scope of the DID."
                          type: string
                        name:
                          description: "The name of the DID."
                          type: string
                        meta:
                          description: "The metadata to add. A dictionary with the meta key as key and the value as value."
                          type: object
        responses:
          200:
            description: "Created"
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
          409:
            description: "Unsupported Operation"
        """
        parameters = json_parameters()
        dids = param_get(parameters, 'dids')

        try:
            set_dids_metadata_bulk(dids=dids, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return 'Created', 201


class Rules(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get rules
        description: "Lists all rules of a given DID."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "The rules associated with a DID."
            content:
              application/x-json-stream:
                schema:
                  description: "The rules associated with a DID."
                  type: array
                  items:
                    description: "A rule."
                    type: object
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID or rule not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])

            def generate(vo):
                get_did(scope=scope, name=name, vo=vo)
                for rule in list_replication_rules({'scope': scope, 'name': name}, vo=vo):
                    yield dumps(rule, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ['vo']))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class BulkMeta(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """
        ---
        summary: Get metadata bulk
        description: "List all metadata of a list of data identifiers."
        tags:
          - Data Identifiers
        requestBody:
          content:
            'application/x-json-stream':
              schema:
                type: object
                required:
                - dids
                properties:
                  dids:
                    description: "The DIDs."
                    type: array
                    items:
                      description: "A DID."
                      type: object
                      properties:
                        name:
                          description: "The name of the DID."
                          type: string
                        scope:
                          description: "The scope of the DID."
                          type: string
                  inherit:
                    description: "Concatenated the metadata of the parent if set to true."
                    type: boolean
                    default: false
                  plugin:
                    description: "The DID meta plugin to query or 'ALL' for all available plugins"
                    type: string
                    default: "JSON"
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  description: "A list of metadata identifiers for the DIDs. Separated by new lines."
                  type: array
                  items:
                    description: "The metadata for one DID."
                    type: object
          400:
            description: "Cannot decode json parameter list"
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
        """
        parameters = json_parameters()
        dids = param_get(parameters, 'dids')
        inherit = param_get(parameters, 'inherit', default=False)
        plugin = param_get(parameters, 'plugin', default='JSON')

        try:
            def generate(vo):
                for meta in get_metadata_bulk(dids, inherit=inherit, plugin=plugin, vo=vo):
                    yield render_json(**meta) + '\n'

            return try_stream(generate(vo=request.environ['vo']))
        except ValueError as error:
            return generate_http_error_flask(400, error, 'Cannot decode json parameter list')
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class AssociatedRules(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get associated rules
        description: "Gets all associated rules for a file."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "All associated rules for a file. Items are separated by new line character."
                  type: array
                  items:
                    description: "A replication rule associated with the file. Has more fields than listed here."
                    type: object
                    properties:
                      id:
                        description: "The id of the rule."
                        type: string
                      subscription_id:
                        description: "The subscription id of the rule."
                        type: string
                      account:
                        description: "The account associated with the rule."
                        type: string
                      scope:
                        description: "The scope associated with the rule."
                        type: string
                      name:
                        description: "The name of the rule."
                        type: string
                      state:
                        description: "The state of the rule."
                        type: string
                      rse_expression:
                        description: "The rse expression of the rule."
                        type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])

            def generate(vo):
                for rule in list_associated_replication_rules_for_file(scope=scope, name=name, vo=vo):
                    yield dumps(rule, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ['vo']))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class GUIDLookup(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, guid):
        """
        ---
        summary: Get dataset
        description: "Returns the dataset associated with a GUID."
        tags:
          - Data Identifiers
        parameters:
        - name: guid
          in: path
          description: "The GUID to query buy."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "A list of all datasets associated with the guid. Items are separated by new line character."
                  type: array
                  items:
                    description: "A dataset associated with a guid."
                    type: object
                    properties:
                      scope:
                        description: "The scope of the dataset."
                        type: string
                      name:
                        description: "The name of the dataset."
                        type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
        """
        try:
            def generate(vo):
                for dataset in get_dataset_by_guid(guid, vo=vo):
                    yield dumps(dataset, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ['vo']))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class SampleLegacy(ErrorHandlingMethodView):

    def post(self, input_scope, input_name, output_scope, output_name, nbfiles):
        """
        ---
        summary: Create sample
        description: "Creates a sample from an input collection."
        tags:
          - Data Identifiers
        parameters:
        - name: input_scope
          in: path
          description: "The input scope."
          schema:
            type: string
          style: simple
        - name: input_name
          in: path
          description: "The input name."
          schema:
            type: string
          style: simple
        - name: output_scope
          in: path
          description: "The output scope."
          schema:
            type: string
          style: simple
        - name: output_name
          in: path
          description: "The output name."
          schema:
            type: string
          style: simple
        - name: nbfiles
          in: path
          description: "The number of files to register in the output dataset."
          schema:
            type: string
          style: simple
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          406:
            description: "Not acceptable"
          409:
            description: "Duplication"
        """
        try:
            create_did_sample(
                input_scope=input_scope,
                input_name=input_name,
                output_scope=output_scope,
                output_name=output_name,
                issuer=request.environ['issuer'],
                nbfiles=nbfiles,
                vo=request.environ['vo'],
            )
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except (DuplicateContent, DataIdentifierAlreadyExists, UnsupportedOperation) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return 'Created', 201


class Sample(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Create sample
        description: "Creates a sample from an input collection."
        tags:
          - Data Identifiers
        requestBody:
          description: "Parameters (source and destination) for the files in the sample to be created"
          content:
            'application/json':
              schema:
                type: object
                required:
                - input_scope
                - input_name
                - output_scope
                - output_name
                - nbfiles
                properties:
                  input_scope:
                    description: "The input scope."
                    type: string
                  input_name:
                    description: "The input name."
                    type: string
                  output_scope:
                    description: "The output scope."
                    type: string
                  output_name:
                    description: "The output name."
                    type: string
                  nbfiles:
                    description: "The number of files to register in the output dataset."
                    type: string
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          406:
            description: "Not acceptable"
          409:
            description: "Duplication"
        """
        parameters = json_parameters()
        try:
            create_did_sample(
                input_scope=parameters['input_scope'],
                input_name=parameters['input_name'],
                output_scope=parameters['output_scope'],
                output_name=parameters['output_name'],
                issuer=request.environ['issuer'],
                nbfiles=parameters['nbfiles'],
                vo=request.environ['vo'],
            )
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except (DuplicateContent, DataIdentifierAlreadyExists, UnsupportedOperation) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return 'Created', 201


class NewDIDs(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: Get recent identifiers
        description: "Returns a list of recent identifiers."
        tags:
          - Data Identifiers
        parameters:
        - name: type
          in: query
          description: "The type of the DID."
          schema:
            type: string
          required: false
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "A list of the recent DIDs. Items are separated by new line characters."
                  type: array
                  items:
                    description: "A DID."
                    type: object
                    properties:
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      did_type:
                        description: "The type of the DID."
                        type: string
          401:
            description: "Invalid Auth Token"
          406:
            description: "Not acceptable"
        """
        def generate(_type, vo):
            for did in list_new_dids(did_type=_type, vo=vo):
                yield dumps(did, cls=APIEncoder) + '\n'

        type_param = request.args.get('type', default=None)

        return try_stream(generate(_type=type_param, vo=request.environ['vo']))


class Resurrect(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Resurrect DIDs
        description: "Resurrect all given DIDs."
        tags:
          - Data Identifiers
        requestBody:
          content:
            'application/json':
              schema:
                description: "List of DIDs to resurrect."
                type: array
                items:
                  description: "A DID to resurrect."
                  type: object
                  properties:
                    scope:
                      description: "The scope of the DID."
                      type: string
                    name:
                      description: "The name of the DID"
                      type: string
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          409:
            description: "Conflict"
          500:
            description: "Internal error"
        """
        dids = json_list()

        try:
            resurrect(dids=dids, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except (DuplicateContent, DataIdentifierAlreadyExists, UnsupportedOperation) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        return 'Created', 201


class Follow(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope_name):
        """
        ---
        summary: Get followers
        description: "Get all followers for a specific DID."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  description: "A list of all followers of a DID."
                  type: array
                  items:
                    description: "A follower of a DID."
                    type: object
                    properties:
                      user:
                        description: "The user which follows the DID."
                        type: string
          400:
            description: "Value error"
          401:
            description: "Invalid Auth Token"
          404:
            description: "DID not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])

            def generate(vo):
                for user in get_users_following_did(scope=scope, name=name, vo=vo):
                    yield render_json(**user) + '\n'

            return try_stream(generate(vo=request.environ['vo']), content_type='application/json')
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self, scope_name):
        """
        ---
        summary: Post follow
        description: "Mark the input DID as being followed by the given account."
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - account
                properties:
                  account:
                    description: "The account to follow the DID."
                    type: string
        responses:
          201:
            description: "OK"
          400:
            description: "Scope or name could not be interpreted"
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          500:
            description: "Internal error"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        account = param_get(parameters, 'account')

        try:
            add_did_to_followed(scope=scope, name=name, account=account, vo=request.environ['vo'])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

    def delete(self, scope_name):
        """
        ---
        summary: Delete follow
        description: "Mark the input DID as not followed"
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: "The scope and the name of the DID."
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - account
                properties:
                  account:
                    description: "The account to unfollow the DID."
                    type: string
        responses:
          200:
            description: "OK"
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          500:
            description: "Internal error"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ['vo'])
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        account = param_get(parameters, 'account')

        try:
            remove_did_from_followed(scope=scope, name=name, account=account, issuer=request.environ['issuer'], vo=request.environ['vo'])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200


def blueprint():
    bp = AuthenticatedBlueprint('dids', __name__, url_prefix='/dids')

    scope_view = Scope.as_view('scope')
    bp.add_url_rule('/<scope>/',
                    view_func=scope_view, methods=['get', ])

    guid_lookup_view = GUIDLookup.as_view('guid_lookup')
    bp.add_url_rule('/<guid>/guid',
                    view_func=guid_lookup_view, methods=['get', ])

    search_view = Search.as_view('search')
    bp.add_url_rule('/<scope>/dids/search',
                    view_func=search_view, methods=['get', ])

    dids_view = DIDs.as_view('dids')
    bp.add_url_rule('/<path:scope_name>/status',
                    view_func=dids_view, methods=['put', 'get'])

    files_view = Files.as_view('files')
    bp.add_url_rule('/<path:scope_name>/files',
                    view_func=files_view, methods=['get', ])

    attachment_history_view = AttachmentHistory.as_view('attachment_history')
    bp.add_url_rule('/<path:scope_name>/dids/history',
                    view_func=attachment_history_view, methods=['get', ])

    attachment_view = Attachment.as_view('attachment')
    bp.add_url_rule('/<path:scope_name>/dids',
                    view_func=attachment_view, methods=['get', 'post', 'delete'])

    meta_view = Meta.as_view('meta')
    bp.add_url_rule('/<path:scope_name>/meta',
                    defaults={'key': None}, view_func=meta_view, methods=['get', 'post', 'delete'])
    bp.add_url_rule('/<path:scope_name>/meta/<key>',
                    view_func=meta_view, methods=['post', ])

    bulkdidsmeta_view = BulkDIDsMeta.as_view('bulkdidsmeta')
    bp.add_url_rule('/bulkdidsmeta',
                    view_func=bulkdidsmeta_view, methods=['post', ])

    rules_view = Rules.as_view('rules')
    bp.add_url_rule('/<path:scope_name>/rules',
                    view_func=rules_view, methods=['get', ])

    parents_view = Parents.as_view('parents')
    bp.add_url_rule('/<path:scope_name>/parents',
                    view_func=parents_view, methods=['get', ])

    associated_rules_view = AssociatedRules.as_view('associated_rules')
    bp.add_url_rule('/<path:scope_name>/associated_rules',
                    view_func=associated_rules_view, methods=['get', ])

    follow_view = Follow.as_view('follow')
    bp.add_url_rule('/<path:scope_name>/follow',
                    view_func=follow_view, methods=['get', 'post', 'delete'])
    bp.add_url_rule('/<path:scope_name>',
                    view_func=dids_view, methods=['get', 'post'])

    bulkdids_view = BulkDIDS.as_view('bulkdids')
    bp.add_url_rule('',
                    view_func=bulkdids_view, methods=['post', ])

    sample_view_legacy = SampleLegacy.as_view('sample')
    bp.add_url_rule('/<input_scope>/<input_name>/<output_scope>/<output_name>/<nbfiles>/sample',
                    view_func=sample_view_legacy, methods=['post', ])

    sample_view = Sample.as_view('sample_new')
    bp.add_url_rule('/sample',
                    view_func=sample_view, methods=['post', ])
    attachments_view = Attachments.as_view('attachments')
    bp.add_url_rule('/attachments',
                    view_func=attachments_view, methods=['post', ])

    new_dids_view = NewDIDs.as_view('new_dids')
    bp.add_url_rule('/new',
                    view_func=new_dids_view, methods=['get', ])

    resurrect_view = Resurrect.as_view('resurrect')
    bp.add_url_rule('/resurrect',
                    view_func=resurrect_view, methods=['post', ])

    bulkmeta_view = BulkMeta.as_view('bulkmeta')
    bp.add_url_rule('/bulkmeta',
                    view_func=bulkmeta_view, methods=['post', ])

    files_view = BulkFiles.as_view('bulkfiles')
    bp.add_url_rule('/bulkfiles',
                    view_func=files_view, methods=['post', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
