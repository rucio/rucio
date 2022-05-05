# -*- coding: utf-8 -*-
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

from flask import Flask, Blueprint, Response, request

from rucio.api.did import add_did, add_dids, list_content, list_content_history, list_dids, list_dids_extended, \
    list_files, scope_list, get_did, set_metadata, get_metadata, get_metadata_bulk, set_status, attach_dids, \
    detach_dids, attach_dids_to_dids, get_dataset_by_guid, list_parent_dids, create_did_sample, list_new_dids, \
    resurrect, get_users_following_did, remove_did_from_followed, add_did_to_followed, delete_metadata, \
    set_metadata_bulk, set_dids_metadata_bulk
from rucio.api.rule import list_replication_rules, list_associated_replication_rules_for_file
from rucio.common.exception import ScopeNotFound, DataIdentifierNotFound, DataIdentifierAlreadyExists, \
    DuplicateContent, AccessDenied, KeyNotFound, Duplicate, InvalidValueForKey, UnsupportedStatus, \
    UnsupportedOperation, RSENotFound, RuleNotFound, InvalidMetadata, InvalidPath, FileAlreadyExists, InvalidObject, FileConsistencyMismatch
from rucio.common.utils import render_json, APIEncoder
from rucio.db.sqla.constants import DIDType
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    parse_scope_name, try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, json_list, param_get, json_parse


class Scope(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope):
        """
        ---
        summary: Get Data Identifier
        description: Return all data identifiers in the given scope.
        tags:
          - Data Identifiers
        parameters:
        - name: scope
          in: path
          description: The scope.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  name:
                    description: The name of the did.
                    type: string
                  recursive:
                    description: If specified, also returns the child ids recursively.
                    type: boolean
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: Line seperated dictionary of dids.
                  type: array
                  items:
                    type: object
                    description: Data identifier
                    properties:
                      scope:
                        type: string
                        description: The scope of the did.
                      name:
                        type: string
                        description: The name of the did.
                      type:
                        type: string
                        description: The type of the did.
                        enum: ['F', 'D', 'C', 'A', 'X', 'Y', 'Z']
                      parent:
                        type: string
                        description: The parent of the did.
                      level:
                        type: integer
                        description: The level of the did.
          401:
            description: Invalid Auth Token
          404:
            description: No Dids found
          406:
            description: Not acceptable
        """
        try:
            def generate(name, recursive, vo):
                for did in scope_list(scope=scope, name=name, recursive=recursive, vo=vo):
                    yield render_json(**did) + '\n'

            recursive = 'recursive' in request.args

            return try_stream(
                generate(
                    name=request.args.get('name', default=None),
                    recursive=recursive,
                    vo=request.environ.get('vo')
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
        description: List all data identifiers in a scope which match a given metadata.
        tags:
          - Data Identifiers
        parameters:
        - name: scope
          in: path
          description: The scope of the data identifiers.
          schema:
            type: string
          style: simple
        - name: type
          in: query
          description: The did type to search for.
          schema:
            type: string
            enum: ['all', 'collection', 'container', 'dataset', 'file']
            default: 'collection'
        - name: limit
          in: query
          description: The maximum number od dids returned.
          schema:
            type: integer
        - name: long
          in: query
          description: Provides a longer output, otherwise just prints names.
          schema:
            type: boolean
            default: false
        - name: recursive
          in: query
          description: Recursively list chilred.
          schema:
            type: boolean
        - name: created_before
          in: query
          description: Date string in RFC-1123 format where the creation date was earlier.
          schema:
            type: string
        - name: created_after
          in: query
          description: Date string in RFC-1123 format where the creation date was later.
          schema:
            type: string
        - name: length
          in: query
          description:  Exact number of attached DIDs.
          schema:
            type: integer
        - name: length.gt
          in: query
          description: Number of attached DIDs greater than.
          schema:
            type: integer
        - name: length.lt
          in: query
          description: Number of attached DIDs less than.
          schema:
            type: integer
        - name: length.gte
          in: query
          description: Number of attached DIDs greater than or equal to
          schema:
            type: integer
        - name: length.lte
          in: query
          description: Number of attached DIDs less than or equal to.
          schema:
            type: integer
        - name: name
          in: query
          description: Name or pattern of a did.
          schema:
            type: string
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: Line separated name of DIDs or dictionaries of DIDs for long option.
                  type: array
                  items:
                    type: object
                    description: the name of a DID or a dictionarie of a DID for long option.
          401:
            description: Invalid Auth Token
          404:
            description: Invalid key in filter.
          406:
            description: Not acceptable
          409:
            description: Wrong did type
        """
        filters = request.args.get('filters', default=None)
        if filters is not None:
            filters = ast.literal_eval(filters)
        else:
            # backwards compatability for created*, length* and name filters passed through as request args
            filters = {}
            for arg, value in request.args.copy().items():
                if arg not in ['type', 'limit', 'long', 'recursive']:
                    filters[arg] = value
            filters = [filters]

        did_type = request.args.get('type', default=None)
        limit = request.args.get('limit', default=None)
        long = request.args.get('long', type=['True', '1'].__contains__, default=False)
        recursive = request.args.get('recursive', type='True'.__eq__, default=False)
        try:
            def generate(vo):
                for did in list_dids(scope=scope, filters=filters, did_type=did_type, limit=limit, long=long, recursive=recursive, vo=vo):
                    yield dumps(did) + '\n'
            return try_stream(generate(vo=request.environ.get('vo')))
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, error)
        except KeyNotFound as error:
            return generate_http_error_flask(404, error)


class SearchExtended(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope):
        """
        ---
        summary: List Data identifier with plugin metadata
        description: List all data identifiers in a scope which match a given metadata. Extended Version to included meteadata from various plugins.
        tags:
          - Data Identifiers
        parameters:
        - name: scope
          in: path
          description: The scope of the data identifiers.
          schema:
            type: string
          style: simple
        - name: type
          in: query
          description: The did type to search for.
          schema:
            type: string
            enum: ['all', 'collection', 'container', 'dataset', 'file']
            default: 'collection'
        - name: limit
          in: query
          description: The maximum number od dids returned.
          schema:
            type: integer
        - name: long
          in: query
          description: Provides a longer output, otherwise just prints names.
          schema:
            type: boolean
            default: false
        - name: recursive
          in: query
          description: Recursively list chilred.
          schema:
            type: boolean
        - name: created_before
          in: query
          description: Date string in RFC-1123 format where the creation date was earlier.
          schema:
            type: string
        - name: created_after
          in: query
          description: Date string in RFC-1123 format where the creation date was later.
          schema:
            type: string
        - name: length
          in: query
          description:  Exact number of attached DIDs.
          schema:
            type: integer
        - name: length.gt
          in: query
          description: Number of attached DIDs greater than.
          schema:
            type: integer
        - name: length.lt
          in: query
          description: Number of attached DIDs less than.
          schema:
            type: integer
        - name: length.gte
          in: query
          description: Number of attached DIDs greater than or equal to
          schema:
            type: integer
        - name: length.lte
          in: query
          description: Number of attached DIDs less than or equal to.
          schema:
            type: integer
        - name: name
          in: query
          description: Name or pattern of a did.
          schema:
            type: string
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: Line separated name of DIDs or dictionaries of DIDs for long option.
                  type: array
                  items:
                    type: object
                    description: the name of a DID or a dictionarie of a DID for long option.
          401:
            description: Invalid Auth Token
          404:
            description: Invalid key in filter.
          406:
            description: Not acceptable
          409:
            description: Wrong did type
        """
        filters = request.args.get('filters', default=None)
        if filters is not None:
            filters = ast.literal_eval(filters)
        else:
            # backwards compatability for created*, length* and name filters passed through as request args
            filters = {}
            for arg, value in request.args.copy().items():
                if arg not in ['type', 'limit', 'long', 'recursive']:
                    filters[arg] = value
            filters = [filters]

        did_type = request.args.get('type', default=None)
        limit = request.args.get('limit', default=None)
        long = request.args.get('long', type=['True', '1'].__contains__, default=False)
        recursive = request.args.get('recursive', type='True'.__eq__, default=False)
        try:
            def generate(vo):
                for did in list_dids_extended(scope=scope, filters=filters, did_type=did_type, limit=limit, long=long, recursive=recursive, vo=vo):
                    yield dumps(did) + '\n'
            return try_stream(generate(vo=request.environ.get('vo')))
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, error)
        except KeyNotFound as error:
            return generate_http_error_flask(404, error)


class BulkDIDS(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self):
        """
        ---
        summary: Add Dids bulk
        description: Add new Dids in bulk.
        tags:
          - Data Identifiers
        requestBody:
          content:
            application/json:
              schema:
                type: array
                items:
                  description: One did to add.
                  type: object
                  required:
                    - scope
                    - name
                    - type
                  properties:
                    scope:
                      description: The did scope.
                      type: string
                    name:
                      description: The did name.
                      type: string
                    type:
                      description: The type of the did.
                      type: string
                      enum: ["F", "D", "C", "A", "X", "Y", "Z"]
                    account:
                      description: The account associated with the did.
                      type: string
                    statuses:
                      description: The monotonic status
                      type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
          409:
            description: Did already exists
        """
        dids = json_list()
        try:
            add_dids(dids=dids, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
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
        summary: Attach did to did
        description: Attaches a did to another did
        tags:
          - Data Identifiers
        requestBody:
          content:
            'application/json':
              schema:
                oneOf:
                  - description: An array containing all dids. Duplicates are not ignored.
                    type: array
                    required:
                      - scope
                      - name
                      - dids
                    properties:
                      scope:
                        description: The scope of the did.
                        type: string
                      name:
                        description: The name of the did.
                        type: string
                      dids:
                        description: The dids associated to the did.
                        type: array
                        items:
                          type: object
                          description: A did.
                          required:
                            - scope
                            - name
                          properties:
                            scope:
                              description: The scope of the did.
                              type: string
                            name:
                              description: The name of the did.
                              type: string
                      rse_id:
                        description: The rse id of the did.
                        type: string
                  - type: object
                    required:
                      - attachments
                    properties:
                      ignore_duplicates:
                        description: If duplicates should be ignored.
                        type: boolean
                        default: false
                      attachments:
                        description: An array containing all dids. Duplicates are not ignored.
                        type: array
                        required:
                          - scope
                          - name
                          - dids
                        properties:
                          scope:
                            description: The scope of the did.
                            type: string
                          name:
                            description: The name of the did.
                            type: string
                          dids:
                            description: The dids associated to the did.
                            type: array
                            items:
                              type: object
                              description: A did.
                              required:
                                - scope
                                - name
                              properties:
                                scope:
                                  description: The scope of the did.
                                  type: string
                                name:
                                  description: The name of the did.
                                  type: string
                          rse_id:
                            description: The rse id of the did.
                            type: string
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        parameters = json_parse((dict, list))
        if isinstance(parameters, list):
            attachments = parameters
            ignore_duplicate = False
        else:
            assert isinstance(parameters, dict)
            attachments = param_get(parameters, 'attachments')
            ignore_duplicate = param_get(parameters, 'ignore_duplicate', default=False)

        try:
            attach_dids_to_dids(attachments=attachments, ignore_duplicate=ignore_duplicate, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
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
        summary: Get did
        description: Get a single data identifier.
        tags:
          - Data identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        - name: dynamic_depth
          in: query
          description: The DID type at which to stop the dynamic length/size estimation
          schema:
            type: string
            enum: ["FILE", "DATASET"]
        - name: dynamic
          in: query
          description: Same as dynamic_depth = "FILE"
          deprecated: true
          schema:
            type: string
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  oneOf:
                  - description: A single file did.
                    type: object
                    properties:
                      scope:
                        description: The scope of the did.
                        type: string
                      name:
                        description: The name of the did.
                        type: string
                      type:
                        description: The type of the string.
                        type: string
                      account:
                        description: The associated account.
                        type: string
                      bytes:
                        description: The size in bytes.
                        type: integer
                      length:
                        description: The number of files. Corresponses to 1.
                        type: integer
                        enum: [1]
                      md5:
                        description: md5 checksum.
                        type: string
                      adler32:
                        description: adler32 checksum.
                        type: string
                  - description: A single file did.
                    type: object
                    properties:
                      scope:
                        description: The scope of the did.
                        type: string
                      name:
                        description: The name of the did.
                        type: string
                      type:
                        description: The type of the string.
                        type: string
                      account:
                        description: The associated account.
                        type: string
                      open:
                        description: If the did is write open.
                        type: boolean
                      monotonic:
                        description: If the did is monotonic.
                        type: boolean
                      expired_at:
                        description: When the did expired.
                        type: string
                      length:
                        description: The number of associated dids.
                        type: number
                      bytes:
                        description: The size in bytes.
                        type: number
          401:
            description: Invalid Auth Token
          404:
            description: Scope not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
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
            did = get_did(scope=scope, name=name, dynamic_depth=dynamic_depth, vo=request.environ.get('vo'))
            return Response(render_json(**did), content_type='application/json')
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (ScopeNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)

    def post(self, scope_name):
        """
        ---
        summary: Create did
        description: Create a new data identifier.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
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
                    description: The type of the did.
                    type: string
                  statuses:
                    description: The statuses of the did.
                    type: string
                  meta:
                    description: The meta of the did.
                    type: string
                  rules:
                    description: The rules associated with the did.
                    type: array
                    items:
                      type: object
                      description: A rule.
                  lifetime:
                    description: The lifetime of the did.
                    type: string
                  dids:
                    description: The dids associated with the did.
                    type: array
                    items:
                      type: object
                      description: The did associated with a did.
                      properties:
                        scope:
                          description: The scope of the did.
                          type: string
                        name:
                          description: The name of the did.
                          type: string
                  rse:
                    description: The rse associated with the did.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: Invalid Auth Token
          404:
            description: Did or scope not found
          409:
            description: Did already exists
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
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
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
            )
        except (InvalidObject, InvalidPath) as error:
            return generate_http_error_flask(400, error)
        except (DataIdentifierNotFound, ScopeNotFound) as error:
            return generate_http_error_flask(404, error)
        except (DuplicateContent, DataIdentifierAlreadyExists, UnsupportedOperation) as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return 'Created', 201

    def put(self, scope_name):
        """
        ---
        summary: Update did
        description: Update a did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
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
                    description: The open status
                    type: boolean
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          409:
            description: Wrong status
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()

        try:
            set_status(scope=scope, name=name, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'), **parameters)
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
        summary: Get did
        description: Returns the contents of a data identifier.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: Did found
            content:
              application/x-json-stream:
                schema:
                  description: The contents of a did. Items are line seperated.
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
                        description: The scope of the did.
                        type: string
                      name:
                        description: The name of the did.
                        type: string
                      type:
                        description: The type of the did.
                        type: string
                      bytes:
                        description: The size of the did.
                        type: number
                      adler32:
                        description: The adler32 checksum of the did.
                        type: string
                      md5:
                        description: The md5 checksum of the did.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Scope not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for did in list_content(scope=scope, name=name, vo=vo):
                    yield render_json(**did) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self, scope_name):
        """
        ---
        summary: Add dids to did
        description: Append data identifiers to data identifiers.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
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
                    description: The name of the rse.
                    type: string
                  account:
                    description: The account which attaches the dids.
                    type: string
                  dids:
                    description: The dids to attach.
                    type: object
                    properties:
                      account:
                        description: The account attaching the did.
                        type: string
                      scope:
                        description: The scope of the did.
                        type: string
                      name:
                        description: The name of the did.
                        type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
          409:
            description: Already attached
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        attachments = json_parameters()

        try:
            attach_dids(scope=scope, name=name, attachment=attachments, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
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
        summary: Detach dids from did
        description: Detach data identifiers from data identifiers.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
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
                    description: The dids to detach.
                    type: array
                    items:
                      type: object
                      properties:
                        scope:
                          description: The scope of the did.
                          type: string
                        name:
                          description: The name of the did.
                          type: string
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        dids = param_get(parameters, 'dids')

        try:
            detach_dids(scope=scope, name=name, dids=dids, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
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
        description: Returns the content history of a data identifier.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: Did found
            content:
              application/x-json-stream:
                schema:
                  description: The dids with their information and history. Elements are seperated by new line characters.
                  type: array
                  items:
                    type: object
                    description: A single did with history data.
                    properties:
                      scope:
                        description: The scope of the did.
                        type: string
                      name:
                        description: The name of the did.
                        type: string
                      type:
                        description: The type of the did.
                        type: string
                      bytes:
                        description: The size of the did in bytes.
                        type: integer
                      adler32:
                        description: The abler32 sha checksum.
                        type: string
                      md5:
                        description: The md5 checksum.
                        type: string
                      deleted_at:
                        description: The deleted_at date time.
                        type: string
                      created_at:
                        description: The created_at date time.
                        type: string
                      updated_at:
                        description: The last time the did was updated.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for did in list_content_history(scope=scope, name=name, vo=vo):
                    yield render_json(**did) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
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
        description: List all replicas for a did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        - name: long
          in: query
          description: Flag to trigger long output.
          schema:
            type: object
          required: false
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  oneOf:
                    - description: All replica information if `long` is defined.
                      type: array
                      items:
                        type: object
                        properties:
                          scope:
                            description: The scope of the did.
                            type: string
                          name:
                            description: The name of the did.
                            type: string
                          bytes:
                            description: The size of the did in bytes.
                            type: integer
                          guid:
                            description: The guid of the did.
                            type: string
                          events:
                            description: The number of events of the did.
                            type: integer
                          adler32:
                            description: The adler32 checksum.
                            type: string
                          lumiblocknr:
                            description: The lumi block nr. Only availabe if `long` is defined in the query.
                            type: integer
                    - description: All replica information.
                      type: array
                      items:
                        type: object
                        properties:
                          scope:
                            description: The scope of the did.
                            type: string
                          name:
                            description: The name of the did.
                            type: string
                          bytes:
                            description: The size of the did in bytes.
                            type: integer
                          guid:
                            description: The guid of the did.
                            type: string
                          events:
                            description: The number of events of the did.
                            type: integer
                          adler32:
                            description: The adler32 checksum.
                            type: string
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        long = 'long' in request.args

        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for file in list_files(scope=scope, name=name, long=long, vo=vo):
                    yield dumps(file) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class Parents(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get Parents
        description: Lists all parents of the did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: The parents of the did.
                  type: array
                  items:
                    type: object
                    description: A parent of the did.
                    properties:
                      scope:
                        description: The scope of the did.
                        type: string
                      name:
                        description: The name of the did.
                        type: string
                      type:
                        description: The type of the did.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for dataset in list_parent_dids(scope=scope, name=name, vo=vo):
                    yield render_json(**dataset) + "\n"

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class Meta(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope_name):
        """
        ---
        summary: Get metadata
        description: Get the metadata of a did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        - name: plugin
          in: query
          description: The plugin to use.
          schema:
            type: string
          default: DID_COLUMN
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: A data identifer with all attributes.
                  type: object
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        try:
            plugin = request.args.get('plugin', default='DID_COLUMN')
            meta = get_metadata(scope=scope, name=name, plugin=plugin, vo=request.environ.get('vo'))
            return Response(render_json(**meta), content_type='application/json')
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self, scope_name):
        """
        ---
        summary: Add metadata
        description: Add metadata to a did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type:
                required:
                - meta
                properties:
                  meta:
                    description: The metadata to add. A dictionary containg the metadata name as key and the value as value.
                    type: object
                  recursive:
                    description: Flag if the metadata should be applied recirsively to children.
                    type: boolean
                    default: false
        responses:
          201:
            description: Created
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        meta = param_get(parameters, 'meta')

        try:
            set_metadata_bulk(
                scope=scope,
                name=name,
                meta=meta,
                issuer=request.environ.get('issuer'),
                recursive=param_get(parameters, 'recursive', default=False),
                vo=request.environ.get('vo'),
            )
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except (KeyNotFound, InvalidMetadata, InvalidValueForKey) as error:
            return generate_http_error_flask(400, error)

        return "Created", 201

    def delete(self, scope_name):
        """
        ---
        summary: Delete metadata
        description: Deletes the specified metadata from the did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        - name: key
          in: query
          description: The key to delete.
          schema:
            type: string
        responses:
          200:
            description: OK
          400:
            description: scope_name could not be parsed.
          401:
            description: Invalid Auth Token
          404:
            description: Did or key not found
          406:
            description: Not acceptable
          409:
            description: Feature is not in current database.
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        if 'key' in request.args:
            key = request.args['key']
        else:
            return generate_http_error_flask(404, KeyNotFound.__name__, 'No key provided to remove')

        try:
            delete_metadata(scope=scope, name=name, key=key, vo=request.environ.get('vo'))
        except (KeyNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)
        except NotImplementedError as error:
            return generate_http_error_flask(409, error, 'Feature not in current database')

        return '', 200


class SingleMeta(ErrorHandlingMethodView):
    def post(self, scope_name, key):
        """
        ---
        summary: Add metadata
        description: Add metadata to a did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        - name: key
          in: path
          description: The key for the metadata.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type:
                required:
                - value
                properties:
                  value:
                    description: The value to set.
                    type: AnyValue
        responses:
          201:
            description: Created
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
          409:
            description: Matadata already exists
          400:
            description: Invalid key or value
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        value = param_get(parameters, 'value')

        try:
            set_metadata(
                scope=scope,
                name=name,
                key=key,
                value=value,
                issuer=request.environ.get('issuer'),
                recursive=param_get(parameters, 'recursive', default=False),
                vo=request.environ.get('vo'),
            )
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except (KeyNotFound, InvalidMetadata, InvalidValueForKey) as error:
            return generate_http_error_flask(400, error)

        return 'Created', 201


class BulkDIDsMeta(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Add metadata bulk
        description: Adds metadata in a bulk.
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
                    description: A list with all the dids and the metadata.
                    type: array
                    items:
                      description: The did and associated metadata.
                      type: object
                      properties:
                        scope:
                          description: The scope of the did.
                          type: string
                        name:
                          description: The name of the did.
                          type: string
                        meta:
                          description: The metadata to add. A dictionary with the meta key as key and the value as value.
                          type: object
        responses:
          200:
            description: Created
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
          409:
            description: Unsupported Operation
        """
        parameters = json_parameters()
        dids = param_get(parameters, 'dids')

        try:
            set_dids_metadata_bulk(dids=dids, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
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
        description: Lists all rules of a given did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: The rules associated with a did.
            content:
              application/x-json-stream:
                schema:
                  description: The rules associated with a did.
                  type: array
                  items:
                    description: A rule.
                    type: object
          401:
            description: Invalid Auth Token
          404:
            description: Did or rule not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for rule in list_replication_rules({'scope': scope, 'name': name}, vo=vo):
                    yield dumps(rule, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)


class BulkMeta(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """
        ---
        summary: Get metadata bulk
        description: List all metadata of a list of data identifiers.
        tags:
          - Data Identifiers
        requestBody:
          content:
            'application/x-json-stream':
              schema:
                type:
                required:
                - dids
                properties:
                  dids:
                    description: The dids.
                    type: array
                    items:
                      description: A did.
                      type: object
                      properties:
                        name:
                          description: The name of the did.
                          type: string
                        scope:
                          description: The scope of the did.
                          type: string
                  inherit:
                    description: Concatenated the metadata of the parent if set to true.
                    type: boolean
                    default: false
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: A list of metadata identifiers for the dids. Seperated by new lines.
                  type: array
                  items:
                    description: The metadata for one did.
                    type: object
          400:
            description: Cannot decode json parameter list
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        parameters = json_parameters()
        dids = param_get(parameters, 'dids')
        inherit = param_get(parameters, 'inherit', default=False)

        try:
            def generate(vo):
                for meta in get_metadata_bulk(dids, inherit=inherit, vo=vo):
                    yield render_json(**meta) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error, 'Cannot decode json parameter list')
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class AssociatedRules(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get accociated rules
        description: Gets all associated rules for a file.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: All associated rules for a file. Items are seperated by new line character.
                  type: array
                  items:
                    description: A replication rule associated with the file. Has more fields than listed here.
                    type: object
                    properties:
                      id:
                        description: The id of the rule.
                        type: string
                      subscription_id:
                        description: The subscription id of the rule.
                        type: string
                      account:
                        description: The account associated with the rule.
                        type: string
                      scope:
                        description: The scope associated with the rule.
                        type: string
                      name:
                        description: The name of the rule.
                        type: string
                      state:
                        description: The state of the rule.
                        type: string
                      rse_expression:
                        description: The rse expression of the rule.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for rule in list_associated_replication_rules_for_file(scope=scope, name=name, vo=vo):
                    yield dumps(rule, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
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
        description: Returns the dataset associated with a GUID.
        tags:
          - Data Identifiers
        parameters:
        - name: guid
          in: path
          description: The GUID to query buy.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of all datasets associated with the guid. Items are seperated by new line character.
                  type: array
                  items:
                    description: A dataset associated with a guid.
                    type: object
                    properties:
                      scope:
                        description: The scope of the dataset.
                        type: string
                      name:
                        description: The name of the dataset.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        try:
            def generate(vo):
                for dataset in get_dataset_by_guid(guid, vo=vo):
                    yield dumps(dataset, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class Sample(ErrorHandlingMethodView):

    def post(self, input_scope, input_name, output_scope, output_name, nbfiles):
        """
        ---
        summary: Create sample
        description: Creates a sample from an input collection.
        tags:
          - Data Identifiers
        parameters:
        - name: input_scope
          in: path
          description: The input scope.
          schema:
            type: string
          style: simple
        - name: input_name
          in: path
          description: The input name.
          schema:
            type: string
          style: simple
        - name: output_scope
          in: path
          description: The output scope.
          schema:
            type: string
          style: simple
        - name: output_name
          in: path
          description: The output name.
          schema:
            type: string
          style: simple
        - name: nbfiles
          in: path
          description: The number of files to register in the output dataset.
          schema:
            type: string
          style: simple
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
          409:
            description: Duplication
        """
        try:
            create_did_sample(
                input_scope=input_scope,
                input_name=input_name,
                output_scope=output_scope,
                output_name=output_name,
                issuer=request.environ.get('issuer'),
                nbfiles=nbfiles,
                vo=request.environ.get('vo'),
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
        description: Returns a list of recent identifiers.
        tags:
          - Data Identifiers
        parameters:
        - name: type
          in: query
          description: The type of the did.
          schema:
            type: string
          required: false
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of the recent dids. Items are seperated by new line characters.
                  type: array
                  items:
                    description: A did.
                    type: object
                    properties:
                      scope:
                        description: The scope of the did.
                        type: string
                      name:
                        description: The name of the did.
                        type: string
                      did_type:
                        description: The type of the did.
                        type: string
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
        """
        def generate(_type, vo):
            for did in list_new_dids(did_type=_type, vo=vo):
                yield dumps(did, cls=APIEncoder) + '\n'

        type_param = request.args.get('type', default=None)

        return try_stream(generate(_type=type_param, vo=request.environ.get('vo')))


class Resurrect(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Resurrect dids
        description: Resurrect all given dids.
        tags:
          - Data Identifiers
        requestBody:
          content:
            'application/json':
              schema:
                description: List of did to resurrect.
                type: array
                items:
                  description: A did to resurrect.
                  type: object
                  properties:
                    scope:
                      description: The scope of the did.
                      type: string
                    name:
                      description: The name of the did
                      type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          409:
            description: Conflict
          500:
            description: Internal error
        """
        dids = json_list()

        try:
            resurrect(dids=dids, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
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
        description: Get all followers for a specific did.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: A list of all followers of a did.
                  type: array
                  items:
                    description: A follower of a did.
                    type: object
                    properties:
                      user:
                        description: The user which follows the did.
                        type: string
          400:
            description: Value error
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for user in get_users_following_did(scope=scope, name=name, vo=vo):
                    yield render_json(**user) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')), content_type='application/json')
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self, scope_name):
        """
        ---
        summary: Post follow
        description: Mark the input DID as being followed by the given account.
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
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
                    description: The account to follow the did.
                    type: string
        responses:
          201:
            description: OK
          400:
            description: Scope or name could not be interpreted
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          500:
            description: Internal error
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        account = param_get(parameters, 'account')

        try:
            add_did_to_followed(scope=scope, name=name, account=account, vo=request.environ.get('vo'))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

    def delete(self, scope_name):
        """
        ---
        summary: Delete follow
        description: Mark the input DID as not followed
        tags:
          - Data Identifiers
        parameters:
        - name: scope_name
          in: path
          description: The scope and the name of the did.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type:
                required:
                - account
                properties:
                  account:
                    description: The account to unfollow the did.
                    type: string
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          500:
            description: Internal error
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        parameters = json_parameters()
        account = param_get(parameters, 'account')

        try:
            remove_did_from_followed(scope=scope, name=name, account=account, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200


def blueprint():
    bp = Blueprint('dids', __name__, url_prefix='/dids')

    scope_view = Scope.as_view('scope')
    bp.add_url_rule('/<scope>/', view_func=scope_view, methods=['get', ])
    guid_lookup_view = GUIDLookup.as_view('guid_lookup')
    bp.add_url_rule('/<guid>/guid', view_func=guid_lookup_view, methods=['get', ])
    search_view = Search.as_view('search')
    bp.add_url_rule('/<scope>/dids/search', view_func=search_view, methods=['get', ])
    search_extended_view = SearchExtended.as_view('search_extended')
    bp.add_url_rule('/<scope>/dids/search_extended', view_func=search_extended_view, methods=['get', ])
    dids_view = DIDs.as_view('dids')
    bp.add_url_rule('/<path:scope_name>/status', view_func=dids_view, methods=['put', ])
    files_view = Files.as_view('files')
    bp.add_url_rule('/<path:scope_name>/files', view_func=files_view, methods=['get', ])
    attachment_history_view = AttachmentHistory.as_view('attachment_history')
    bp.add_url_rule('/<path:scope_name>/dids/history', view_func=attachment_history_view, methods=['get', ])
    attachment_view = Attachment.as_view('attachment')
    bp.add_url_rule('/<path:scope_name>/dids', view_func=attachment_view, methods=['get', 'post', 'delete'])
    meta_view = Meta.as_view('meta')
    bp.add_url_rule('/<path:scope_name>/meta', view_func=meta_view, methods=['get', 'post', 'delete'])
    singlemeta_view = SingleMeta.as_view('singlemeta')
    bp.add_url_rule('/<path:scope_name>/meta/<key>', view_func=singlemeta_view, methods=['post', ])
    bulkdidsmeta_view = BulkDIDsMeta.as_view('bulkdidsmeta')
    bp.add_url_rule('/bulkdidsmeta', view_func=bulkdidsmeta_view, methods=['post', ])
    rules_view = Rules.as_view('rules')
    bp.add_url_rule('/<path:scope_name>/rules', view_func=rules_view, methods=['get', ])
    parents_view = Parents.as_view('parents')
    bp.add_url_rule('/<path:scope_name>/parents', view_func=parents_view, methods=['get', ])
    associated_rules_view = AssociatedRules.as_view('associated_rules')
    bp.add_url_rule('/<path:scope_name>/associated_rules', view_func=associated_rules_view, methods=['get', ])
    follow_view = Follow.as_view('follow')
    bp.add_url_rule('/<path:scope_name>/follow', view_func=follow_view, methods=['get', 'post', 'delete'])
    bp.add_url_rule('/<path:scope_name>', view_func=dids_view, methods=['get', 'post'])
    bulkdids_view = BulkDIDS.as_view('bulkdids')
    bp.add_url_rule('', view_func=bulkdids_view, methods=['post', ])
    sample_view = Sample.as_view('sample')
    bp.add_url_rule('/<input_scope>/<input_name>/<output_scope>/<output_name>/<nbfiles>/sample', view_func=sample_view, methods=['post', ])
    attachements_view = Attachments.as_view('attachments')
    bp.add_url_rule('/attachments', view_func=attachements_view, methods=['post', ])
    new_dids_view = NewDIDs.as_view('new_dids')
    bp.add_url_rule('/new', view_func=new_dids_view, methods=['get', ])
    resurrect_view = Resurrect.as_view('resurrect')
    bp.add_url_rule('/resurrect', view_func=resurrect_view, methods=['post', ])
    bulkmeta_view = BulkMeta.as_view('bulkmeta')
    bp.add_url_rule('/bulkmeta', view_func=bulkmeta_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
