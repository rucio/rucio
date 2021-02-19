# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
#
# Authors:
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2020
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2020
# - Muhammad Aditya Hilmy <didithilmy@gmail.com>, 2020
# - Alan Malta Rodrigues <alan.malta@cern.ch>, 2020
# - Martin Barisits <martin.barisits@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
from json import dumps

from flask import Flask, Blueprint, Response, request

from rucio.api.did import add_did, add_dids, list_content, list_content_history, list_dids, list_dids_extended, \
    list_files, scope_list, get_did, set_metadata, get_metadata, get_metadata_bulk, set_status, attach_dids, \
    detach_dids, attach_dids_to_dids, get_dataset_by_guid, list_parent_dids, create_did_sample, list_new_dids, \
    resurrect, get_users_following_did, remove_did_from_followed, add_did_to_followed, delete_metadata, \
    set_metadata_bulk
from rucio.api.rule import list_replication_rules, list_associated_replication_rules_for_file
from rucio.common.exception import ScopeNotFound, DataIdentifierNotFound, DataIdentifierAlreadyExists, \
    DuplicateContent, AccessDenied, KeyNotFound, Duplicate, InvalidValueForKey, UnsupportedStatus, \
    UnsupportedOperation, RSENotFound, RuleNotFound, InvalidMetadata, InvalidPath, FileAlreadyExists, InvalidObject, FileConsistencyMismatch
from rucio.common.utils import render_json, APIEncoder
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    parse_scope_name, try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, json_list, param_get, json_parse


class Scope(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope):
        """
        Return all data identifiers in the given scope.

        .. :quickref: Scopes; List all dids for scope

        **Example request**:

        .. sourcecode:: http

            GET /dids/scope1/?name=container1&recursive HTTP/1.1
            Host: rucio.cern.ch

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/x-json-stream

            {"scope": "scope1", "type": "CONTAINER", "name": "container1",
             "parent": null, "level": 0}
            {"scope": "scope1", "type": "DATASET", "name": "dataset1", "parent":
             {"scope": "scope1", "name": "container1"}, "level": 1}
            {"scope": "scope1", "type": "FILE", "name": "file1", "parent":
             {"scope": "scope1", "name": "dataset1"}, "level": 2}

        :query name: specify a DID name
        :query recursive: flag to do a recursive search
        :resheader Content-Type: application/x-json-stream
        :status 200: DIDs found
        :status 401: Invalid Auth Token
        :status 404: no DIDs found in scope
        :status 406: Not Acceptable
        :returns: Line separated dictionaries of DIDs
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
        List all data identifiers in a scope which match a given metadata.

        .. :quickref: Search; Search DIDs in a scope with given metadata.

        **Example request**:

        .. sourcecode:: http

            GET /dids/scope1/dids/search?type=collection&long=True&length.lt=10 HTTP/1.1
            Host: rucio.cern.ch

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/x-json-stream

            {"scope": "scope1", "did_type": "CONTAINER", "name": "container1",
             "bytes": 1234, "length": 1}
            {"scope": "scope1", "did_type": "DATASET", "name": "dataset1",
             "bytes": 234, "length": 3}

        :query type: specify a DID type to search for
        :query limit: The maximum number of DIDs returned.
        :query long: set to True for long output, otherwise only name
        :query recursive: set to True to recursively list DIDs content
        :query created_before: Date string in RFC-1123 format where the creation date was earlier
        :query created_after: Date string in RFC-1123 format where the creation date was later
        :query length: Exact number of attached DIDs
        :query length.gt: Number of attached DIDs greater than
        :query length.lt: Number of attached DIDs less than
        :query length.gte: Number of attached DIDs greater than or equal to
        :query length.lte: Number of attached DIDs less than or equal to
        :query name: Name or pattern of a DID name
        :resheader Content-Type: application/x-json-stream
        :status 200: DIDs found
        :status 401: Invalid Auth Token
        :status 404: Invalid key in filters
        :status 406: Not Acceptable
        :status 409: Wrong DID type
        :returns: Line separated name of DIDs or dictionaries of DIDs for long option
        """
        filters = request.args.copy()
        for param in ['type', 'limit', 'long', 'recursive']:
            if param in filters:
                del filters[param]

        type_param = request.args.get('type', default=None)
        limit = request.args.get('limit', default=None)
        long = request.args.get('long', type=['True', '1'].__contains__, default=False)
        recursive = request.args.get('recursive', type='True'.__eq__, default=False)
        try:
            def generate(vo):
                for did in list_dids(scope=scope, filters=filters, type=type_param, limit=limit, long=long, recursive=recursive, vo=vo):
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
        List all data identifiers in a scope which match a given metadata.
        Extended Version to included meteadata from various plugins.

        .. :quickref: Search; Search DIDs in a scope with given metadata.

        **Example request**:

        .. sourcecode:: http

            GET /dids/scope1/dids/search_extended?type=collection&long=True&length.lt=10 HTTP/1.1
            Host: rucio.cern.ch

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/x-json-stream

            {"scope": "scope1", "did_type": "CONTAINER", "name": "container1",
             "bytes": 1234, "length": 1}
            {"scope": "scope1", "did_type": "DATASET", "name": "dataset1",
             "bytes": 234, "length": 3}

        :query type: specify a DID type to search for
        :query limit: The maximum number of DIDs returned.
        :query long: set to True for long output, otherwise only name
        :query recursive: set to True to recursively list DIDs content
        :query created_before: Date string in RFC-1123 format where the creation date was earlier
        :query created_after: Date string in RFC-1123 format where the creation date was later
        :query length: Exact number of attached DIDs
        :query length.gt: Number of attached DIDs greater than
        :query length.lt: Number of attached DIDs less than
        :query length.gte: Number of attached DIDs greater than or equal to
        :query length.lte: Number of attached DIDs less than or equal to
        :query name: Name or pattern of a DID name
        :resheader Content-Type: application/x-json-stream
        :status 200: DIDs found
        :status 401: Invalid Auth Token
        :status 404: Invalid key in filters
        :status 406: Not Acceptable
        :status 409: Wrong DID type
        :returns: Line separated name of DIDs or dictionaries of DIDs for long option
        """
        filters = request.args.copy()
        for param in ['type', 'limit', 'long', 'recursive']:
            if param in filters:
                del filters[param]

        type_param = request.args.get('type', default=None)
        limit = request.args.get('limit', default=None)
        long = request.args.get('long', type=['True', '1'].__contains__, default=False)
        recursive = request.args.get('recursive', type='True'.__eq__, default=False)
        try:
            def generate(vo):
                for did in list_dids_extended(scope=scope, filters=filters, type=type_param, limit=limit, long=long, recursive=recursive, vo=vo):
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
        Add new DIDs in bulk.

        .. :quickref: BulkDID; Bulk add DIDs.

                **Example request**:

        .. sourcecode:: http

            POST /dids/ HTTP/1.1
            Host: rucio.cern.ch

            [
              {"scope": "scope1", "type": "CONTAINER", "name": "container1",
               "account": "jdoe", "length": 1},
              {"scope": "scope1", "type": "DATASET", "name": "dataset1",
               "account": "jdoe", "length": 3}
            ]


        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 201 Created
            Vary: Accept

        :reqheader Accept: application/json
        :<json string scope: the new DID scope
        :<json string name: the new DID name
        :<json string type: the new DID type
        :<json string account: the owner account of the new DID
        :<json string statuses: monotonic
        :status 201: new DIDs created
        :status 401: Invalid Auth Token
        :status 406: Not Acceptable
        :status 409: DID already exists
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
        Attach DIDs to DIDs

        .. :quickref: Attachements; Attach DIDs to DIDs.
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
        Retrieve a single data identifier.

        .. :quickref: DIDs; Retrieve a single DID.

        **Example request**:

        .. sourcecode:: http

            GET /dids/scope1/dataset1?dynamic HTTP/1.1
            Host: rucio.cern.ch

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/json

            {"scope": "scope1", "did_type": "DATASET", "name": "dataset1",
             "bytes": 234, "length": 3, "account": "jdoe", "open": True,
             "monotonic": False, "expired_at": null}

        :query dynamic: Flag to dynamically calculate size for open DIDs
        :resheader Content-Type: application/json
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: Scope not found
        :status 406: Not Acceptable.
        :returns: Dictionary with DID metadata
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
            dynamic = 'dynamic' in request.args
            did = get_did(scope=scope, name=name, dynamic=dynamic, vo=request.environ.get('vo'))
            return Response(render_json(**did), content_type='application/json')
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (ScopeNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)

    def post(self, scope_name):
        """
        Create a new data identifier.

        .. :quickref: DIDs; Create a new DID.

        .. sourcecode:: http

            POST /dids/scope1/container1 HTTP/1.1
            Host: rucio.cern.ch

            {"type": "CONTAINER", "lifetime": 86400},

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 201 Created
            Vary: Accept

        :reqheader Accept: application/json
        :param scope_name: data identifier (scope)/(name).
        :<json string type: the new DID type
        :<json dict statuses: Dictionary with statuses, e.g. {'monotonic':True}
        :<json dict meta: Dictionary with metadata, e.g. {'length':1234}
        :<json dict rules: Replication rules associated with the did. e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ]
        :<json int lifetime: DID's liftime in seconds.
        :<json list dids: The content.
        :<json string rse: The RSE name when registering replicas.
        :status 201: new DIDs created
        :status 401: Invalid Auth Token
        :status 409: DID already exists
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
                type=type_param,
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
        Update data identifier status.

        .. :quickref: DIDs; Update DID status.

        .. sourcecode:: http

            PUT /dids/scope1/container1 HTTP/1.1
            Host: rucio.cern.ch

            {"open": False},

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept

        :param scope_name: data identifier (scope)/(name).
        :<json bool open: open or close did
        :status 200: DIDs successfully updated
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 409: Wrong status
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
        Returns the contents of a data identifier.

        .. :quickref: Attachement; Get DID contents.

        **Example request**:

        .. sourcecode:: http

            GET /dids/scope1/dataset1?dynamic HTTP/1.1
            Host: rucio.cern.ch

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/json

            {"scope": "scope1", "did_type": "DATASET", "name": "dataset1",
             "bytes": 234, "length": 3, "account": "jdoe", "open": True,
             "monotonic": False, "expired_at": null}

        :query dynamic: Flag to dynamically calculate size for open DIDs
        :resheader Content-Type: application/x-json-stream
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: Scope not found
        :status 406: Not Acceptable
        :returns: Dictionary with DID metadata
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
        Append data identifiers to data identifiers.

        .. :quickref: Attachment; Append DID to DID.

        **Example request**:

        .. sourcecode:: http

            POST /dids/scope1/datasets1/dids HTTP/1.1
            Host: rucio.cern.ch

            [{"scope": "scope1", "name": "file1"},
             {"scope": "scope1", "name": "file2"},
             {"scope": "scope1", "name": "file3"}]

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 201 Created
            Vary: Accept

        :param scope_name: data identifier (scope)/(name).
        :<json list attachments: List of dicts of DIDs to attach.
        :status 201: DIDs successfully attached
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 409: DIDs already attached
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
        Detach data identifiers from data identifiers.

        .. :quickref: DIDs; Detach DID from DID.

        :param scope_name: data identifier (scope)/(name).
        :<json dicts data: Must contain key 'dids' with list of dids to detach.
        :status 200: DIDs successfully detached
        :status 401: Invalid Auth Token
        :status 404: DID not found
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
        Returns the contents history of a data identifier.

        .. :quickref: AttachementHistory; List the content history of a DID.

        :resheader Content-Type: application/x-json-stream
        :param scope_name: data identifier (scope)/(name).
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :returns: Stream of dictionarys with DIDs
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
        """ List all replicas of a data identifier.

        .. :quickref: Files; List replicas of DID.

        :resheader Content-Type: application/x-json-stream
        :param scope_name: data identifier (scope)/(name).
        :query long: Flag to trigger long output
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :returns: A dictionary containing all replicas information.
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
        """ List all parents of a data identifier.

        .. :quickref: Parents; List parents of DID.

        :resheader Content-Type: application/x-json-stream
        :param scope_name: data identifier (scope)/(name).
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable.
        :returns: A list of dictionary containing all dataset information.
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
        List all meta of a data identifier.

        .. :quickref: Meta; List DID metadata.

        :resheader Content-Type: application/json
        :param scope_name: data identifier (scope)/(name).
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :returns: A dictionary containing all meta.
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
        Add metadata to a data identifier in bulk.

        .. :quickref: Meta; Add DID metadata.

        :param scope_name: data identifier (scope)/(name).
        :status 201: Metadata created.
        :status 400: Invalid input data.
        :status 404: DID not found.
        :status 409: Duplicate.
        :returns: Created
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
        Deletes the specified metadata from the DID

        .. :quickref: Meta; Delete DID metadata.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 KeyNotFound
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
        Add metadata to a data identifier.

        .. :quickref: SingleMeta; Add DID metadata.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param scope_name: data identifier (scope)/(name).
        :param key: the key.

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


class Rules(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        Return all rules of a given DID.

        .. :quickref: Rules; List rules of DID.

        :resheader Content-Type: application/x-json-stream
        :param scope_name: data identifier (scope)/(name).
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :returns: List of replication rules.
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
        List all meta of a list of data identifiers.

        .. :quickref: Meta; List metadata of multiple DIDs

        :resheader Content-Type: application/x-json-stream
        :status 200: OK
        :status 400: Bad Request
        :status 401: Unauthorized
        :status 404: DataIdentifierNotFound
        :returns: A list of dictionaries containing all meta.
        """
        parameters = json_parameters()
        dids = param_get(parameters, 'dids')

        try:
            def generate(vo):
                for meta in get_metadata_bulk(dids, vo=vo):
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
        Return all associated rules of a file.

        .. :quickref: AssociatedRules; List associated rules of DID.

        :resheader Content-Type: application/x-json-stream
        :param scope_name: data identifier (scope)/(name).
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :returns: List of associated rules.
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
        Return the file associated to a GUID.

        .. :quickref: GUIDLookup; List file by GUID.

        :resheader Content-Type: application/x-json-stream
        :param guid: the GUID to query by.
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :returns: List of files for given GUID
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
        Return the file associated to a GUID.

        .. :quickref: Sample; Create a sample DID.

        HTTP Success:
            201 Created


        HTTP Error:
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param input_scope: The scope of the input DID.
        :param input_name: The name of the input DID.
        :param output_scope: The scope of the output dataset.
        :param output_name: The name of the output dataset.
        :param nbfiles: The number of files to register in the output dataset.
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
        Returns list of recent identifiers.

        .. :quickref: NewDIDs; List recent DIDs.

        :resheader Content-Type: application/x-json-stream
        :query type: the DID type.
        :status 200: DIDs found
        :status 401: Invalid Auth Token
        :status 406: Not Acceptable
        :returns: List recently created DIDs.
        """
        def generate(_type, vo):
            for did in list_new_dids(type=_type, vo=vo):
                yield dumps(did, cls=APIEncoder) + '\n'

        type_param = request.args.get('type', default=None)

        return try_stream(generate(_type=type_param, vo=request.environ.get('vo')))


class Resurrect(ErrorHandlingMethodView):

    def post(self):
        """
        Resurrect DIDs.

        .. :quickref: Resurrect; Resurrect DID.

        HTTP Success:
            201 Created


        HTTP Error:
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

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
        Return all users following a specific DID.

        .. :quickref: Follow; List users following DID.

        :status 200: OK
        :status 400: ValueError
        :status 401: Unauthorized
        :status 404: DataIdentifierNotFound
        :status 406: Not Acceptable
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
        Mark the input DID as being followed by the given account.

        .. :quickref: Follow; Follow DID.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 Internal Error

        :param scope_name: data identifier (scope)/(name).
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
        Mark the input DID as not followed

        .. :quickref: Follow; Unfollow DID.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope_name: data identifier (scope)/(name).
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
