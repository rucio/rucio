#!/usr/bin/env python
# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Angelos Molfetas <angelos.molfetas@cern.ch>, 2012
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Yun-Pin Sun <yun-pin.sun@cern.ch>, 2013
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2018
# - Martin Baristis <martin.barisits@cern.ch>, 2014-2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from __future__ import print_function
from json import dumps, loads
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.did import (add_did, add_dids, list_content, list_content_history,
                           list_dids, list_files, scope_list, get_did, set_metadata,
                           get_metadata, set_status, attach_dids, detach_dids,
                           attach_dids_to_dids, get_dataset_by_guid, list_parent_dids,
                           create_did_sample, list_new_dids, resurrect)
from rucio.api.rule import list_replication_rules, list_associated_replication_rules_for_file
from rucio.common.exception import (ScopeNotFound, DataIdentifierNotFound,
                                    DataIdentifierAlreadyExists, DuplicateContent,
                                    AccessDenied, KeyNotFound, DatabaseException,
                                    Duplicate, InvalidValueForKey,
                                    UnsupportedStatus, UnsupportedOperation,
                                    RSENotFound, RucioException, RuleNotFound,
                                    InvalidMetadata)
from rucio.common.utils import generate_http_error_flask, render_json, APIEncoder
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask


class Scope(MethodView):

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

        name = request.args.get('name', None)
        recursive = False
        if 'recursive' in request.args:
            recursive = True

        try:
            data = ""
            for did in scope_list(scope=scope, name=name, recursive=recursive):
                data += render_json(**did) + '\n'
            return Response(data, content_type='application/x-json-stream')
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class Search(MethodView):

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

        filters = {}
        long = False
        recursive = False
        type = 'collection'
        for k, v in request.args.items():
            if k == 'type':
                type = v
            elif k == 'long':
                long = v == '1'
            elif k == 'recursive':
                recursive = v == 'True'
            else:
                filters[k] = v

        try:
            data = ""
            for did in list_dids(scope=scope, filters=filters, type=type, long=long, recursive=recursive):
                data += dumps(did) + '\n'
            return Response(data, content_type='application/x-json-stream')
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except KeyNotFound as error:
            return generate_http_error_flask(404, 'KeyNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class BulkDIDS(MethodView):

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
        :status 500: Database Exception
        """
        try:
            json_data = loads(request.data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            print(json_data)
            add_dids(json_data, issuer=request.environ.get('issuer'))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            return generate_http_error_flask(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except DatabaseException as error:
            return generate_http_error_flask(500, 'DatabaseException', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return "Created", 201


class Attachments(MethodView):

    def post(self):
        """
        Attach DIDs to DIDs

        .. :quickref: Attachements; Attach DIDs to DIDs.
        """

        # To be moved in a common processor

        attachments, ignore_duplicate = [], False
        try:
            json_data = loads(request.data)
            if type(json_data) is dict:
                attachments = json_data.get('attachments')
                ignore_duplicate = json_data.get('ignore_duplicate')
            elif type(json_data) is list:
                attachments = json_data
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            attach_dids_to_dids(attachments=attachments, ignore_duplicate=ignore_duplicate, issuer=request.environ.get('issuer'))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            return generate_http_error_flask(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        return "Created", 201


class DIDs(MethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope, name):
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
            dynamic = False
            if 'dynamic' in request.args:
                dynamic = True
            did = get_did(scope=scope, name=name, dynamic=dynamic)
            return Response(render_json(**did), content_type='application/json')
        except ScopeNotFound as error:
            return generate_http_error_flask(404, 'ScopeNotFound', error.args[0])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

    def post(self, scope, name):
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
        :param scope: data identifier scope.
        :param name: data identifier name.
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
        :status 500: Database Exception
        """
        statuses, meta, rules, lifetime, dids, rse = {}, {}, [], None, [], None
        try:
            json_data = loads(request.data)
            type = json_data['type']
            if 'statuses' in json_data:
                statuses = json_data['statuses']
            if 'meta' in json_data:
                meta = json_data['meta']
            if 'rules' in json_data:
                rules = json_data['rules']
            if 'lifetime' in json_data:
                lifetime = json_data['lifetime']
            if 'dids' in json_data:
                dids = json_data['dids']
            if 'rse' in json_data:
                rse = json_data['rse']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')
        except KeyError as error:
            return generate_http_error_flask(400, 'ValueError', str(error))

        try:
            add_did(scope=scope, name=name, type=type, statuses=statuses, meta=meta, rules=rules, lifetime=lifetime, dids=dids, rse=rse, issuer=request.environ.get('issuer'))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            return generate_http_error_flask(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except DatabaseException as error:
            return generate_http_error_flask(500, 'DatabaseException', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return "Created", 201

    def put(self, scope, name):
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

        :param scope: data identifier scope.
        :param name: data identifier name.
        :<json bool open: open or close did
        :status 200: DIDs successfully updated
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 409: Wrong status
        :status 500: Database Exception
        """

        json_data = request.data
        try:
            kwargs = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json data parameter')

        try:
            set_status(scope=scope, name=name, issuer=request.environ.get('issuer'), **kwargs)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except UnsupportedStatus as error:
            return generate_http_error_flask(409, 'UnsupportedStatus', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        return "Ok", 200


class Attachment(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
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
            data = ""
            for did in list_content(scope=scope, name=name):
                data += render_json(**did) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

    def post(self, scope, name):
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

        :param scope: The scope of the DID to attach to.
        :param name: The name of the DID to attach to.
        :<json list attachments: List of dicts of DIDs to attach.
        :status 201: DIDs successfully attached
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 409: DIDs already attached
        :status 500: Database Exception
        """

        try:
            json_data = loads(request.data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            attach_dids(scope=scope, name=name, attachment=json_data, issuer=request.environ.get('issuer'))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            return generate_http_error_flask(409, 'DuplicateContent', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        return "Created", 201

    def delete(self, scope, name):
        """
        Detach data identifiers from data identifiers.

        .. :quickref: DIDs; Detach DID from DID.

        :param scope: Scope of the DID to detach from.
        :param name: Name of the DID to detach from.
        :<json dicts data: Must contain key 'dids' with list of dids to detach.
        :status 200: DIDs successfully detached
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 500: Database Exception
        """

        try:
            json_data = loads(request.data)
            if 'dids' in json_data:
                dids = json_data['dids']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            detach_dids(scope=scope, name=name, dids=dids, issuer=request.environ.get('issuer'))
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        return "OK", 200


class AttachmentHistory(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
        """
        Returns the contents history of a data identifier.

        .. :quickref: AttachementHistory; List the content history of a DID.

        :resheader Content-Type: application/x-json-stream
        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: Stream of dictionarys with DIDs
        """
        try:
            data = ""
            for did in list_content_history(scope=scope, name=name):
                data += render_json(**did) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class Files(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
        """ List all replicas of a data identifier.

        .. :quickref: Files; List replicas of DID.

        :resheader Content-Type: application/x-json-stream
        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.
        :query long: Flag to trigger long output
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: A dictionary containing all replicas information.
        """
        long = False

        if "long" in request.args:
            long = True
        try:
            data = ""
            for file in list_files(scope=scope, name=name, long=long):
                data += dumps(file) + "\n"
            return Response(data, content_type="application/x-json-stream")
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class Parents(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
        """ List all parents of a data identifier.

        .. :quickref: Parents; List parents of DID.

        :resheader Content-Type: application/x-json-stream
        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable.
        :status 500: Database Exception
        :returns: A list of dictionary containing all dataset information.
        """
        try:
            data = ""
            for dataset in list_parent_dids(scope=scope, name=name):
                data += render_json(**dataset) + "\n"
            return Response(data, content_type="application/x-json-stream")
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class Meta(MethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope, name):
        """
        List all meta of a data identifier.

        .. :quickref: Meta; List DID metadata.

        :resheader Content-Type: application/json
        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: A dictionary containing all meta.
        """
        try:
            meta = get_metadata(scope=scope, name=name)
            return Response(render_json(**meta), content_type='application/json')
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

    def post(self, scope, name, key):
        """
        Add metadata to a data identifier.

        .. :quickref: Meta; Add DID metadata.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param scope: The scope name.
        :param name: The data identifier name.
        :param key: the key.

        """
        json_data = request.data
        try:
            params = loads(json_data)
            value = params['value']
            recursive = params.get('recursive', False)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')
        try:
            set_metadata(scope=scope, name=name, key=key, value=value,
                         issuer=request.environ.get('issuer'), recursive=recursive)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except KeyNotFound as error:
            return generate_http_error_flask(400, 'KeyNotFound', error.args[0])
        except InvalidMetadata as error:
            return generate_http_error_flask(400, 'InvalidMetadata', error.args[0])
        except InvalidValueForKey as error:
            return generate_http_error_flask(400, 'InvalidValueForKey', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        return "Created", 201


class Rules(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
        """
        Return all rules of a given DID.

        .. :quickref: Rules; List rules of DID.

        :resheader Content-Type: application/x-json-stream
        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: List of replication rules.
        """

        try:
            data = ""
            for rule in list_replication_rules({'scope': scope, 'name': name}):
                data += dumps(rule, cls=APIEncoder) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except RuleNotFound as error:
            return generate_http_error_flask(404, 'RuleNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500


class AssociatedRules(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
        """
        Return all associated rules of a file.

        .. :quickref: AssociatedRules; List associated rules of DID.

        :resheader Content-Type: application/x-json-stream
        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.
        :status 200: DID found
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: List of associated rules.
        """
        try:
            data = ""
            for rule in list_associated_replication_rules_for_file(scope=scope, name=name):
                data += dumps(rule, cls=APIEncoder) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500


class GUIDLookup(MethodView):

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
        :status 500: Database Exception
        :returns: List of files for given GUID
        """
        try:
            data = ""
            for dataset in get_dataset_by_guid(guid):
                data += dumps(dataset, cls=APIEncoder) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500


class Sample(MethodView):

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
            create_did_sample(input_scope=input_scope, input_name=input_name, output_scope=output_scope, output_name=output_name, issuer=request.environ.get('issuer'), nbfiles=nbfiles)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            return generate_http_error_flask(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except DatabaseException as error:
            return generate_http_error_flask(500, 'DatabaseException', error.args)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return "Created", 201


class NewDIDs(MethodView):

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
        :status 500: Database Exception
        :returns: List recently created DIDs.
        """

        type = None
        if 'type' in request.args:
            type = request.args.get('type')
        try:
            data = ""
            for did in list_new_dids(type):
                data += dumps(did, cls=APIEncoder) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500


class Resurrect(MethodView):

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
        json_data = request.data
        try:
            dids = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            resurrect(dids=dids, issuer=request.environ.get('issuer'))
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            return generate_http_error_flask(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except DatabaseException as error:
            return generate_http_error_flask(500, 'DatabaseException', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return "Created", 201


bp = Blueprint('did', __name__)

scope_view = Scope.as_view('scope')
bp.add_url_rule('/<scope>/', view_func=scope_view, methods=['get', ])
guid_lookup_view = GUIDLookup.as_view('guid_lookup')
bp.add_url_rule('/<guid>/guid', view_func=guid_lookup_view, methods=['get', ])
search_view = Search.as_view('search')
bp.add_url_rule('/<scope>/dids/search', view_func=search_view, methods=['get', ])
bulkdids_view = BulkDIDS.as_view('bulkdids')
bp.add_url_rule('/', view_func=bulkdids_view, methods=['post', ])
attachements_view = Attachments.as_view('attachments')
bp.add_url_rule('/attachments', view_func=attachements_view, methods=['post', ])
dids_view = DIDs.as_view('dids')
bp.add_url_rule('/<scope>/<name>', view_func=dids_view, methods=['get', 'post'])
bp.add_url_rule('/<scope>/<name>/status', view_func=dids_view, methods=['put', ])
files_view = Files.as_view('files')
bp.add_url_rule('/<scope>/<name>/files', view_func=files_view, methods=['get', ])
attachment_history_view = AttachmentHistory.as_view('attachment_history')
bp.add_url_rule('/<scope>/<name>/dids/history', view_func=attachment_history_view, methods=['get', ])
attachment_view = Attachment.as_view('attachment')
bp.add_url_rule('/<scope>/<name>/dids', view_func=attachment_view, methods=['get', 'post', 'delete'])
meta_view = Meta.as_view('meta')
bp.add_url_rule('/<scope>/<name>/meta', view_func=meta_view, methods=['get', ])
bp.add_url_rule('/<scope>/<name>/meta/<key>', view_func=meta_view, methods=['post', ])
rules_view = Rules.as_view('rules')
bp.add_url_rule('/<scope>/<name>/rules', view_func=rules_view, methods=['get', ])
parents_view = Parents.as_view('parents')
bp.add_url_rule('/<scope>/<name>/parents', view_func=parents_view, methods=['get', ])
associated_rules_view = AssociatedRules.as_view('associated_rules')
bp.add_url_rule('/<scope>/<name>/associated_rules', view_func=associated_rules_view, methods=['get', ])
sample_view = Sample.as_view('sample')
bp.add_url_rule('/<input_scope>/<input_name>/<output_scope>/<output_name>/<nbfiles>/sample', view_func=sample_view, methods=['post', ])
new_dids_view = NewDIDs.as_view('new_dids')
bp.add_url_rule('/new', view_func=new_dids_view, methods=['get', ])
resurrect_view = Resurrect.as_view('resurrect')
bp.add_url_rule('/resurrect', view_func=resurrect_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/dids')
    return doc_app


if __name__ == "__main__":
    application.run()
