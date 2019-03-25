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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2013,2015
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Yun-Pin Sun <yun-pin.sun@cern.ch>, 2013
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2018
# - Martin Baristis <martin.barisits@cern.ch>, 2014-2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from json import dumps, loads
from traceback import format_exc
try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs
from web import application, ctx, data, Created, header, InternalError, OK, loadhook

from rucio.api.did import (add_did, add_dids, list_content, list_content_history,
                           list_dids, list_files, scope_list, get_did, set_metadata,
                           get_metadata, set_status, attach_dids, detach_dids,
                           attach_dids_to_dids, get_dataset_by_guid, list_parent_dids,
                           create_did_sample, list_new_dids, resurrect, get_did_meta,
                           add_did_meta, list_dids_by_meta, delete_did_meta)
from rucio.api.rule import list_replication_rules, list_associated_replication_rules_for_file
from rucio.common.exception import (ScopeNotFound, DataIdentifierNotFound,
                                    DataIdentifierAlreadyExists, DuplicateContent,
                                    AccessDenied, KeyNotFound, DatabaseException,
                                    Duplicate, InvalidValueForKey,
                                    UnsupportedStatus, UnsupportedOperation,
                                    RSENotFound, RucioException, RuleNotFound,
                                    InvalidMetadata)
from rucio.common.schema import SCOPE_NAME_REGEXP
from rucio.common.utils import generate_http_error, render_json, APIEncoder
from rucio.web.rest.common import rucio_loadhook, RucioController, check_accept_header_wrapper

URLS = (
    '/(.*)/$', 'Scope',
    '/(.*)/guid', 'GUIDLookup',
    '/(.*)/dids/search', 'Search',
    '%s/files' % SCOPE_NAME_REGEXP, 'Files',
    '%s/dids/history' % SCOPE_NAME_REGEXP, 'AttachmentHistory',
    '%s/dids' % SCOPE_NAME_REGEXP, 'Attachment',
    '%s/meta/(.*)' % SCOPE_NAME_REGEXP, 'Meta',
    '%s/meta' % SCOPE_NAME_REGEXP, 'Meta',
    '%s/status' % SCOPE_NAME_REGEXP, 'DIDs',
    '%s/rules' % SCOPE_NAME_REGEXP, 'Rules',
    '%s/parents' % SCOPE_NAME_REGEXP, 'Parents',
    '%s/associated_rules' % SCOPE_NAME_REGEXP, 'AssociatedRules',
    '%s/did_meta' % SCOPE_NAME_REGEXP, 'DidMeta',
    '/(.*)/(.*)/(.*)/(.*)/(.*)/sample', 'Sample',
    '%s' % SCOPE_NAME_REGEXP, 'DIDs',
    '', 'BulkDIDS',
    '/attachments', 'Attachments',
    '/new', 'NewDIDs',
    '/resurrect', 'Resurrect',
    '/list_dids_by_meta', 'ListByMeta',
)


class Scope(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope):
        """
        Return all data identifiers in the given scope.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        name = None
        recursive = False
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'name' in params:
                name = params['name'][0]
            if 'recursive' in params:
                recursive = True

        try:
            for did in scope_list(scope=scope, name=name, recursive=recursive):
                yield render_json(**did) + '\n'
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class Search(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope):
        """
        List all data identifiers in a scope which match a given metadata.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 KeyNotFound
            406 Not Acceptable
            409 UnsupportedOperation

        :param scope: The scope name.
        """

        header('Content-Type', 'application/x-json-stream')
        filters = {}
        long = False
        recursive = False
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            for k, v in params.items():
                if k == 'type':
                    type = v[0]
                elif k == 'long':
                    long = v[0] == '1'
                elif k == 'recursive':
                    recursive = v[0] == 'True'
                else:
                    filters[k] = v[0]

        try:
            for did in list_dids(scope=scope, filters=filters, type=type, long=long, recursive=recursive):
                yield dumps(did) + '\n'
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except KeyNotFound as error:
            raise generate_http_error(404, 'KeyNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class BulkDIDS(RucioController):

    def POST(self):
        try:
            json_data = loads(data())
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_dids(json_data, issuer=ctx.env.get('issuer'))
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except DatabaseException as error:
            raise generate_http_error(500, 'DatabaseException', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


class Attachments(RucioController):

    def POST(self):

        # To be moved in a common processor

        attachments, ignore_duplicate = [], False
        try:
            json_data = loads(data())
            if type(json_data) is dict:
                attachments = json_data.get('attachments')
                ignore_duplicate = json_data.get('ignore_duplicate')
            elif type(json_data) is list:
                attachments = json_data
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            attach_dids_to_dids(attachments=attachments, ignore_duplicate=ignore_duplicate, issuer=ctx.env.get('issuer'))
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise Created()


class DIDs(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def GET(self, scope, name):
        """
        Retrieve a single data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 Not Found

        :param scope: The scope name.
        :param name: The data identifier name.
        """
        header('Content-Type', 'application/json')
        try:
            dynamic = False
            if ctx.query:
                params = parse_qs(ctx.query[1:])
                if 'dynamic' in params:
                    dynamic = True
            did = get_did(scope=scope, name=name, dynamic=dynamic)
            return render_json(**did)
        except ScopeNotFound as error:
            raise generate_http_error(404, 'ScopeNotFound', error.args[0])
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def POST(self, scope, name):
        """
        Create a new data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope: Create the data identifier within this scope.
        :param name: Create the data identifier with this name.
        """
        statuses, meta, rules, lifetime, dids, rse = {}, {}, [], None, [], None
        try:
            json_data = loads(data())
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
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')
        except KeyError as error:
            raise generate_http_error(400, 'ValueError', str(error))

        try:
            add_did(scope=scope, name=name, type=type, statuses=statuses, meta=meta, rules=rules, lifetime=lifetime, dids=dids, rse=rse, issuer=ctx.env.get('issuer'))
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except DatabaseException as error:
            raise generate_http_error(500, 'DatabaseException', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()

    def PUT(self, scope, name):
        """
        Update data identifier status.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope: data identifier scope.
        :param name: data identifier name.
        """
        json_data = data()
        try:
            kwargs = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json data parameter')

        try:
            set_status(scope=scope, name=name, issuer=ctx.env.get('issuer'), **kwargs)
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except UnsupportedStatus as error:
            raise generate_http_error(409, 'UnsupportedStatus', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise OK()


class Attachment(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """
        Returns the contents of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.

        :returns: A list with the contents.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for did in list_content(scope=scope, name=name):
                yield render_json(**did) + '\n'
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def POST(self, scope, name):
        """
        Append data identifiers to data identifiers.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope: Create the data identifier within this scope.
        :param name: Create the data identifier with this name.
        """
        try:
            json_data = loads(data())
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            attach_dids(scope=scope, name=name, attachment=json_data, issuer=ctx.env.get('issuer'))
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise Created()

    def DELETE(self, scope, name):
        """
        Detach data identifiers from data identifiers.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope: Detach the data identifier from this scope.
        :param name: Detach the data identifier from this name.
        """
        try:
            json_data = loads(data())
            if 'dids' in json_data:
                dids = json_data['dids']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            detach_dids(scope=scope, name=name, dids=dids, issuer=ctx.env.get('issuer'))
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise OK()


class AttachmentHistory(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """
        Returns the contents history of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.

        :returns: A list with the contents.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for did in list_content_history(scope=scope, name=name):
                yield render_json(**did) + '\n'
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class Replicas(RucioController):

    def GET(self, scope, name):
        raise DeprecationWarning('Use endpoint /replicas instead')


class Files(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """ List all replicas of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :returns: A dictionary containing all replicas information.
        """
        header('Content-Type', 'application/x-json-stream')
        long = False
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'long' in params:
                long = True
        try:
            for file in list_files(scope=scope, name=name, long=long):
                yield dumps(file) + "\n"
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class Parents(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """ List all parents of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :returns: A list of dictionary containing all dataset information.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for dataset in list_parent_dids(scope=scope, name=name):
                yield render_json(**dataset) + "\n"
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class Meta(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def GET(self, scope, name):
        """
        List all meta of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 DataIdentifierNotFound
            406 Not Acceptable
            500 InternalError

        :param scope: The scope name.
        :param name: The data identifier name.

        :returns: A dictionary containing all meta.
        """
        header('Content-Type', 'application/json')
        try:
            meta = get_metadata(scope=scope, name=name)
            return render_json(**meta)
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def POST(self, scope, name, key):
        """
        Add metadata to a data identifier.

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
        json_data = data()
        try:
            params = loads(json_data)
            value = params['value']
            recursive = params.get('recursive', False)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')
        try:
            set_metadata(scope=scope, name=name, key=key, value=value,
                         issuer=ctx.env.get('issuer'), recursive=recursive)
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except KeyNotFound as error:
            raise generate_http_error(400, 'KeyNotFound', error.args[0])
        except InvalidMetadata as error:
            raise generate_http_error(400, 'InvalidMetadata', error.args[0])
        except InvalidValueForKey as error:
            raise generate_http_error(400, 'InvalidValueForKey', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise Created()


class Rules(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """
        Return all rules of a given DID.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for rule in list_replication_rules({'scope': scope, 'name': name}):
                yield dumps(rule, cls=APIEncoder) + '\n'
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)


class AssociatedRules(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """
        Return all associated rules of a file.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for rule in list_associated_replication_rules_for_file(scope=scope, name=name):
                yield dumps(rule, cls=APIEncoder) + '\n'
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)


class GUIDLookup(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, guid):
        """
        Return the file associated to a GUID.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for dataset in get_dataset_by_guid(guid):
                yield dumps(dataset, cls=APIEncoder) + '\n'
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)


class Sample(RucioController):

    def POST(self, input_scope, input_name, output_scope, output_name, nbfiles):
        """
        Return the file associated to a GUID.

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
            create_did_sample(input_scope=input_scope, input_name=input_name, output_scope=output_scope, output_name=output_name, issuer=ctx.env.get('issuer'), nbfiles=nbfiles)
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except DatabaseException as error:
            raise generate_http_error(500, 'DatabaseException', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


class NewDIDs(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """
        Returns list of recent identifiers.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable

        :param type: The DID type.
        """
        header('Content-Type', 'application/x-json-stream')
        params = parse_qs(ctx.query[1:])

        type = None
        if 'type' in params:
            type = params['type'][0]
        try:
            for did in list_new_dids(type):
                yield dumps(did, cls=APIEncoder) + '\n'
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)


class Resurrect(RucioController):

    def POST(self):
        """
        Resurrect DIDs.

        HTTP Success:
            201 Created


        HTTP Error:
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        """
        json_data = data()
        try:
            dids = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            resurrect(dids=dids, issuer=ctx.env.get('issuer'))
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except DuplicateContent as error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0])
        except DataIdentifierAlreadyExists as error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except DatabaseException as error:
            raise generate_http_error(500, 'DatabaseException', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


class ListByMeta(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """
        List all data identifiers in a scope(optional) which match a given metadata.

        HTTP Success:
            200 OK

        HTTP Error:
            406 Not Acceptable
            500 Server Error

        :param scope: The scope name.
        """

        select = {}
        scope = ""
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'scope' in params:
                scope = params['scope'][0]
            if 'select' in params:
                select = loads(params['select'][0])

        try:
            dids = list_dids_by_meta(scope=scope, select=select)
            yield dumps(dids, cls=APIEncoder) + '\n'
        except NotImplementedError:
            raise generate_http_error(409, 'NotImplementedError', 'Feature not in current database')
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class DidMeta(RucioController):

    def POST(self, scope, name):
        """
        Add did_meta to DID
        HTTP Success:
        201 Created

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 Internal Error

        """
        json_data = data()
        try:
            meta = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_did_meta(scope=scope, name=name, meta=meta)
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except DataIdentifierAlreadyExists as error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except NotImplementedError:
            raise generate_http_error(409, 'NotImplementedError', 'Feature not in current database')
        except DatabaseException as error:
            raise generate_http_error(500, 'DatabaseException', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """
        Gets metadata for a did
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 DataIdentifier Not found
            406 Not Acceptable
            409 NotImplemented
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            meta = get_did_meta(scope=scope, name=name)
            yield dumps(meta, cls=APIEncoder) + "\n"
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except NotImplementedError:
            raise generate_http_error(409, 'NotImplementedError', 'Feature not in current database')
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

    def DELETE(self, scope, name):
        """
        Deletes the specified key from the DID
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 KeyNotFound
        """
        key = ""
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'key' in params:
                key = params['key'][0]
            else:
                raise generate_http_error(404, 'KeyNotFound', 'No key provided to remove')

        try:
            delete_did_meta(scope=scope, name=name, key=key)
        except KeyNotFound as error:
            raise generate_http_error(404, 'KeyNotFound', error.args[0])
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except NotImplementedError:
            raise generate_http_error(409, 'NotImplementedError', 'Feature not in current database')
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise OK()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
