#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012-2013,2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2016
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2014
# - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2015
# - Martin Baristis, <martin.barisits@cern.ch>, 2014-2015

from json import dumps, loads
from traceback import format_exc
from urlparse import parse_qs
from web import application, ctx, data, Created, header, InternalError, OK, loadhook

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
from rucio.common.schema import SCOPE_NAME_REGEXP
from rucio.common.utils import generate_http_error, render_json, APIEncoder
from rucio.web.rest.common import rucio_loadhook, RucioController

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
    '/(.*)/(.*)/(.*)/(.*)/(.*)/sample', 'Sample',
    '%s' % SCOPE_NAME_REGEXP, 'DIDs',
    '', 'BulkDIDS',
    '/attachments', 'Attachments',
    '/new', 'NewDIDs',
    '/resurrect', 'Resurrect',
)


class Scope(RucioController):

    def GET(self, scope):
        """
        Return all data identifiers in the given scope.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
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
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)


class Search(RucioController):

    def GET(self, scope):
        """
        List all data identifiers in a scope which match a given metadata.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 KeyNotFound
            409 UnsupportedOperation

        :param scope: The scope name.
        """

        header('Content-Type', 'application/x-json-stream')
        filters = {}
        long = False
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            for k, v in params.items():
                if k == 'type':
                    type = v[0]
                elif k == 'long':
                    long = bool(v[0])
                else:
                    filters[k] = v[0]

        try:
            for did in list_dids(scope=scope, filters=filters, type=type, long=long):
                yield dumps(did) + '\n'
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except KeyNotFound, error:
            raise generate_http_error(404, 'KeyNotFound', error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)


class BulkDIDS(RucioController):

    def POST(self):
        try:
            json_data = loads(data())
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_dids(json_data, issuer=ctx.env.get('issuer'))
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except DuplicateContent, error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0][0])
        except DataIdentifierAlreadyExists, error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0][0])
        except AccessDenied, error:
            raise generate_http_error(401, 'AccessDenied', error.args[0][0])
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except DatabaseException, error:
            raise generate_http_error(500, 'DatabaseException', error.args)
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            print format_exc()
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
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except DuplicateContent, error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0][0])
        except DataIdentifierAlreadyExists, error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0][0])
        except AccessDenied, error:
            raise generate_http_error(401, 'AccessDenied', error.args[0][0])
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)

        raise Created()


class DIDs(RucioController):

    def GET(self, scope, name):
        """
        Retrieve a single data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
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
        except ScopeNotFound, error:
            raise generate_http_error(404, 'ScopeNotFound', error.args[0][0])
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
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
        except KeyError, error:
            raise generate_http_error(400, 'ValueError', str(error))

        try:
            add_did(scope=scope, name=name, type=type, statuses=statuses, meta=meta, rules=rules, lifetime=lifetime, dids=dids, rse=rse, issuer=ctx.env.get('issuer'))
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except DuplicateContent, error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0][0])
        except DataIdentifierAlreadyExists, error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0][0])
        except AccessDenied, error:
            raise generate_http_error(401, 'AccessDenied', error.args[0][0])
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except DatabaseException, error:
            raise generate_http_error(500, 'DatabaseException', error.args)
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
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
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except UnsupportedStatus, error:
            raise generate_http_error(409, 'UnsupportedStatus', error.args[0][0])
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except AccessDenied, error:
            raise generate_http_error(401, 'AccessDenied', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)

        raise OK()


class Attachment(RucioController):

    def GET(self, scope, name):
        """
        Returns the contents of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.

        :returns: A list with the contents.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for did in list_content(scope=scope, name=name):
                yield render_json(**did) + '\n'
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
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
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except DuplicateContent, error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0][0])
        except AccessDenied, error:
            raise generate_http_error(401, 'AccessDenied', error.args[0][0])
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except RSENotFound, error:
            raise generate_http_error(404, 'RSENotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            print format_exc()
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
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except AccessDenied, error:
            raise generate_http_error(401, 'AccessDenied', error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)

        raise OK()


class AttachmentHistory(RucioController):

    def GET(self, scope, name):
        """
        Returns the contents history of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param scope: The scope of the data identifier.
        :param name: The name of the data identifier.

        :returns: A list with the contents.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for did in list_content_history(scope=scope, name=name):
                yield render_json(**did) + '\n'
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)


class Replicas(RucioController):

    def GET(self, scope, name):
        raise DeprecationWarning('Use endpoint /replicas instead')


class Files(RucioController):

    def GET(self, scope, name):
        """ List all replicas of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
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
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)


class Parents(RucioController):

    def GET(self, scope, name):
        """ List all parents of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A list of dictionary containing all dataset information.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for dataset in list_parent_dids(scope=scope, name=name):
                yield render_json(**dataset) + "\n"
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)


class Meta(RucioController):

    def GET(self, scope, name):
        """
        List all meta of a data identifier.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 DataIdentifierNotFound
            500 InternalError

        :param scope: The scope name.
        :param name: The data identifier name.

        :returns: A dictionary containing all meta.
        """
        header('Content-Type', 'application/json')
        try:
            meta = get_metadata(scope=scope, name=name)
            return render_json(**meta)
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)

    def POST(self, scope, name, key):
        """
        Add metadata to a data identifier.

        HTTP Success:
            201 Created

        HTTP Error:
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
        except Duplicate, error:
            raise generate_http_error(409, 'Duplicate', error[0][0])
        except KeyNotFound, error:
            raise generate_http_error(400, 'KeyNotFound', error[0][0])
        except InvalidMetadata, error:
            raise generate_http_error(400, 'InvalidMetadata', error[0][0])
        except InvalidValueForKey, error:
            raise generate_http_error(400, 'InvalidValueForKey', error[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0][0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)

        raise Created()


class Rules(RucioController):

    def GET(self, scope, name):
        """
        Return all rules of a given DID.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for rule in list_replication_rules({'scope': scope, 'name': name}):
                yield dumps(rule, cls=APIEncoder) + '\n'
        except RuleNotFound, error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            raise InternalError(error)


class AssociatedRules(RucioController):

    def GET(self, scope, name):
        """
        Return all associated rules of a file.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for rule in list_associated_replication_rules_for_file(scope=scope, name=name):
                yield dumps(rule, cls=APIEncoder) + '\n'
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            raise InternalError(error)


class GUIDLookup(RucioController):

    def GET(self, guid):
        """
        Return the file associated to a GUID.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for dataset in get_dataset_by_guid(guid):
                yield dumps(dataset, cls=APIEncoder) + '\n'
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
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
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except DuplicateContent, error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0][0])
        except DataIdentifierAlreadyExists, error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0][0])
        except AccessDenied, error:
            raise generate_http_error(401, 'AccessDenied', error.args[0][0])
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except DatabaseException, error:
            raise generate_http_error(500, 'DatabaseException', error.args)
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)
        raise Created()


class NewDIDs(RucioController):
    def GET(self):
        """
        Returns list of recent identifiers.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

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
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
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
        except DataIdentifierNotFound, error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0][0])
        except DuplicateContent, error:
            raise generate_http_error(409, 'DuplicateContent', error.args[0][0])
        except DataIdentifierAlreadyExists, error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0][0])
        except AccessDenied, error:
            raise generate_http_error(401, 'AccessDenied', error.args[0][0])
        except UnsupportedOperation, error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0][0])
        except DatabaseException, error:
            raise generate_http_error(500, 'DatabaseException', error.args)
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            print format_exc()
            raise InternalError(error)
        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
