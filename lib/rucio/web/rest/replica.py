#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

from json import dumps, loads
from traceback import format_exc
from urllib import unquote
from urlparse import parse_qs
from web import application, ctx, Created, data, header, InternalError, loadhook, OK

from rucio.api.replica import add_replicas, list_replicas, delete_replicas, get_did_from_pfns, update_replicas_states
from rucio.common.exception import AccessDenied, DataIdentifierNotFound, Duplicate, RessourceTemporaryUnavailable, RucioException, RSENotFound, UnsupportedOperation
from rucio.common.replicas_selector import random_order, geoIP_order


from rucio.common.utils import generate_http_error, parse_response
from rucio.web.rest.common import authenticate, RucioController

urls = ('/list/?$', 'ListReplicas',
        '/?$', 'Replicas',
        '/(.*)/(.*)/?$', 'Replicas',
        '/getdidsfromreplicas/?$', 'ReplicasDIDs')


class Replicas(RucioController):

    def GET(self, scope, name):
        """
        List all replicas for data identifiers.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionary containing all replicas information.
        :returns: A metalink description of replicas if metalink(4)+xml is specified in Accept:
        """

        metalink = None
        if ctx.env.get('HTTP_ACCEPT') is not None:
            tmp = ctx.env.get('HTTP_ACCEPT').split(',')
            # first check if client accepts metalink
            if 'application/metalink+xml' in tmp:
                metalink = 3
            # but prefer metalink4 if the client has support for it
            # (clients can put both in their ACCEPT header!)
            if 'application/metalink4+xml' in tmp:
                metalink = 4

        dids, schemes, select = [{'scope': scope, 'name': name}], None, None
        if ctx.query:
            try:
                params = loads(unquote(ctx.query[1:]))
                if 'schemes' in params:
                    schemes = params['schemes']
            except ValueError:
                params = parse_qs(ctx.query[1:])
                if 'select' in params:
                    select = params['select'][0]
        try:
            # first, set the appropriate content type, and stream the header
            if metalink is None:
                header('Content-Type', 'application/x-json-stream')
            elif metalink == 3:
                header('Content-Type', 'application/metalink+xml')
                schemes = ['http', 'https']
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink version="3.0" xmlns="http://www.metalinker.org/">\n<files>\n'
            elif metalink == 4:
                header('Content-Type', 'application/metalink4+xml')
                schemes = ['http', 'https']
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n<files>\n'

            # then, stream the replica information
            for rfile in list_replicas(dids=dids, schemes=schemes):
                client_ip = ctx.get('ip')
                replicas = []
                dictreplica = {}
                for rse in rfile['rses']:
                    for replica in rfile['rses'][rse]:
                        replicas.append(replica)
                        dictreplica[replica] = rse
                if select == 'geoip':
                    replicas = geoIP_order(dictreplica, client_ip)
                else:
                    replicas = random_order(dictreplica, client_ip)
                if metalink is None:
                    yield dumps(rfile) + '\n'
                elif metalink == 3:
                    idx = 0
                    yield ' <file name="' + rfile['name'] + '">\n  <resources>\n'
                    for replica in replicas:
                        yield '   <url type="http" preference="' + str(idx) + '">' + replica + '</url>\n'
                        idx += 1
                    yield '  </resources>\n </file>\n'
                elif metalink == 4:
                    yield ' <file name="' + rfile['name'] + '">\n'
                    yield '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'
                    if rfile['adler32'] is not None:
                        yield '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                    if rfile['md5'] is not None:
                        yield '  <hash type="md5">' + rfile['md5'] + '</hash>\n'
                    yield '  <size>' + str(rfile['bytes']) + '</size>\n'
                    idx = 0
                    for replica in replicas:
                        yield '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx) + '">' + replica + '</url>\n'
                        idx += 1
                    yield ' </file>\n'

            # don't forget to send the metalink footer
            if metalink is not None:
                yield '</files>\n</metalink>\n'

        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

    def POST(self):
        """
        Create file replicas at a given RSE.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error
        """
        json_data = data()
        try:
            parameters = parse_response(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_replicas(rse=parameters['rse'], files=parameters['files'], issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RessourceTemporaryUnavailable, e:
            raise generate_http_error(503, 'RessourceTemporaryUnavailable', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)
        raise Created()

    def PUT(self):
        """
        Update a file replicas state at a given RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 Internal Error
        """
        json_data = data()
        try:
            parameters = parse_response(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            update_replicas_states(rse=parameters['rse'], files=parameters['files'], issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except UnsupportedOperation, e:
            raise generate_http_error(500, 'UnsupportedOperation', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)
        raise OK()

    def DELETE(self):
        """
        Delete file replicas at a given RSE.

        HTTP Success:
            200 Ok

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error
        """
        json_data = data()
        try:
            parameters = parse_response(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            delete_replicas(rse=parameters['rse'], files=parameters['files'], issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except RessourceTemporaryUnavailable, e:
            raise generate_http_error(503, 'RessourceTemporaryUnavailable', e[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)
        raise OK()


class ListReplicas(RucioController):

    def POST(self):
        """
        List all replicas for data identifiers.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionary containing all replicas information.
        :returns: A metalink description of replicas if metalink(4)+xml is specified in Accept:
        """

        metalink = None
        if ctx.env.get('HTTP_ACCEPT') is not None:
            tmp = ctx.env.get('HTTP_ACCEPT').split(',')
            # first check if client accepts metalink
            if 'application/metalink+xml' in tmp:
                metalink = 3
            # but prefer metalink4 if the client has support for it
            # (clients can put both in their ACCEPT header!)
            if 'application/metalink4+xml' in tmp:
                metalink = 4

        dids, schemes, select, unavailable = [], None, None, False
        json_data = data()
        try:
            params = parse_response(json_data)
            if 'dids' in params:
                dids = params['dids']
            if 'schemes' in params:
                schemes = params['schemes']
            if 'unavailable' in params:
                unavailable = params['unavailable']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'select' in params:
                select = params['select'][0]

        try:
            # first, set the appropriate content type, and stream the header
            if metalink is None:
                header('Content-Type', 'application/x-json-stream')
            elif metalink == 3:
                header('Content-Type', 'application/metalink+xml')
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink version="3.0" xmlns="http://www.metalinker.org/">\n<files>\n'
            elif metalink == 4:
                header('Content-Type', 'application/metalink4+xml')
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n<files>\n'

            # then, stream the replica information
            for rfile in list_replicas(dids=dids, schemes=schemes, unavailable=unavailable):
                client_ip = ctx.get('ip')
                replicas = []
                dictreplica = {}
                for rse in rfile['rses']:
                    for replica in rfile['rses'][rse]:
                        replicas.append(replica)
                        dictreplica[replica] = rse
                if select == 'geoip':
                    replicas = geoIP_order(dictreplica, client_ip)
                else:
                    replicas = random_order(dictreplica, client_ip)
                if metalink is None:
                    yield dumps(rfile) + '\n'
                elif metalink == 3:
                    idx = 0
                    yield ' <file name="' + rfile['name'] + '">\n  <resources>\n'
                    for replica in replicas:
                        yield '   <url type="http" preference="' + str(idx) + '">' + replica + '</url>\n'
                        idx += 1
                    yield '  </resources>\n </file>\n'
                elif metalink == 4:
                    yield ' <file name="' + rfile['name'] + '">\n'
                    yield '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'
                    if rfile['adler32'] is not None:
                        yield '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                    if rfile['md5'] is not None:
                        yield '  <hash type="md5">' + rfile['md5'] + '</hash>\n'
                    yield '  <size>' + str(rfile['bytes']) + '</size>\n'
                    idx = 0
                    for replica in replicas:
                        yield '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx) + '">' + replica + '</url>\n'
                        idx += 1
                    yield ' </file>\n'

            # don't forget to send the metalink footer
            if metalink is not None:
                yield '</files>\n</metalink>\n'

        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)


class ReplicasDIDs(RucioController):

    def POST(self):
        """
        List the DIDs associated to a list of replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A list of dictionaries containing the mapping PFNs to DIDs.
        """
        json_data = data()
        rse, pfns = None, []
        header('Content-Type', 'application/x-json-stream')
        try:
            params = parse_response(json_data)
            if 'pfns' in params:
                pfns = params['pfns']
            if 'rse' in params:
                rse = params['rse']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            for pfn in get_did_from_pfns(pfns, rse):
                yield dumps(pfn) + '\n'
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(authenticate))
application = app.wsgifunc()
