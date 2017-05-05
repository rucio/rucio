#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013 - 2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013, 2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2015
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

from datetime import datetime
from json import dumps, loads
from traceback import format_exc
from urllib import unquote
from urlparse import parse_qs
from web import application, ctx, Created, data, header, InternalError, loadhook, OK, unloadhook

from geoip2.errors import AddressNotFoundError

from rucio.api.replica import (add_replicas, list_replicas, list_dataset_replicas,
                               delete_replicas,
                               get_did_from_pfns, update_replicas_states,
                               declare_bad_file_replicas,
                               declare_suspicious_file_replicas, list_bad_replicas_status,
                               get_bad_replicas_summary, list_datasets_per_rse)
from rucio.db.sqla.constants import BadFilesStatus
from rucio.common.exception import (AccessDenied, DataIdentifierAlreadyExists,
                                    DataIdentifierNotFound, Duplicate, InvalidPath,
                                    ResourceTemporaryUnavailable, RucioException,
                                    RSENotFound, UnsupportedOperation, ReplicaNotFound)
from rucio.common.replicas_selector import random_order, geoIP_order

from rucio.common.utils import generate_http_error, parse_response, APIEncoder
from rucio.web.rest.common import rucio_loadhook, rucio_unloadhook, RucioController

URLS = ('/list/?$', 'ListReplicas',
        '/?$', 'Replicas',
        '/bad/states/?$', 'BadReplicasStates',
        '/bad/summary/?$', 'BadReplicasSummary',
        '/rse/(.*)/?$', 'ReplicasRSE',
        '/(.*)/(.*)/datasets$', 'DatasetReplicas',
        '/(.*)/(.*)/?$', 'Replicas',
        '/bad/?$', 'BadReplicas',
        '/suspicious/?$', 'SuspiciousReplicas',
        '/dids/?$', 'ReplicasDIDs')


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

        dids, schemes, select, limit = [{'scope': scope, 'name': name}], None, None, None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'schemes' in params:
                schemes = params['schemes']
            if 'select' in params:
                select = params['select'][0]
            if 'limit' in params:
                limit = int(params['limit'][0])

        try:
            # first, set the APPropriate content type, and stream the header
            if metalink is None:
                header('Content-Type', 'application/x-json-stream')
            elif metalink == 3:
                header('Content-Type', 'application/metalink+xml')
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink version="3.0" xmlns="http://www.metalinker.org/">\n<files>\n'
            elif metalink == 4:
                header('Content-Type', 'application/metalink4+xml')
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'

            # then, stream the replica information
            for rfile in list_replicas(dids=dids, schemes=schemes):
                client_ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
                if client_ip is None:
                    client_ip = ctx.ip

                replicas = []
                dictreplica = {}
                for rse in rfile['rses']:
                    for replica in rfile['rses'][rse]:
                        replicas.append(replica)
                        dictreplica[replica] = rse
                if select == 'geoip':
                    try:
                        replicas = geoIP_order(dictreplica, client_ip)
                    except AddressNotFoundError:
                        pass
                else:
                    replicas = random_order(dictreplica, client_ip)
                if metalink is None:
                    yield dumps(rfile) + '\n'

                elif metalink == 3:
                    idx = 0
                    yield ' <file name="' + rfile['name'] + '">\n'

                    # To help support the FAX transition period, add the glfn to the metalink:
                    # AGIS does not expose specific FAX redirectors per DDM Endpoint, so go through top-level redirector
                    yield '  <glfn name="%s%s">' % ('root://atlas-xrd-eu.cern.ch:1094//atlas/rucio/',
                                                    '%s:%s' % (rfile['scope'], rfile['name']))
                    yield '</glfn>\n'

                    yield '  <resources>\n'
                    for replica in replicas:
                        yield '   <url type="http" preference="' + str(idx) + '">' + replica + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    yield '  </resources>\n </file>\n'

                elif metalink == 4:
                    yield ' <file name="' + rfile['name'] + '">\n'
                    yield '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'

                    if rfile['adler32'] is not None:
                        yield '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                    if rfile['md5'] is not None:
                        yield '  <hash type="md5">' + rfile['md5'] + '</hash>\n'

                    yield '  <size>' + str(rfile['bytes']) + '</size>\n'

                    # To help support the FAX transition period, add the glfn to the metalink:
                    # AGIS does not expose specific FAX redirectors per DDM Endpoint, so go through top-level redirector
                    yield '  <glfn name="%s%s">' % ('root://atlas-xrd-eu.cern.ch:1094//atlas/rucio/',
                                                    '%s:%s' % (rfile['scope'], rfile['name']))
                    yield '</glfn>\n'

                    idx = 0
                    for replica in replicas:
                        yield '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx + 1) + '">' + replica + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    yield ' </file>\n'

            # don't forget to send the metalink footer
            if metalink:
                if metalink == 3:
                    yield '</files>\n</metalink>\n'
                elif metalink == 4:
                    yield '</metalink>\n'

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
            add_replicas(rse=parameters['rse'], files=parameters['files'], issuer=ctx.env.get('issuer'), ignore_availability=parameters.get('ignore_availability', False))
        except InvalidPath, e:
            raise generate_http_error(400, 'InvalidPath', e.args[0][0])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e[0][0])
        except DataIdentifierAlreadyExists, e:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', e[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except ResourceTemporaryUnavailable, e:
            raise generate_http_error(503, 'ResourceTemporaryUnavailable', e[0][0])
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
            delete_replicas(rse=parameters['rse'], files=parameters['files'], issuer=ctx.env.get('issuer'), ignore_availability=parameters.get('ignore_availability', False))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e[0][0])
        except ResourceTemporaryUnavailable, e:
            raise generate_http_error(503, 'ResourceTemporaryUnavailable', e[0][0])
        except ReplicaNotFound, e:
            raise generate_http_error(404, 'ReplicaNotFound', e.args[0][0])
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

        dids, schemes, select, unavailable, limit = [], None, None, False, None
        ignore_availability, rse_expression, all_states = False, None, False
        json_data = data()
        try:
            params = parse_response(json_data)
            if 'dids' in params:
                dids = params['dids']
            if 'schemes' in params:
                schemes = params['schemes']
            if 'unavailable' in params:
                unavailable = params['unavailable']
                ignore_availability = True
            if 'all_states' in params:
                all_states = params['all_states']
            if 'rse_expression' in params:
                rse_expression = params['rse_expression']

        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'select' in params:
                select = params['select'][0]
            if 'limit' in params:
                limit = params['limit'][0]

        try:
            # first, set the APPropriate content type, and stream the header
            if metalink is None:
                header('Content-Type', 'application/x-json-stream')
            elif metalink == 3:
                header('Content-Type', 'application/metalink+xml')
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink version="3.0" xmlns="http://www.metalinker.org/">\n<files>\n'
            elif metalink == 4:
                header('Content-Type', 'application/metalink4+xml')
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'

            # then, stream the replica information
            for rfile in list_replicas(dids=dids, schemes=schemes,
                                       unavailable=unavailable,
                                       request_id=ctx.env.get('request_id'),
                                       ignore_availability=ignore_availability,
                                       all_states=all_states,
                                       rse_expression=rse_expression):
                client_ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
                if client_ip is None:
                    client_ip = ctx.ip
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
                    yield dumps(rfile, cls=APIEncoder) + '\n'
                elif metalink == 3:
                    idx = 0
                    yield ' <file name="' + rfile['name'] + '">\n  <resources>\n'
                    for replica in replicas:
                        yield '   <url type="http" preference="' + str(idx) + '">' + replica + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
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
                        yield '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx + 1) + '">' + replica + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    yield ' </file>\n'

            # don't forget to send the metalink footer
            if metalink:
                if metalink == 3:
                    yield '</files>\n</metalink>\n'
                elif metalink == 4:
                    yield '</metalink>\n'

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

        :returns: A list of dictionaries containing the mAPPing PFNs to DIDs.
        """
        json_data = data()
        rse, pfns = None, []
        header('Content-Type', 'application/x-json-stream')
        rse = None
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


class BadReplicas(RucioController):

    def POST(self):
        """
        Declare a list of bad replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        """
        json_data = data()
        pfns = []
        header('Content-Type', 'application/x-json-stream')
        try:
            params = parse_response(json_data)
            if 'pfns' in params:
                pfns = params['pfns']
            if 'reason' in params:
                reason = params['reason']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        not_declared_files = {}
        try:
            not_declared_files = declare_bad_file_replicas(pfns=pfns, reason=reason, issuer=ctx.env.get('issuer'))
        except ReplicaNotFound, e:
            raise generate_http_error(404, 'ReplicaNotFound', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)
        raise Created(dumps(not_declared_files))


class SuspiciousReplicas(RucioController):

    def POST(self):
        """
        Declare a list of suspicious replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        """
        json_data = data()
        pfns = []
        header('Content-Type', 'application/x-json-stream')
        try:
            params = parse_response(json_data)
            if 'pfns' in params:
                pfns = params['pfns']
            if 'reason' in params:
                reason = params['reason']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        not_declared_files = {}
        try:
            not_declared_files = declare_suspicious_file_replicas(pfns=pfns, reason=reason, issuer=ctx.env.get('issuer'))
        except ReplicaNotFound, e:
            raise generate_http_error(404, 'ReplicaNotFound', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)
        raise Created(dumps(not_declared_files))


class BadReplicasStates(RucioController):

    def GET(self):
        """
        List the bad or suspicious replicas by states.

        HTTP Success:
            200 OK

        HTTP Error:
            500 InternalError

        """
        header('Content-Type', 'application/x-json-stream')
        result = []
        state, rse, younger_than, older_than, limit, list_pfns = None, None, None, None, None, None
        if ctx.query:
            try:
                params = loads(unquote(ctx.query[1:]))
            except ValueError:
                params = parse_qs(ctx.query[1:])
            if 'state' in params:
                state = params['state'][0]
            if type(state) is str or type(state) is unicode:
                state = BadFilesStatus.from_string(state)
            if 'rse' in params:
                rse = params['rse'][0]
            if 'younger_than' in params:
                younger_than = datetime.strptime(params['younger_than'], "%Y-%m-%dT%H:%M:%S.%f")
            if 'older_than' in params:
                older_than = datetime.strptime(params['older_than'], "%Y-%m-%dT%H:%M:%S.%f")
            if 'limit' in params:
                limit = int(params['limit'][0])
            if 'list_pfns' in params:
                list_pfns = bool(params['list_pfns'][0])

        try:
            result = list_bad_replicas_status(state=state, rse=rse, younger_than=younger_than, older_than=older_than, limit=limit, list_pfns=list_pfns)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)
        for row in result:
            yield dumps(row, cls=APIEncoder) + '\n'


class BadReplicasSummary(RucioController):

    def GET(self):
        """
        Return a summary of the bad replicas by incident.

        HTTP Success:
            200 OK

        HTTP Error:
            500 InternalError

        """
        header('Content-Type', 'application/x-json-stream')
        result = []
        rse_expression, from_date, to_date = None, None, None
        if ctx.query:
            try:
                params = loads(unquote(ctx.query[1:]))
            except ValueError:
                params = parse_qs(ctx.query[1:])
            if 'rse_expression' in params:
                rse_expression = params['rse_expression'][0]
            if 'from_date' in params:
                from_date = datetime.strptime(params['from_date'][0], "%Y-%m-%d")
            if 'to_date' in params:
                to_date = datetime.strptime(params['to_date'][0], "%Y-%m-%d")

        try:
            result = get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date, to_date=to_date)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)
        for row in result:
            yield dumps(row, cls=APIEncoder) + '\n'


class DatasetReplicas(RucioController):

    def GET(self, scope, name):
        """
        List dataset replicas replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionary containing all replicas information.
        :returns: A metalink description of replicas if metalink(4)+xml is specified in Accept:
        """
        header('Content-Type', 'application/x-json-stream')
        deep = False
        if ctx.query:
            try:
                params = loads(unquote(ctx.query[1:]))
            except ValueError:
                params = parse_qs(ctx.query[1:])
            if 'deep' in params:
                deep = params['deep'][0]
        try:
            for row in list_dataset_replicas(scope=scope, name=name, deep=deep):
                yield dumps(row, cls=APIEncoder) + '\n'
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)


class ReplicasRSE(RucioController):

    def GET(self, rse):
        """
        List dataset replicas replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionary containing all replicas on the RSE.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for row in list_datasets_per_rse(rse=rse):
                yield dumps(row, cls=APIEncoder) + '\n'
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
APP.add_processor(unloadhook(rucio_unloadhook))
application = APP.wsgifunc()
