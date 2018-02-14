#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

from datetime import datetime
from json import dumps
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView
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
from rucio.common.replica_sorter import sort_random, sort_geoip, sort_closeness, sort_dynamic, sort_ranking
from rucio.common.utils import generate_http_error_flask, parse_response, APIEncoder
from rucio.web.rest.flaskapi.v1.common import before_request, after_request


class Replicas(MethodView):

    def get(self, scope, name):
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

        metalink = False
        if request.environ.get('HTTP_ACCEPT') is not None:
            tmp = request.environ.get('HTTP_ACCEPT').split(',')
            if 'application/metalink4+xml' in tmp:
                metalink = True

        dids, schemes, select, limit = [{'scope': scope, 'name': name}], None, None, None

        schemes = request.args.get('schemes', None)
        select = request.args.get('select', None)
        limit = request.args.get('limit', None)
        if limit:
            limit = int(limit)

        data = ""
        content_type = 'application/x-json-stream'
        try:
            # first, set the appropriate content type, and stream the header
            if metalink:
                content_type = 'application/metalink4+xml'
                data += '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'

            # then, stream the replica information
            for rfile in list_replicas(dids=dids, schemes=schemes):
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR')
                if client_ip is None:
                    client_ip = request.remote_addr

                replicas = []
                dictreplica = {}
                for rse in rfile['rses']:
                    for replica in rfile['rses'][rse]:
                        replicas.append(replica)
                        dictreplica[replica] = rse
                if select == 'geoip':
                    try:
                        replicas = sort_geoip(dictreplica, client_ip)
                    except AddressNotFoundError:
                        pass
                else:
                    replicas = sort_random(dictreplica)
                if not metalink:
                    data += dumps(rfile) + '\n'
                else:
                    data += ' <file name="' + rfile['name'] + '">\n'
                    data += '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'

                    if rfile['adler32'] is not None:
                        data += '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                    if rfile['md5'] is not None:
                        data += '  <hash type="md5">' + rfile['md5'] + '</hash>\n'

                    data += '  <size>' + str(rfile['bytes']) + '</size>\n'

                    data += '  <glfn name="/atlas/rucio/%s:%s">' % (rfile['scope'], rfile['name'])
                    data += '</glfn>\n'

                    idx = 0
                    for replica in replicas:
                        data += '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx + 1) + '">' + replica + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    data += ' </file>\n'

            # don't forget to send the metalink footer
            if metalink:
                data += '</metalink>\n'

            return Response(data, content_type=content_type)
        except DataIdentifierNotFound, e:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500

    def post(self):
        """
        Create file replicas at a given RSE.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_replicas(rse=parameters['rse'], files=parameters['files'], issuer=request.environ.get('issuer'), ignore_availability=parameters.get('ignore_availability', False))
        except InvalidPath, e:
            return generate_http_error_flask(400, 'InvalidPath', e.args[0][0])
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            return generate_http_error_flask(409, 'Duplicate', e[0][0])
        except DataIdentifierAlreadyExists, e:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', e[0][0])
        except RSENotFound, e:
            return generate_http_error_flask(404, 'RSENotFound', e[0][0])
        except ResourceTemporaryUnavailable, e:
            return generate_http_error_flask(503, 'ResourceTemporaryUnavailable', e[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        return 'Created', 201

    def put(self):
        """
        Update a file replicas state at a given RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 Internal Error
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            update_replicas_states(rse=parameters['rse'], files=parameters['files'], issuer=request.environ.get('issuer'))
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except UnsupportedOperation, e:
            return generate_http_error_flask(500, 'UnsupportedOperation', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        return 'OK', 200

    def delete(self):
        """
        Delete file replicas at a given RSE.

        HTTP Success:
            200 Ok

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            delete_replicas(rse=parameters['rse'], files=parameters['files'], issuer=request.environ.get('issuer'), ignore_availability=parameters.get('ignore_availability', False))
        except AccessDenied, e:
            return generate_http_error_flask(401, 'AccessDenied', e.args[0][0])
        except RSENotFound, e:
            return generate_http_error_flask(404, 'RSENotFound', e[0][0])
        except ResourceTemporaryUnavailable, e:
            return generate_http_error_flask(503, 'ResourceTemporaryUnavailable', e[0][0])
        except ReplicaNotFound, e:
            return generate_http_error_flask(404, 'ReplicaNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        return 'OK', 200


class ListReplicas(MethodView):

    def post(self):
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

        metalink = False
        if request.environ.get('HTTP_ACCEPT') is not None:
            tmp = request.environ.get('HTTP_ACCEPT').split(',')
            if 'application/metalink4+xml' in tmp:
                metalink = True

        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if client_ip is None:
            client_ip = request.remote_addr

        dids, schemes, select, unavailable, limit = [], None, None, False, None
        ignore_availability, rse_expression, all_states = False, None, False
        client_location = {}

        json_data = request.data
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
            if 'client_location' in params:
                client_location = params['client_location']
                client_location['ip'] = params['client_location'].get('ip', client_ip)
            if 'sort' in params:
                select = params['sort']
            if 'domain' in params:
                domain = params['domain']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        schemes = request.args.get('schemes', None)
        select = request.args.get('select', None)
        select = request.args.get('sort', None)

        data = ""
        content_type = 'application/x-json-stream'
        try:
            # first, set the appropriate content type, and stream the header
            if metalink:
                content_type = 'application/metalink4+xml'
                data += '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'

            # then, stream the replica information
            for rfile in list_replicas(dids=dids, schemes=schemes,
                                       unavailable=unavailable,
                                       request_id=request.environ.get('request_id'),
                                       ignore_availability=ignore_availability,
                                       all_states=all_states,
                                       rse_expression=rse_expression,
                                       client_location=client_location,
                                       domain=domain):
                replicas = []
                dictreplica = {}
                for rse in rfile['rses']:
                    for replica in rfile['rses'][rse]:
                        replicas.append(replica)
                        dictreplica[replica] = rse

                if not metalink:
                    data += dumps(rfile, cls=APIEncoder) + '\n'
                else:
                    data += ' <file name="' + rfile['name'] + '">\n'
                    data += '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'
                    if rfile['adler32'] is not None:
                        data += '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                    if rfile['md5'] is not None:
                        data += '  <hash type="md5">' + rfile['md5'] + '</hash>\n'
                    data += '  <size>' + str(rfile['bytes']) + '</size>\n'

                    data += '  <glfn name="/atlas/rucio/%s:%s">' % (rfile['scope'], rfile['name'])
                    data += '</glfn>\n'

                    if select == 'geoip':
                        replicas = sort_geoip(dictreplica, client_location['ip'])
                    elif select == 'closeness':
                        replicas = sort_closeness(dictreplica, client_location)
                    elif select == 'dynamic':
                        replicas = sort_dynamic(dictreplica, client_location)
                    elif select == 'ranking':
                        replicas = sort_ranking(dictreplica, client_location)
                    else:
                        replicas = sort_random(dictreplica)

                    idx = 0
                    for replica in replicas:
                        data += '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx + 1) + '">' + replica + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    data += ' </file>\n'

            # don't forget to send the metalink footer
            if metalink:
                data += '</metalink>\n'

            return Response(data, content_type=content_type)
        except DataIdentifierNotFound, e:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


class ReplicasDIDs(MethodView):

    def post(self):
        """
        List the DIDs associated to a list of replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A list of dictionaries containing the mAPPing PFNs to DIDs.
        """
        json_data = request.data
        rse, pfns = None, []
        rse = None
        try:
            params = parse_response(json_data)
            if 'pfns' in params:
                pfns = params['pfns']
            if 'rse' in params:
                rse = params['rse']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            data = ""
            for pfn in get_did_from_pfns(pfns, rse):
                data += dumps(pfn) + '\n'
            return Response(data, content_type='application/x-json-string')
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


class BadReplicas(MethodView):

    def post(self):
        """
        Declare a list of bad replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        """
        json_data = request.data
        pfns = []

        try:
            params = parse_response(json_data)
            if 'pfns' in params:
                pfns = params['pfns']
            if 'reason' in params:
                reason = params['reason']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        not_declared_files = {}
        try:
            not_declared_files = declare_bad_file_replicas(pfns=pfns, reason=reason, issuer=request.environ.get('issuer'))
        except ReplicaNotFound, e:
            return generate_http_error_flask(404, 'ReplicaNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        return Response(dumps(not_declared_files), status=201, content_type='application/x-json-stream')


class SuspiciousReplicas(MethodView):

    def post(self):
        """
        Declare a list of suspicious replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        """
        json_data = request.data
        pfns = []
        try:
            params = parse_response(json_data)
            if 'pfns' in params:
                pfns = params['pfns']
            if 'reason' in params:
                reason = params['reason']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        not_declared_files = {}
        try:
            not_declared_files = declare_suspicious_file_replicas(pfns=pfns, reason=reason, issuer=request.environ.get('issuer'))
        except ReplicaNotFound, e:
            return generate_http_error_flask(404, 'ReplicaNotFound', e.args[0][0])
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        return Response(dumps(not_declared_files), status=201, content_type='application/x-json-stream')


class BadReplicasStates(MethodView):

    def get(self):
        """
        List the bad or suspicious replicas by states.

        HTTP Success:
            200 OK

        HTTP Error:
            500 InternalError

        """
        result = []
        state = request.args.get('state', None)
        rse = request.args.get('rse', None)
        younger_than = request.args.get('younger_than', None)
        older_than = request.args.get('older_than', None)
        limit = request.args.get('limit', None)
        list_pfns = request.args.get('list_pfns', None)

        if type(state) is str or type(state) is unicode:
            state = BadFilesStatus.from_string(state)
        if younger_than:
            younger_than = datetime.strptime(younger_than, "%Y-%m-%dT%H:%M:%S.%f")
        if older_than:
            older_than = datetime.strptime(older_than, "%Y-%m-%dT%H:%M:%S.%f")
        if 'limit':
            limit = int(limit)
        if 'list_pfns':
            list_pfns = bool(list_pfns)

        try:
            result = list_bad_replicas_status(state=state, rse=rse, younger_than=younger_than, older_than=older_than, limit=limit, list_pfns=list_pfns)
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        data = ""
        for row in result:
            data += dumps(row, cls=APIEncoder) + '\n'

        return Response(data, content_type='application/x-json-stream')


class BadReplicasSummary(MethodView):

    def get(self):
        """
        Return a summary of the bad replicas by incident.

        HTTP Success:
            200 OK

        HTTP Error:
            500 InternalError

        """
        result = []
        rse_expression = request.args.get('rse_expression', None)
        from_date = request.args.get('from_date', None)
        to_date = request.args.get('to_date', None)

        if from_date:
            from_date = datetime.strptime(from_date, "%Y-%m-%d")
        if to_date:
            to_date = datetime.strptime(to_date, "%Y-%m-%d")

        try:
            result = get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date, to_date=to_date)
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        data = ""
        for row in result:
            data += dumps(row, cls=APIEncoder) + '\n'

        return Response(data, content_type='application/x-json-stream')


class DatasetReplicas(MethodView):

    def get(self, scope, name):
        """
        List dataset replicas replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionary containing all replicas information.
        """
        deep = request.args.get('deep', False)
        try:
            data = ""
            for row in list_dataset_replicas(scope=scope, name=name, deep=deep):
                data += dumps(row, cls=APIEncoder) + '\n'
            return Response(data, content_type='application/x-json-stream')
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


class ReplicasRSE(MethodView):

    def get(self, rse):
        """
        List dataset replicas replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A dictionary containing all replicas on the RSE.
        """
        print rse
        try:
            data = ""
            for row in list_datasets_per_rse(rse=rse):
                data += dumps(row, cls=APIEncoder) + '\n'
            return Response(data, content_type='application/x-json-stream')
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500


bp = Blueprint('did', __name__)

list_replicas_view = ListReplicas.as_view('list_replicas')
bp.add_url_rule('/list', view_func=list_replicas_view, methods=['post', ])
replicas_view = Replicas.as_view('replicas')
bp.add_url_rule('/', view_func=list_replicas_view, methods=['post', 'put', 'delete'])
bp.add_url_rule('/<scope>/<name>', view_func=list_replicas_view, methods=['get', ])
bad_replicas_view = BadReplicas.as_view('bad_replicas')
bp.add_url_rule('/bad', view_func=bad_replicas_view, methods=['post', ])
bad_replicas_states_view = BadReplicasStates.as_view('bad_replicas_states')
bp.add_url_rule('/bad/states', view_func=bad_replicas_states_view, methods=['get', ])
bad_replicas_summary_view = BadReplicasSummary.as_view('bad_replicas_summary')
bp.add_url_rule('/bad/summary', view_func=bad_replicas_summary_view, methods=['get', ])
replicas_rse_view = ReplicasRSE.as_view('replicas_rse')
bp.add_url_rule('/rse/<rse>', view_func=replicas_rse_view, methods=['get', ])
dataset_replicas_view = DatasetReplicas.as_view('dataset_replicas')
bp.add_url_rule('/<scope>/<name>/datasets', view_func=dataset_replicas_view, methods=['get', ])
replicas_dids_view = ReplicasDIDs.as_view('replicas_dids')
bp.add_url_rule('/dids', view_func=replicas_dids_view, methods=['post', ])
suspicious_replicas_view = SuspiciousReplicas.as_view('suspicious_replicas')
bp.add_url_rule('/suspicious', view_func=suspicious_replicas_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/replicas')
    return doc_app


if __name__ == "__main__":
    application.run()
