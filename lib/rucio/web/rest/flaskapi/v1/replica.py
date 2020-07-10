#!/usr/bin/env python
# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function
from datetime import datetime
from json import dumps
from six import string_types
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView
from geoip2.errors import AddressNotFoundError
from xml.sax.saxutils import escape

from rucio.api.replica import (add_replicas, list_replicas, list_dataset_replicas, list_dataset_replicas_bulk,
                               delete_replicas,
                               get_did_from_pfns, update_replicas_states,
                               declare_bad_file_replicas, add_bad_pfns, get_suspicious_files,
                               declare_suspicious_file_replicas, list_bad_replicas_status,
                               get_bad_replicas_summary, list_datasets_per_rse,
                               set_tombstone)
from rucio.db.sqla.constants import BadFilesStatus
from rucio.common.exception import (AccessDenied, DataIdentifierAlreadyExists, InvalidType,
                                    DataIdentifierNotFound, Duplicate, InvalidPath,
                                    ResourceTemporaryUnavailable, RucioException,
                                    RSENotFound, UnsupportedOperation, ReplicaNotFound, InvalidObject)
from rucio.common.replica_sorter import sort_random, sort_geoip, sort_closeness, sort_dynamic, sort_ranking
from rucio.common.utils import generate_http_error_flask, parse_response, APIEncoder, render_json_list
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask


class Replicas(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream', 'application/metalink4+xml'])
    def get(self, scope, name):
        """
        List all replicas for data identifiers.

        .. :quickref: Replicas; List all replicas for did
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :reqheader HTTP_ACCEPT: application/metalink4+xml
        :param scope: data identifier scope.
        :param name: data identifier name.
        :resheader Content-Type: application/x-json-stream
        :resheader Content-Type: application/metalink4+xml
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 404: DID not found.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
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
            for rfile in list_replicas(dids=dids, schemes=schemes, vo=request.environ.get('vo')):
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
                        data += '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx + 1) + '">' + escape(replica) + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    data += ' </file>\n'

            # don't forget to send the metalink footer
            if metalink:
                data += '</metalink>\n'

            return Response(data, content_type=content_type)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

    def post(self):
        """
        Create file replicas at a given RSE.

        .. :quickref: Replicas; create replicas at RSE

        :<json string rse: The RSE name.
        :<json list files: list of dicts with 'scope', 'name', 'bytes', 'meta' and 'adler32'.
        :<json bool ignore_availability: Flag to ignore the RSE blacklisting.
        :status 201: Replica Successfully created.
        :status 400: Invalid Path.
        :status 401: Invalid auth token.
        :status 404: RSE not found.
        :status 409: Replica already exists.
        :status 409: DID already exists.
        :status 503: Resource Temporary Unavailable.
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_replicas(rse=parameters['rse'], files=parameters['files'],
                         issuer=request.environ.get('issuer'), vo=request.environ.get('vo'),
                         ignore_availability=parameters.get('ignore_availability', False))
        except InvalidPath as error:
            return generate_http_error_flask(400, 'InvalidPath', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except DataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except ResourceTemporaryUnavailable as error:
            return generate_http_error_flask(503, 'ResourceTemporaryUnavailable', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return 'Created', 201

    def put(self):
        """
        Update a file replicas state at a given RSE.

        .. :quickref: Replicas; update replicas state.

        :<json string rse: The RSE name.
        :<json list files: list of dicts with 'scope', 'name' and 'state'.
        :status 201: Replica successfully updated.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid auth token.
        :status 500: Internal Error.
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            update_replicas_states(rse=parameters['rse'], files=parameters['files'], issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(500, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return 'OK', 200

    def delete(self):
        """
        Delete file replicas at a given RSE.

        .. :quickref: Replicas; Delete replica at RSE.

        :<json string rse: The RSE name.
        :<json list files: list of dicts with 'scope', 'name'.
        :<json bool ignore_availability: Flag to ignore the RSE blacklisting.
        :status 200: Replica successfully deleted.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid auth token.
        :status 404: RSE not found.
        :status 404: Replica not found.
        :status 500: Internal Error.
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            delete_replicas(rse=parameters['rse'], files=parameters['files'],
                            issuer=request.environ.get('issuer'), vo=request.environ.get('vo'),
                            ignore_availability=parameters.get('ignore_availability', False))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except ResourceTemporaryUnavailable as error:
            return generate_http_error_flask(503, 'ResourceTemporaryUnavailable', error.args[0])
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return 'OK', 200


class ListReplicas(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream', 'application/metalink4+xml'])
    def post(self):
        """
        List all replicas for data identifiers.

        .. :quickref: ListReplicas; List all replicas for did.

        :reqheader HTTP_ACCEPT: application/metalink4+xml
        :query schemes: A list of schemes to filter the replicas.
        :query sort: Requested sorting of the result, e.g., 'geoip', 'closeness', 'dynamic', 'ranking'.
        :<json list dids: list of DIDs.
        :<json list schemes: A list of schemes to filter the replicas.
        :<json bool unavailable: Also include unavailable replicas.
        :<json bool all_states: Return all replicas whatever state they are in. Adds an extra 'states' entry in the result dictionary.
        :<json string rse_expression: The RSE expression to restrict on a list of RSEs.
        :<json dict client_location: Client location dictionary for PFN modification {'ip', 'fqdn', 'site'}.
        :<json bool sort: Requested sorting of the result, e.g., 'geoip', 'closeness', 'dynamic', 'ranking'.
        :<json string domain: The network domain for the call, either None, 'wan' or 'lan'. None is fallback to 'wan', 'all' is both ['lan','wan']
        :resheader Content-Type: application/x-json-stream
        :resheader Content-Type: application/metalink4+xml
        :status 200: OK.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid auth token.
        :status 404: DID not found.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
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
                                       domain=domain, vo=request.environ.get('vo')):
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
                        data += '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx + 1) + '">' + escape(replica) + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    data += ' </file>\n'

            # don't forget to send the metalink footer
            if metalink:
                data += '</metalink>\n'

            return Response(data, content_type=content_type)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class ReplicasDIDs(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """
        List the DIDs associated to a list of replicas.

        .. :quickref: ReplicasDIDs; List DIDs for replicas.

        :<json string pfns: The list of PFNs.
        :<json string rse: The RSE name.
        :resheader Content-Type: application/x-json-string
        :status 200: OK.
        :status 400: Cannot decode json parameter list.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: A list of dictionaries containing the mapping PFNs to DIDs.
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
            for pfn in get_did_from_pfns(pfns, rse, vo=request.environ.get('vo')):
                data += dumps(pfn) + '\n'
            return Response(data, content_type='application/x-json-string')
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class BadReplicas(MethodView):

    def post(self):
        """
        Declare a list of bad replicas.

        .. :quickref: BadReplicasStates; Declare bad replicas.

        :<json string pfns: The list of PFNs.
        :<json string reason: The reason of the loss.
        :resheader Content-Type: application/x-json-string
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid auth token.
        :status 404: Replica not found.
        :status 500: Internal Error.
        :returns: A list of not successfully declared files.
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
            not_declared_files = declare_bad_file_replicas(pfns=pfns, reason=reason, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return Response(dumps(not_declared_files), status=201, content_type='application/x-json-stream')


class SuspiciousReplicas(MethodView):

    def post(self):
        """
        Declare a list of suspicious replicas.

        .. :quickref: SuspiciousReplicas; Declare suspicious replicas.

        :<json string pfns: The list of PFNs.
        :<json string reason: The reason of the loss.
        :resheader Content-Type: application/x-json-string
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid auth token.
        :status 404: Replica not found.
        :status 500: Internal Error.
        :returns: A list of not successfully declared files.
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
            not_declared_files = declare_suspicious_file_replicas(pfns=pfns, reason=reason, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return Response(dumps(not_declared_files), status=201, content_type='application/x-json-stream')

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        List the suspicious replicas on a list of RSEs.

        .. :quickref: SuspiciousReplicas; Get suspicious replicas.

        :resheader Content-Type: application/json
        :status 200: OK.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: List of suspicious file replicas.
        """
        result = []
        rse_expression = request.args.get('rse_expression', None)
        younger_than = request.args.get('younger_than', None)
        nattempts = request.args.get('nattempts', None)
        if younger_than:
            younger_than = datetime.strptime(younger_than, "%Y-%m-%dT%H:%M:%S.%f")

        try:
            result = get_suspicious_files(rse_expression=rse_expression, younger_than=younger_than, nattempts=nattempts, vo=request.environ.get('vo'))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return render_json_list(result)


class BadReplicasStates(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        List the bad or suspicious replicas by states.

        .. :quickref: BadReplicasStates; List bad replicas.

        :query state: The state of the file (SUSPICIOUS or BAD).
        :query rse: The RSE name.
        :query younger_than: date in format "%Y-%m-%dT%H:%M:%S.%f" to select bad replicas younger than this date.
        :query older_than: date in format "%Y-%m-%dT%H:%M:%S.%f" to select bad replicas older than this date.
        :query limit: The maximum number of replicas returned.
        :query list_pfns: Flag to include pfns.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: List of dicts of bad file replicas.
        """
        result = []
        state = request.args.get('state', None)
        rse = request.args.get('rse', None)
        younger_than = request.args.get('younger_than', None)
        older_than = request.args.get('older_than', None)
        limit = request.args.get('limit', None)
        list_pfns = request.args.get('list_pfns', None)

        if isinstance(state, string_types):
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
            result = list_bad_replicas_status(state=state, rse=rse, younger_than=younger_than, older_than=older_than, limit=limit, list_pfns=list_pfns, vo=request.environ.get('vo'))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        data = ""
        for row in result:
            data += dumps(row, cls=APIEncoder) + '\n'

        return Response(data, content_type='application/x-json-stream')


class BadReplicasSummary(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        Return a summary of the bad replicas by incident.

        .. :quickref: BadReplicasSummary; List bad replicas by incident.

        :query rse_expression: The RSE expression.
        :query from_date: The start date.
        :query to_date: The end date.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: List of bad replicas by incident.
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
            result = get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date, to_date=to_date, vo=request.environ.get('vo'))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        data = ""
        for row in result:
            data += dumps(row, cls=APIEncoder) + '\n'

        return Response(data, content_type='application/x-json-stream')


class DatasetReplicas(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
        """
        List dataset replicas.

        .. :quickref: DatasetReplicas; List dataset replicas.

        :query deep: Flag to ennable lookup at the file level.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: A dictionary containing all replicas information.
        """
        deep = request.args.get('deep', False)
        try:
            data = ""
            for row in list_dataset_replicas(scope=scope, name=name, deep=deep, vo=request.environ.get('vo')):
                data += dumps(row, cls=APIEncoder) + '\n'
            return Response(data, content_type='application/x-json-stream')
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class DatasetReplicasBulk(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """
        List dataset replicas for multiple DIDs.

        .. :quickref: DatasetReplicasBulk; List dataset replicas (bulk).

        :<json list dids: List of DIDs for querying the datasets.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 400: Bad Request.
        :status 401: Invalid auth token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: A dictionary containing all replicas information.
        """

        json_data = request.data
        try:
            params = parse_response(json_data)
            dids = params['dids']
            didslength = len(dids)
        except KeyError as error:
            return generate_http_error_flask(400, 'KeyError', 'Cannot find mandatory parameter : %s' % str(error))
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        if didslength == 0:
            return generate_http_error_flask(400, 'ValueError', 'List of DIDs is empty')
        try:
            data = ""
            for row in list_dataset_replicas_bulk(dids=dids, vo=request.environ.get('vo')):
                data += dumps(row, cls=APIEncoder) + '\n'
            return Response(data, content_type='application/x-json-stream')
        except InvalidObject as error:
            return generate_http_error_flask(400, 'InvalidObject', 'Cannot validate DIDs: %s' % (str(error)))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class ReplicasRSE(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rse):
        """
        List dataset replicas per RSE.

        .. :quickref: ReplicasRSE; List dataset replicas per RSE.

        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: A dictionary containing all replicas on the RSE.
        """
        try:
            data = ""
            for row in list_datasets_per_rse(rse=rse, vo=request.environ.get('vo')):
                data += dumps(row, cls=APIEncoder) + '\n'
            return Response(data, content_type='application/x-json-stream')
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500


class BadPFNs(MethodView):

    def post(self):
        """
        Declare a list of bad PFNs.

        .. :quickref: BadPFNs; Declare bad replicas.

        :<json string pfns: The list of PFNs.
        :<json string reason: The reason of the loss.
        :<json string state: The state is eiher BAD, SUSPICIOUS or TEMPORARY_UNAVAILABLE.
        :<json string expires_at: The expiration date. Only apply to TEMPORARY_UNAVAILABLE.
        :resheader Content-Type: application/x-json-string
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid auth token.
        :status 404: Replica not found.
        :status 500: Internal Error.
        :returns: A list of not successfully declared files.
        """

        json_data = request.data
        pfns = []
        reason = None
        state = None
        expires_at = None
        try:
            params = parse_response(json_data)
            if 'pfns' in params:
                pfns = params['pfns']
            if 'reason' in params:
                reason = params['reason']
            if 'reason' in params:
                reason = params['reason']
            if 'state' in params:
                reason = params['state']
            if 'expires_at' in params:
                expires_at = datetime.strptime(params['expires_at'], "%Y-%m-%dT%H:%M:%S.%f")
            add_bad_pfns(pfns=pfns, issuer=request.environ.get('issuer'), state=state, reason=reason, expires_at=expires_at, vo=request.environ.get('vo'))
        except (ValueError, InvalidType) as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, 'ReplicaNotFound', error.args[0])
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return 'Created', 201


class Tombstone(MethodView):

    def post(self):
        """
        Set a tombstone on a list of replicas.

        .. :quickref: Tombstone; Set a tombstone on a list of replicas.

        :<json string replicas: list fo replicas
        :resheader Content-Type: application/x-json-string
        :status 201: Created.
        :status 401: Invalid auth token.
        :status 404: ReplicaNotFound.
        :status 500: Internal Error.
        """

        json_data = request.data
        replicas = []

        try:
            params = parse_response(json_data)
            if 'replicas' in params:
                replicas = params['replicas']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            for replica in replicas:
                set_tombstone(replica['rse'], replica['scope'], replica['name'], issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return 'Created', 201


bp = Blueprint('did', __name__)

list_replicas_view = ListReplicas.as_view('list_replicas')
bp.add_url_rule('/list', view_func=list_replicas_view, methods=['post', ])
replicas_view = Replicas.as_view('replicas')
bp.add_url_rule('/', view_func=replicas_view, methods=['post', 'put', 'delete'])
bp.add_url_rule('/<scope>/<name>', view_func=replicas_view, methods=['get', ])
bad_replicas_view = BadReplicas.as_view('bad_replicas')
bp.add_url_rule('/bad', view_func=bad_replicas_view, methods=['post', ])
bad_replicas_states_view = BadReplicasStates.as_view('bad_replicas_states')
bp.add_url_rule('/bad/states', view_func=bad_replicas_states_view, methods=['get', ])
bad_replicas_summary_view = BadReplicasSummary.as_view('bad_replicas_summary')
bp.add_url_rule('/bad/summary', view_func=bad_replicas_summary_view, methods=['get', ])
bad_replicas_pfn_view = BadPFNs.as_view('add_bad_pfns')
bp.add_url_rule('/bad/pfns', view_func=bad_replicas_pfn_view, methods=['post', ])
replicas_rse_view = ReplicasRSE.as_view('replicas_rse')
bp.add_url_rule('/rse/<rse>', view_func=replicas_rse_view, methods=['get', ])
dataset_replicas_view = DatasetReplicas.as_view('dataset_replicas')
bp.add_url_rule('/<scope>/<name>/datasets', view_func=dataset_replicas_view, methods=['get', ])
dataset_replicas_bulk_view = DatasetReplicasBulk.as_view('dataset_replicas_bulk')
bp.add_url_rule('/datasets_bulk', view_func=dataset_replicas_bulk_view, methods=['post', ])
replicas_dids_view = ReplicasDIDs.as_view('replicas_dids')
bp.add_url_rule('/dids', view_func=replicas_dids_view, methods=['post', ])
suspicious_replicas_view = SuspiciousReplicas.as_view('suspicious_replicas')
bp.add_url_rule('/suspicious', view_func=suspicious_replicas_view, methods=['post', ])
set_tombstone_view = Tombstone.as_view('set_tombstone')
bp.add_url_rule('/tombstone', view_func=set_tombstone_view, methods=['post', ])

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
