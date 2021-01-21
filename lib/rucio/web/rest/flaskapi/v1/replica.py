# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2020
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019-2020
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019-2020
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

from datetime import datetime
from json import dumps, loads
from traceback import format_exc
from xml.sax.saxutils import escape

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView
from six import string_types

from rucio.api.replica import (add_replicas, list_replicas, list_dataset_replicas,
                               list_dataset_replicas_bulk, delete_replicas,
                               get_did_from_pfns, update_replicas_states,
                               declare_bad_file_replicas, add_bad_dids, add_bad_pfns, get_suspicious_files,
                               declare_suspicious_file_replicas, list_bad_replicas_status,
                               get_bad_replicas_summary, list_datasets_per_rse,
                               set_tombstone, list_dataset_replicas_vp)
from rucio.common.config import config_get
from rucio.common.constants import SUPPORTED_PROTOCOLS
from rucio.common.exception import (AccessDenied, DataIdentifierAlreadyExists, InvalidType,
                                    DataIdentifierNotFound, Duplicate, InvalidPath,
                                    ResourceTemporaryUnavailable, RucioException,
                                    RSENotFound, UnsupportedOperation, ReplicaNotFound,
                                    InvalidObject, ScopeNotFound)
from rucio.common.utils import parse_response, APIEncoder, render_json_list
from rucio.core.replica_sorter import sort_replicas
from rucio.db.sqla.constants import BadFilesStatus, ReplicaState
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, try_stream, parse_scope_name, request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask

try:
    from urllib import unquote
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import unquote
    from urllib.parse import parse_qs


class Replicas(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream', 'application/metalink4+xml'])
    def get(self, scope_name):
        """
        List all replicas for data identifiers.

        .. :quickref: Replicas; List replicas for DID.
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :reqheader HTTP_ACCEPT: application/metalink4+xml
        :param scope_name: data identifier (scope)/(name).
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
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        content_type = request.accept_mimetypes.best_match(['application/x-json-stream', 'application/metalink4+xml'], 'application/x-json-stream')
        metalink = (content_type == 'application/metalink4+xml')

        dids, schemes, select, limit = [{'scope': scope, 'name': name}], None, None, None

        client_ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        client_location = {'ip': client_ip,
                           'fqdn': None,
                           'site': None}

        schemes = request.args.get('schemes', None)
        select = request.args.get('select', None)
        limit = request.args.get('limit', None)
        if limit:
            limit = int(limit)

        # Resolve all reasonable protocols when doing metalink for maximum access possibilities
        if metalink and schemes is None:
            schemes = SUPPORTED_PROTOCOLS

        try:
            def generate(vo):
                # we need to call list_replicas before starting to reply
                # otherwise the exceptions won't be propagated correctly
                first = metalink

                # then, stream the replica information
                for rfile in list_replicas(dids=dids, schemes=schemes, vo=vo):
                    if first and metalink:
                        # first, set the appropriate content type, and stream the header
                        yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'
                        first = False

                    replicas = []
                    dictreplica = {}
                    for rse in rfile['rses']:
                        for replica in rfile['rses'][rse]:
                            replicas.append(replica)
                            dictreplica[replica] = rse

                    replicas = sort_replicas(dictreplica, client_location, selection=select)

                    if not metalink:
                        yield dumps(rfile) + '\n'
                    else:
                        yield ' <file name="' + rfile['name'] + '">\n'
                        yield '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'

                        if rfile['adler32'] is not None:
                            yield '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                        if rfile['md5'] is not None:
                            yield '  <hash type="md5">' + rfile['md5'] + '</hash>\n'

                        yield '  <size>' + str(rfile['bytes']) + '</size>\n'

                        yield '  <glfn name="/atlas/rucio/%s:%s">' % (rfile['scope'], rfile['name'])
                        yield '</glfn>\n'

                        idx = 0
                        for replica in replicas:
                            yield '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx + 1) + '">' + escape(replica) + '</url>\n'
                            idx += 1
                            if limit and limit == idx:
                                break
                        yield ' </file>\n'

                if metalink:
                    if first:
                        # if still first output, i.e. there were no replicas
                        yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n</metalink>\n'
                    else:
                        # don't forget to send the metalink footer
                        yield '</metalink>\n'

            return try_stream(generate(vo=request.environ.get('vo')), content_type=content_type)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

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
        :status 404: Scope not found.
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
        except ScopeNotFound as error:
            return generate_http_error_flask(404, 'ScopeNotFound', error.args[0])
        except ResourceTemporaryUnavailable as error:
            return generate_http_error_flask(503, 'ResourceTemporaryUnavailable', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
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
            return str(error), 500
        return '', 200

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
            return str(error), 500
        return '', 200


class ListReplicas(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream', 'application/metalink4+xml'])
    def post(self):
        """
        List all replicas for data identifiers.

        .. :quickref: Replicas; List replicas for multiple DIDs.

        :reqheader HTTP_ACCEPT: application/metalink4+xml
        :query schemes: A list of schemes to filter the replicas.
        :query sort: Requested sorting of the result, e.g., 'geoip', 'closeness', 'dynamic', 'ranking', 'random'.
        :<json list dids: list of DIDs.
        :<json list schemes: A list of schemes to filter the replicas.
        :<json bool unavailable: Also include unavailable replicas.
        :<json bool all_states: Return all replicas whatever state they are in. Adds an extra 'states' entry in the result dictionary.
        :<json string rse_expression: The RSE expression to restrict on a list of RSEs.
        :<json dict client_location: Client location dictionary for PFN modification {'ip', 'fqdn', 'site'}.
        :<json bool sort: Requested sorting of the result, e.g., 'geoip', 'closeness', 'dynamic', 'ranking', 'random'.
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

        content_type = request.accept_mimetypes.best_match(['application/x-json-stream', 'application/metalink4+xml'], 'application/x-json-stream')
        metalink = (content_type == 'application/metalink4+xml')

        client_ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        dids, schemes, select, unavailable, limit = [], None, None, False, None
        ignore_availability, rse_expression, all_states, domain = False, None, False, None
        signature_lifetime, resolve_archives, resolve_parents = None, True, False
        updated_after = None

        client_location = {'ip': client_ip,
                           'fqdn': None,
                           'site': None}

        try:
            params = parse_response(request.data)
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
                client_location.update(params['client_location'])
            if 'sort' in params:
                select = params['sort']
            if 'domain' in params:
                domain = params['domain']
            if 'resolve_archives' in params:
                resolve_archives = params['resolve_archives']
            if 'resolve_parents' in params:
                resolve_parents = params['resolve_parents']

            if 'signature_lifetime' in params:
                signature_lifetime = params['signature_lifetime']
            else:
                # hardcoded default of 10 minutes if config is not parseable
                signature_lifetime = config_get('credentials', 'signature_lifetime', raise_exception=False, default=600)

            if 'updated_after' in params:
                if isinstance(params['updated_after'], (int, float)):
                    # convert from epoch time stamp to datetime object
                    updated_after = datetime.utcfromtimestamp(params['updated_after'])
                else:
                    # attempt UTC format '%Y-%m-%dT%H:%M:%S' conversion
                    updated_after = datetime.strptime(params['updated_after'], '%Y-%m-%dT%H:%M:%S')

        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        if request.query_string:
            query_string = request.query_string.decode(encoding='utf-8')
            params = parse_qs(query_string)
            if 'select' in params:
                select = params['select'][0]
            if 'limit' in params:
                limit = params['limit'][0]
            if 'sort' in params:
                select = params['sort']

        # Resolve all reasonable protocols when doing metalink for maximum access possibilities
        if metalink and schemes is None:
            schemes = SUPPORTED_PROTOCOLS

        content_type = 'application/metalink4+xml' if metalink else 'application/x-json-stream'

        try:
            def generate(request_id, issuer, vo):
                # we need to call list_replicas before starting to reply
                # otherwise the exceptions won't be propagated correctly
                first = metalink

                for rfile in list_replicas(dids=dids, schemes=schemes,
                                           unavailable=unavailable,
                                           request_id=request_id,
                                           ignore_availability=ignore_availability,
                                           all_states=all_states,
                                           rse_expression=rse_expression,
                                           client_location=client_location,
                                           domain=domain, signature_lifetime=signature_lifetime,
                                           resolve_archives=resolve_archives,
                                           resolve_parents=resolve_parents,
                                           updated_after=updated_after,
                                           issuer=issuer,
                                           vo=vo):

                    # in first round, set the appropriate content type, and stream the header
                    if first and metalink:
                        yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'
                    first = False

                    if not metalink:
                        yield dumps(rfile, cls=APIEncoder) + '\n'
                    else:
                        replicas = []
                        dictreplica = {}
                        for replica in rfile['pfns'].keys():
                            replicas.append(replica)
                            dictreplica[replica] = (rfile['pfns'][replica]['domain'],
                                                    rfile['pfns'][replica]['priority'],
                                                    rfile['pfns'][replica]['rse'],
                                                    rfile['pfns'][replica]['client_extract'])

                        yield ' <file name="' + rfile['name'] + '">\n'

                        if 'parents' in rfile and rfile['parents']:
                            yield '  <parents>\n'
                            for parent in rfile['parents']:
                                yield '   <did>' + parent + '</did>\n'
                            yield '  </parents>\n'

                        yield '  <identity>' + rfile['scope'] + ':' + rfile['name'] + '</identity>\n'
                        if rfile['adler32'] is not None:
                            yield '  <hash type="adler32">' + rfile['adler32'] + '</hash>\n'
                        if rfile['md5'] is not None:
                            yield '  <hash type="md5">' + rfile['md5'] + '</hash>\n'
                        yield '  <size>' + str(rfile['bytes']) + '</size>\n'

                        yield '  <glfn name="/%s/rucio/%s:%s"></glfn>\n' % (config_get('policy', 'schema',
                                                                                       raise_exception=False,
                                                                                       default='generic'),
                                                                            rfile['scope'],
                                                                            rfile['name'])

                        lanreplicas = [replica for replica, v in dictreplica.items() if v[0] == 'lan']
                        replicas = lanreplicas + sort_replicas({k: v for k, v in dictreplica.items() if v[0] != 'lan'}, client_location, selection=select)

                        idx = 1
                        for replica in replicas:
                            yield '  <url location="' + str(dictreplica[replica][2]) \
                                + '" domain="' + str(dictreplica[replica][0]) \
                                + '" priority="' + str(idx) \
                                + '" client_extract="' + str(dictreplica[replica][3]).lower() \
                                + '">' + escape(replica) + '</url>\n'
                            if limit and limit == idx:
                                break
                            idx += 1
                        yield ' </file>\n'

                if metalink:
                    if first:
                        # if still first output, i.e. there were no replicas
                        yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n</metalink>\n'
                    else:
                        # don't forget to send the metalink footer
                        yield '</metalink>\n'

            return try_stream(generate(request_id=request.environ.get('request_id'),
                                       issuer=request.environ.get('issuer'),
                                       vo=request.environ.get('vo')),
                              content_type=content_type)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


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
            def generate(vo):
                for pfn in get_did_from_pfns(pfns, rse, vo=vo):
                    yield dumps(pfn) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class BadReplicas(MethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self):
        """
        Declare a list of bad replicas.

        .. :quickref: BadReplicasStates; Declare bad replicas.

        :<json string pfns: The list of PFNs.
        :<json string reason: The reason of the loss.
        :resheader Content-Type: application/json
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid auth token.
        :status 404: RSE not found.
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
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
        return Response(dumps(not_declared_files), status=201, content_type='application/json')


class SuspiciousReplicas(MethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self):
        """
        Declare a list of suspicious replicas.

        .. :quickref: SuspiciousReplicas; Declare suspicious replicas.

        :<json string pfns: The list of PFNs.
        :<json string reason: The reason of the loss.
        :resheader Content-Type: application/json
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
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
        return Response(dumps(not_declared_files), status=201, content_type='application/json')

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
        rse_expression, younger_than, nattempts = None, None, None
        if request.query_string:
            query_string = request.query_string.decode(encoding='utf-8')
            try:
                params = loads(unquote(query_string))
            except ValueError:
                params = parse_qs(query_string)
            print(params)
            if 'rse_expression' in params:
                rse_expression = params['rse_expression'][0]
            if 'younger_than' in params and params['younger_than'][0]:
                younger_than = datetime.strptime(params['younger_than'][0], "%Y-%m-%dT%H:%M:%S")
            if 'nattempts' in params:
                nattempts = int(params['nattempts'][0])

        try:
            result = get_suspicious_files(rse_expression=rse_expression, younger_than=younger_than, nattempts=nattempts, vo=request.environ.get('vo'))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
        return Response(render_json_list(result), 200, content_type='application/json')


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
        state, rse, younger_than, older_than, limit, list_pfns = None, None, None, None, None, None
        if request.query_string:
            query_string = request.query_string.decode(encoding='utf-8')
            try:
                params = loads(unquote(query_string))
            except ValueError:
                params = parse_qs(query_string)
            if 'state' in params:
                state = params['state'][0]
            if isinstance(state, string_types):
                state = BadFilesStatus(state)
            if 'rse' in params:
                rse = params['rse'][0]
            if 'younger_than' in params:
                younger_than = datetime.strptime(params['younger_than'][0], "%Y-%m-%dT%H:%M:%S.%f")
            if 'older_than' in params and params['older_than']:
                older_than = datetime.strptime(params['older_than'][0], "%Y-%m-%dT%H:%M:%S.%f")
            if 'limit' in params:
                limit = int(params['limit'][0])
            if 'list_pfns' in params:
                list_pfns = bool(params['list_pfns'][0])

        try:
            def generate(vo):
                for row in list_bad_replicas_status(state=state, rse=rse, younger_than=younger_than,
                                                    older_than=older_than, limit=limit, list_pfns=list_pfns,
                                                    vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


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
        rse_expression, from_date, to_date = None, None, None
        if request.query_string:
            query_string = request.query_string.decode(encoding='utf-8')
            try:
                params = loads(unquote(query_string))
            except ValueError:
                params = parse_qs(query_string)
            if 'rse_expression' in params:
                rse_expression = params['rse_expression'][0]
            if 'from_date' in params and params['from_date'][0]:
                from_date = datetime.strptime(params['from_date'][0], "%Y-%m-%d")
            if 'to_date' in params:
                to_date = datetime.strptime(params['to_date'][0], "%Y-%m-%d")

        try:
            def generate(vo):
                for row in get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date,
                                                    to_date=to_date, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class DatasetReplicas(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        List dataset replicas.

        .. :quickref: DatasetReplicas; List dataset replicas.

        :param scope_name: data identifier (scope)/(name).
        :query deep: Flag to ennable lookup at the file level.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: A dictionary containing all replicas information.
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(deep, vo):
                for row in list_dataset_replicas(scope=scope, name=name, deep=deep, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            return try_stream(generate(deep=request.args.get('deep', False), vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class DatasetReplicasBulk(MethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """
        List dataset replicas for multiple DIDs.

        .. :quickref: DatasetReplicas; List replicas for multiple DIDs.

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
            return str(error), 500
        if didslength == 0:
            return generate_http_error_flask(400, 'ValueError', 'List of DIDs is empty')
        try:
            def generate(vo):
                for row in list_dataset_replicas_bulk(dids=dids, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except InvalidObject as error:
            return generate_http_error_flask(400, 'InvalidObject', 'Cannot validate DIDs: %s' % (str(error)))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class DatasetReplicasVP(MethodView):
    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        List dataset replicas using the Virtual Placement service.

        NOTICE: This is an RnD function and might change or go away at any time.

        .. :quickref: DatasetReplicas; List dataset replicas with VP.

        :param scope_name: data identifier (scope)/(name).
        :query deep: Flag to ennable lookup at the file level.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid auth token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: If VP exists a list of dicts of sites, otherwise nothing
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(deep, vo):
                for row in list_dataset_replicas_vp(scope=scope, name=name, deep=deep, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            return try_stream(generate(deep=request.args.get('deep', False), vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


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
            def generate(vo):
                for row in list_datasets_per_rse(rse=rse, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class BadDIDs(MethodView):

    def post(self):
        """
        Declare a list of bad replicas by DID.

        .. :quickref: BadDIDs; Declare bad replicas by DID.

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
        dids = []
        rse = None
        reason = None
        state = None
        expires_at = None
        try:
            params = parse_response(json_data)
            if 'dids' in params:
                dids = params['dids']
            if 'rse' in params:
                rse = params['rse']
            if 'reason' in params:
                reason = params['reason']
            state = ReplicaState.BAD
            if 'expires_at' in params and params['expires_at']:
                expires_at = datetime.strptime(params['expires_at'], "%Y-%m-%dT%H:%M:%S.%f")
            not_declared_files = add_bad_dids(dids=dids, rse=rse, issuer=request.environ.get('issuer'), state=state,
                                              reason=reason, expires_at=expires_at, vo=request.environ.get('vo'))
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
            return str(error), 500
        return Response(dumps(not_declared_files), status=201, content_type='application/json')


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
            if 'state' in params:
                state = params['state']
            if 'expires_at' in params and params['expires_at']:
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
            return str(error), 500
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
            return str(error), 500
        return 'Created', 201


def blueprint(no_doc=True):
    bp = Blueprint('replica', __name__, url_prefix='/replicas')

    list_replicas_view = ListReplicas.as_view('list_replicas')
    bp.add_url_rule('/list', view_func=list_replicas_view, methods=['post', ])
    replicas_view = Replicas.as_view('replicas')
    if no_doc:
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('', view_func=replicas_view, methods=['post', 'put', 'delete'])
    bp.add_url_rule('/', view_func=replicas_view, methods=['post', 'put', 'delete'])
    suspicious_replicas_view = SuspiciousReplicas.as_view('suspicious_replicas')
    bp.add_url_rule('/suspicious', view_func=suspicious_replicas_view, methods=['post', ])
    bad_replicas_states_view = BadReplicasStates.as_view('bad_replicas_states')
    bp.add_url_rule('/bad/states', view_func=bad_replicas_states_view, methods=['get', ])
    bad_replicas_summary_view = BadReplicasSummary.as_view('bad_replicas_summary')
    bp.add_url_rule('/bad/summary', view_func=bad_replicas_summary_view, methods=['get', ])
    bad_replicas_pfn_view = BadPFNs.as_view('add_bad_pfns')
    bp.add_url_rule('/bad/pfns', view_func=bad_replicas_pfn_view, methods=['post', ])
    bad_replicas_dids_view = BadDIDs.as_view('add_bad_dids')
    bp.add_url_rule('/bad/dids', view_func=bad_replicas_dids_view, methods=['post', ])
    replicas_rse_view = ReplicasRSE.as_view('replicas_rse')
    bp.add_url_rule('/rse/<rse>', view_func=replicas_rse_view, methods=['get', ])
    bad_replicas_view = BadReplicas.as_view('bad_replicas')
    bp.add_url_rule('/bad', view_func=bad_replicas_view, methods=['post', ])
    replicas_dids_view = ReplicasDIDs.as_view('replicas_dids')
    bp.add_url_rule('/dids', view_func=replicas_dids_view, methods=['post', ])
    dataset_replicas_view = DatasetReplicas.as_view('dataset_replicas')
    bp.add_url_rule('/<path:scope_name>/datasets', view_func=dataset_replicas_view, methods=['get', ])
    dataset_replicas_bulk_view = DatasetReplicasBulk.as_view('dataset_replicas_bulk')
    bp.add_url_rule('/datasets_bulk', view_func=dataset_replicas_bulk_view, methods=['post', ])
    dataset_replicas_vp_view = DatasetReplicasVP.as_view('dataset_replicas_vp')
    bp.add_url_rule('/<path:scope_name>', view_func=replicas_view, methods=['get', ])
    set_tombstone_view = Tombstone.as_view('set_tombstone')
    bp.add_url_rule('/tombstone', view_func=set_tombstone_view, methods=['post', ])

    if no_doc:
        bp.add_url_rule('/list/', view_func=list_replicas_view, methods=['post', ])
        bp.add_url_rule('/suspicious/', view_func=suspicious_replicas_view, methods=['post', ])
        bp.add_url_rule('/bad/states/', view_func=bad_replicas_states_view, methods=['get', ])
        bp.add_url_rule('/bad/summary/', view_func=bad_replicas_summary_view, methods=['get', ])
        bp.add_url_rule('/bad/pfns/', view_func=bad_replicas_pfn_view, methods=['post', ])
        bp.add_url_rule('/bad/dids/', view_func=bad_replicas_dids_view, methods=['post', ])
        bp.add_url_rule('/rse/<rse>/', view_func=replicas_rse_view, methods=['get', ])
        bp.add_url_rule('/bad/', view_func=bad_replicas_view, methods=['post', ])
        bp.add_url_rule('/dids/', view_func=replicas_dids_view, methods=['post', ])
        bp.add_url_rule('/datasets_bulk/', view_func=dataset_replicas_bulk_view, methods=['post', ])
        bp.add_url_rule('/<path:scope_name>/datasets_vp', view_func=dataset_replicas_vp_view, methods=['get', ])
        bp.add_url_rule('/<path:scope_name>/', view_func=replicas_view, methods=['get', ])
        bp.add_url_rule('/tombstone/', view_func=set_tombstone_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(no_doc=False))
    return doc_app
