#!/usr/bin/env python
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2013-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2019
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from datetime import datetime
from json import dumps, loads
from six import string_types
from traceback import format_exc
try:
    from urllib import unquote
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import unquote
    from urllib.parse import parse_qs
from web import application, ctx, Created, data, header, InternalError, loadhook, OK, unloadhook

from geoip2.errors import AddressNotFoundError

from rucio.api.replica import (add_replicas, list_replicas, list_dataset_replicas,
                               delete_replicas, list_dataset_replicas_vp,
                               get_did_from_pfns, update_replicas_states,
                               declare_bad_file_replicas, add_bad_pfns, get_suspicious_files,
                               declare_suspicious_file_replicas, list_bad_replicas_status,
                               get_bad_replicas_summary, list_datasets_per_rse,
                               set_tombstone)
from rucio.db.sqla.constants import BadFilesStatus
from rucio.common.config import config_get
from rucio.common.exception import (AccessDenied, DataIdentifierAlreadyExists, InvalidType,
                                    DataIdentifierNotFound, Duplicate, InvalidPath,
                                    ResourceTemporaryUnavailable, RucioException,
                                    RSENotFound, UnsupportedOperation, ReplicaNotFound)
from rucio.common.replica_sorter import sort_random, sort_geoip, sort_closeness, sort_dynamic, sort_ranking
from rucio.common.schema import SCOPE_NAME_REGEXP
from rucio.common.utils import generate_http_error, parse_response, APIEncoder, render_json_list
from rucio.rse.protocols import supported_protocols
from rucio.web.rest.common import rucio_loadhook, rucio_unloadhook, RucioController, check_accept_header_wrapper

URLS = ('/list/?$', 'ListReplicas',
        '/?$', 'Replicas',
        '/suspicious/?$', 'SuspiciousReplicas',
        '/bad/states/?$', 'BadReplicasStates',
        '/bad/summary/?$', 'BadReplicasSummary',
        '/bad/pfns/?$', 'BadPFNs',
        '/rse/(.*)/?$', 'ReplicasRSE',
        '/bad/?$', 'BadReplicas',
        '/dids/?$', 'ReplicasDIDs',
        '%s/datasets$' % SCOPE_NAME_REGEXP, 'DatasetReplicas',
        '%s/datasets_vp$' % SCOPE_NAME_REGEXP, 'DatasetReplicasVP',
        '%s/?$' % SCOPE_NAME_REGEXP, 'Replicas',
        '/tombstone/?$', 'Tombstone')


class Replicas(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream', 'application/metalink4+xml'])
    def GET(self, scope, name):
        """
        List all replicas for data identifiers.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :returns: A dictionary containing all replicas information.
        :returns: A metalink description of replicas if metalink(4)+xml is specified in Accept:
        """

        metalink = False
        if ctx.env.get('HTTP_ACCEPT') is not None:
            tmp = ctx.env.get('HTTP_ACCEPT').split(',')
            if 'application/metalink4+xml' in tmp:
                metalink = True

        dids, schemes, select, limit = [{'scope': scope, 'name': name}], None, None, None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'schemes' in params:
                schemes = params['schemes']
            if 'select' in params:
                select = params['select'][0]
            if 'limit' in params:
                limit = int(params['limit'][0])

        # Resolve all reasonable protocols when doing metalink for maximum access possibilities
        if metalink and schemes is None:
            schemes = supported_protocols

        try:

            # we need to call list_replicas before starting to reply
            # otherwise the exceptions won't be propagated correctly
            __first = True

            # then, stream the replica information
            for rfile in list_replicas(dids=dids, schemes=schemes):

                # in first round, set the appropriate content type, and stream the header
                if __first:
                    if not metalink:
                        header('Content-Type', 'application/x-json-stream')
                    else:
                        header('Content-Type', 'application/metalink4+xml')
                        yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'
                    __first = False

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
                        replicas = sort_geoip(dictreplica, client_ip)
                    except AddressNotFoundError:
                        pass
                else:
                    replicas = sort_random(dictreplica)
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
                        yield '   <url location="' + str(dictreplica[replica]) + '" priority="' + str(idx + 1) + '">' + replica + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    yield ' </file>\n'

            # ensure complete metalink
            if __first and metalink:
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'
            if metalink:
                yield '</metalink>\n'

        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

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
        except InvalidPath as error:
            raise generate_http_error(400, 'InvalidPath', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except DataIdentifierAlreadyExists as error:
            raise generate_http_error(409, 'DataIdentifierAlreadyExists', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except ResourceTemporaryUnavailable as error:
            raise generate_http_error(503, 'ResourceTemporaryUnavailable', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
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
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(500, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
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
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            raise generate_http_error(404, 'RSENotFound', error.args[0])
        except ResourceTemporaryUnavailable as error:
            raise generate_http_error(503, 'ResourceTemporaryUnavailable', error.args[0])
        except ReplicaNotFound as error:
            raise generate_http_error(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise OK()


class ListReplicas(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream', 'application/metalink4+xml'])
    def POST(self):
        """
        List all replicas for data identifiers.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :returns: A dictionary containing all replicas information, either as JSON stream or metalink4.
        """

        metalink = False
        if ctx.env.get('HTTP_ACCEPT') is not None:
            tmp = ctx.env.get('HTTP_ACCEPT').split(',')
            if 'application/metalink4+xml' in tmp:
                metalink = True

        client_ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if client_ip is None:
            client_ip = ctx.ip

        dids, schemes, select, unavailable, limit = [], None, None, False, None
        ignore_availability, rse_expression, all_states, domain = False, None, False, None
        signature_lifetime, resolve_archives, resolve_parents = None, True, False
        client_location = {}

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
            if 'client_location' in params:
                client_location = params['client_location']
                client_location['ip'] = params['client_location'].get('ip', client_ip)
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
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'select' in params:
                select = params['select'][0]
            if 'limit' in params:
                limit = params['limit'][0]
            if 'sort' in params:
                select = params['sort']

        # Resolve all reasonable protocols when doing metalink for maximum access possibilities
        if metalink and schemes is None:
            schemes = supported_protocols

        try:

            # we need to call list_replicas before starting to reply
            # otherwise the exceptions won't be propagated correctly
            __first = True

            # then, stream the replica information
            for rfile in list_replicas(dids=dids, schemes=schemes,
                                       unavailable=unavailable,
                                       request_id=ctx.env.get('request_id'),
                                       ignore_availability=ignore_availability,
                                       all_states=all_states,
                                       rse_expression=rse_expression,
                                       client_location=client_location,
                                       domain=domain, signature_lifetime=signature_lifetime,
                                       resolve_archives=resolve_archives,
                                       resolve_parents=resolve_parents,
                                       issuer=ctx.env.get('issuer')):

                # in first round, set the appropriate content type, and stream the header
                if __first:
                    if not metalink:
                        header('Content-Type', 'application/x-json-stream')
                    else:
                        header('Content-Type', 'application/metalink4+xml')
                        yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'
                    __first = False

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

                    # TODO: deprecate this
                    if select == 'geoip':
                        replicas = sort_geoip(dictreplica, client_location['ip'])
                    elif select == 'closeness':
                        replicas = sort_closeness(dictreplica, client_location)
                    elif select == 'dynamic':
                        replicas = sort_dynamic(dictreplica, client_location)
                    elif select == 'ranking':
                        replicas = sort_ranking(dictreplica, client_location)
                    elif select == 'random':
                        replicas = sort_random(dictreplica)
                    else:
                        replicas = sorted(dictreplica, key=dictreplica.get)

                    idx = 0
                    for replica in replicas:
                        yield '  <url location="' + str(dictreplica[replica][2]) \
                            + '" domain="' + str(dictreplica[replica][0]) \
                            + '" priority="' + str(dictreplica[replica][1]) \
                            + '" client_extract="' + str(dictreplica[replica][3]).lower() \
                            + '">' + replica + '</url>\n'
                        idx += 1
                        if limit and limit == idx:
                            break
                    yield ' </file>\n'

            # ensure complete metalink
            if __first and metalink:
                yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'
            if metalink:
                yield '</metalink>\n'

        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class ReplicasDIDs(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def POST(self):
        """
        List the DIDs associated to a list of replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
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
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class BadReplicas(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def POST(self):
        """
        Declare a list of bad replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable
            500 InternalError

        """
        json_data = data()
        pfns = []
        header('Content-Type', 'application/json')
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
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except ReplicaNotFound as error:
            raise generate_http_error(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created(dumps(not_declared_files))


class SuspiciousReplicas(RucioController):

    @check_accept_header_wrapper(['application/json'])
    def POST(self):
        """
        Declare a list of suspicious replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        """
        json_data = data()
        pfns = []
        header('Content-Type', 'application/json')
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
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created(dumps(not_declared_files))

    @check_accept_header_wrapper(['application/json'])
    def GET(self):
        """
        List the suspicious replicas on a lsit of RSEs.

        HTTP Success:
            200 OK

        HTTP Error:
            406 Not Acceptable
            500 InternalError

        """
        header('Content-Type', 'application/json')
        result = []
        rse_expression, younger_than, nattempts = None, None, None
        if ctx.query:
            try:
                params = loads(unquote(ctx.query[1:]))
            except ValueError:
                params = parse_qs(ctx.query[1:])
            print(params)
            if 'rse_expression' in params:
                rse_expression = params['rse_expression'][0]
            if 'younger_than' in params and params['younger_than'][0]:
                younger_than = datetime.strptime(params['younger_than'][0], "%Y-%m-%dT%H:%M:%S")
            if 'nattempts' in params:
                nattempts = int(params['nattempts'][0])

        try:
            result = get_suspicious_files(rse_expression=rse_expression, younger_than=younger_than, nattempts=nattempts)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        return render_json_list(result)


class BadReplicasStates(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """
        List the bad or suspicious replicas by states.

        HTTP Success:
            200 OK

        HTTP Error:
            406 Not Acceptable
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
            if isinstance(state, string_types):
                state = BadFilesStatus.from_string(state)
            if 'rse' in params:
                rse = params['rse'][0]
            if 'younger_than' in params:
                younger_than = datetime.strptime(params['younger_than'], "%Y-%m-%dT%H:%M:%S.%f")
            if 'older_than' in params and params['older_than']:
                older_than = datetime.strptime(params['older_than'], "%Y-%m-%dT%H:%M:%S.%f")
            if 'limit' in params:
                limit = int(params['limit'][0])
            if 'list_pfns' in params:
                list_pfns = bool(params['list_pfns'][0])

        try:
            result = list_bad_replicas_status(state=state, rse=rse, younger_than=younger_than, older_than=older_than, limit=limit, list_pfns=list_pfns)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        for row in result:
            yield dumps(row, cls=APIEncoder) + '\n'


class BadReplicasSummary(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """
        Return a summary of the bad replicas by incident.

        HTTP Success:
            200 OK

        HTTP Error:
            406 Not Acceptable
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
            if 'from_date' in params and params['from_date'][0]:
                from_date = datetime.strptime(params['from_date'][0], "%Y-%m-%d")
            if 'to_date' in params:
                to_date = datetime.strptime(params['to_date'][0], "%Y-%m-%d")

        try:
            result = get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date, to_date=to_date)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        for row in result:
            yield dumps(row, cls=APIEncoder) + '\n'


class DatasetReplicas(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """
        List dataset replicas replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :returns: A dictionary containing all replicas information.
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
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class DatasetReplicasVP(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """
        List dataset replicas for a DID (scope:name) using the
        Virtual Placement service.

        NOTICE: This is an RnD function and might change or go away at any time.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :returns: If VP exists a list of dicts of sites, otherwise a list of dicts of dataset replicas
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
            for row in list_dataset_replicas_vp(scope=scope, name=name, deep=deep):
                yield dumps(row, cls=APIEncoder) + '\n'
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class ReplicasRSE(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, rse):
        """
        List dataset replicas replicas.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            500 InternalError

        :returns: A dictionary containing all replicas on the RSE.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for row in list_datasets_per_rse(rse=rse):
                yield dumps(row, cls=APIEncoder) + '\n'
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)


class BadPFNs(RucioController):

    def POST(self):
        """
        Declare a list of bad PFNs.

        HTTP Success:
            200 OK

        HTTP Error:
            400 BadRequest
            401 Unauthorized
            409 Conflict
            500 InternalError

        """
        json_data = data()
        pfns = []
        reason = None
        state = None
        expires_at = None
        header('Content-Type', 'application/x-json-stream')
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
            add_bad_pfns(pfns=pfns, issuer=ctx.env.get('issuer'), state=state, reason=reason, expires_at=expires_at)
        except (ValueError, InvalidType) as error:
            raise generate_http_error(400, 'ValueError', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except ReplicaNotFound as error:
            raise generate_http_error(404, 'ReplicaNotFound', error.args[0])
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


class Tombstone(RucioController):

    def POST(self):
        """
        Set a tombstone on a list of replicas.

        HTTP Success:
            201 OK

        HTTP Error:
            401 Unauthorized
            404 ReplicaNotFound
            500 InternalError
        """
        json_data = data()
        replicas = []
        try:
            params = parse_response(json_data)
            if 'replicas' in params:
                replicas = params['replicas']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            for replica in replicas:
                set_tombstone(replica['rse'], replica['scope'], replica['name'], issuer=ctx.env.get('issuer'))
        except ReplicaNotFound as error:
            raise generate_http_error(404, 'ReplicaNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
APP.add_processor(unloadhook(rucio_unloadhook))
application = APP.wsgifunc()
