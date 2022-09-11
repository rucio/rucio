# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from datetime import datetime
from itertools import chain
from json import dumps, loads
from urllib.parse import parse_qs, unquote
from xml.sax.saxutils import escape

from flask import Flask, Blueprint, Response, request

from rucio.api.replica import add_replicas, list_replicas, list_dataset_replicas, list_dataset_replicas_bulk, \
    delete_replicas, get_did_from_pfns, update_replicas_states, declare_bad_file_replicas, add_bad_dids, add_bad_pfns, \
    get_suspicious_files, declare_suspicious_file_replicas, list_bad_replicas_status, get_bad_replicas_summary, \
    list_datasets_per_rse, set_tombstone, list_dataset_replicas_vp
from rucio.api.quarantined_replica import quarantine_file_replicas
from rucio.common.config import config_get
from rucio.common.constants import SUPPORTED_PROTOCOLS
from rucio.common.exception import AccessDenied, DataIdentifierAlreadyExists, InvalidType, DataIdentifierNotFound, \
    Duplicate, InvalidPath, ResourceTemporaryUnavailable, RSENotFound, ReplicaNotFound, InvalidObject, ScopeNotFound, ReplicaIsLocked
from rucio.common.utils import parse_response, APIEncoder, render_json_list
from rucio.core.replica_sorter import sort_replicas
from rucio.db.sqla.constants import BadFilesStatus
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, try_stream, parse_scope_name, \
    request_auth_env, response_headers, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


def _sorted_with_priorities(replicas, sorted_pfns, limit=None):
    """
    Pick up to "limit" replicas from "replicas" in the order given by sorted_pfns.
    Sets the corresponding priority in returned replicas.

    :param replicas: Dictionary {pfn: replica_definition}.
    :param sorted_pfns: Sorted list of pfns.
    :param limit: only return this many replicas
    :yields: index and corresponding pfn
    """
    for idx, pfn in enumerate(sorted_pfns, start=1):
        if limit is None or idx <= limit:
            replica = replicas[pfn]
            replica['priority'] = idx
            yield pfn, replica


def _generate_one_metalink_file(rfile, policy_schema, detailed_url=True):
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

    yield f'  <glfn name="/{policy_schema}/rucio/{rfile["scope"]}:{rfile["name"]}"></glfn>\n'

    for pfn, replica in rfile['pfns'].items():
        if detailed_url:
            yield (
                '  '
                f'<url location="{replica["rse"]}"'
                f' domain="{replica["domain"]}"'
                f' priority="{replica["priority"]}"'
                f' client_extract="{str(replica["client_extract"]).lower()}"'
                f'>{escape(pfn)}</url>\n'
            )
        else:
            yield (
                '  '
                f'<url location="{replica["rse"]}"'
                f' priority="{replica["priority"]}"'
                f'>{escape(pfn)}</url>\n'
            )
    yield ' </file>\n'


def _generate_metalink_response(rfiles, policy_schema, detailed_url=True):
    first = True
    for rfile in rfiles:
        if first:
            # first, set the appropriate content type, and stream the header
            yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n'
            first = False

        yield from _generate_one_metalink_file(rfile, policy_schema=policy_schema, detailed_url=detailed_url)

    if first:
        # if still first output, i.e. there were no replicas
        yield '<?xml version="1.0" encoding="UTF-8"?>\n<metalink xmlns="urn:ietf:params:xml:ns:metalink">\n</metalink>\n'
    else:
        # don't forget to send the metalink footer
        yield '</metalink>\n'


def _generate_json_response(rfiles):
    for rfile in rfiles:
        yield dumps(rfile) + '\n'


class Replicas(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream', 'application/metalink4+xml'])
    def get(self, scope_name):
        """
        ---
        summary: Get Replicas
        description: List all replicas for data identifiers.
        tags:
          - Replicas
        parameters:
        - name: scope_name
          in: path
          description: The DID associated with the replicas.
          schema:
            type: string
          style: simple
        - name: X-Forwarded-For
          in: header
          description: The client ip
          schema:
            type: string
        - name: schemes
          in: query
          description: The schemes of the replicas.
          schema:
            type: string
        - name: select
          in: query
          description: The sorting algorithm.
          schema:
            type: string
            enum: ["geoip", "closeness", "dynamic", "ranking", "random"]
        - name: limit
          in: query
          description: The maximum number of replicas returned.
          schema:
            type: integer
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list with all replicas.
                  type: array
                  items:
                    description: A replica. Possibly contains more information.
                    type: object
                    properties:
                      scope:
                        description: The scope of the replica.
                        type: string
                      name:
                        description: The name of the replica.
                        type: string
                      bytes:
                        description: The size of the replica in bytes.
                        type: integer
                      md5:
                        description: The md5 checksum of the replica.
                        type: string
                      adler32:
                        description: The adler32 checksum of the replica.
                        type: string
                      pfns:
                        description: The pfns associated with the replica.
                        type: array
                      rses:
                        description: The rse associated with the replica.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Did not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        content_type = request.accept_mimetypes.best_match(['application/x-json-stream', 'application/metalink4+xml'], 'application/x-json-stream')
        metalink = (content_type == 'application/metalink4+xml')
        dids = [{'scope': scope, 'name': name}]
        select, limit = None, None

        client_ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)
        client_location = {'ip': client_ip, 'fqdn': None, 'site': None}

        schemes = request.args.get('schemes', default=None)
        select = request.args.get('select', default=None)
        limit = request.args.get('limit', default=None)
        if limit:
            limit = int(limit)

        # Resolve all reasonable protocols when doing metalink for maximum access possibilities
        if metalink and schemes is None:
            schemes = SUPPORTED_PROTOCOLS

        try:
            def _list_and_sort_replicas(vo):
                # we need to call list_replicas before starting to reply
                # otherwise the exceptions won't be propagated correctly
                for rfile in list_replicas(dids=dids, schemes=schemes, vo=vo):
                    replicas = []
                    dictreplica = {}
                    for rse in rfile['rses']:
                        for replica in rfile['rses'][rse]:
                            replicas.append(replica)
                            dictreplica[replica] = rse

                    replicas = sort_replicas(dictreplica, client_location, selection=select)
                    rfile['pfns'] = dict(_sorted_with_priorities(rfile['pfns'], replicas, limit=limit))
                    yield rfile

            rfiles = _list_and_sort_replicas(vo=request.environ.get('vo'))
            if metalink:
                response_generator = _generate_metalink_response(rfiles, 'atlas', detailed_url=False)
            else:
                response_generator = _generate_json_response(rfiles)
            return try_stream(response_generator, content_type=content_type)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self):
        """
        ---
        summary: Create File Replicas
        description: Create file replicas at a given RSE.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - rse
                - files
                properties:
                  rse:
                    description: The rse for the replication
                    type: string
                  files:
                    description: The files to replicate
                    type: array
                    items:
                      type: object
                      required:
                        - pfn
                        - bytes
                        - name
                      properties:
                        pfn:
                          description: The pfn of the replica.
                          type: string
                        name:
                          description: The DID name.
                          type: string
                        bytes:
                          description: The size of the replica in bytes.
                          type: integer
                        state:
                          description: The state of the replica.
                          type: string
                        path:
                          description: The path of the new replica.
                          type: string
                        md5:
                          description: The md5 checksum.
                          type: string
                        adler32:
                          description: The adler32 checksum.
                          type: string
                        lcok_cnt:
                          description: The lock count.
                          type: integer
                        tombstone:
                          description: The tombstone.
                          type: string
                  ignore_availability:
                    description: The ignore availability.
                    type: boolean
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          400:
            description: Invalid Path
          401:
            description: Invalid Auth Token
          404:
            description: Rse or scope not found
          409:
            description: Replica or Did already exists
          503:
            description: Resource temporary unavailable
        """
        parameters = json_parameters(parse_response)
        rse = param_get(parameters, 'rse')
        files = param_get(parameters, 'files')

        try:
            add_replicas(
                rse=rse,
                files=files,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
                ignore_availability=param_get(parameters, 'ignore_availability', default=False),
            )
        except InvalidPath as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (Duplicate, DataIdentifierAlreadyExists) as error:
            return generate_http_error_flask(409, error)
        except (RSENotFound, ScopeNotFound) as error:
            return generate_http_error_flask(404, error)
        except ResourceTemporaryUnavailable as error:
            return generate_http_error_flask(503, error)

        return 'Created', 201

    def put(self):
        """
        ---
        summary: Update File Replicas
        description: Update file replicas state at a given RSE.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - rse
                - files
                properties:
                  rse:
                    description: The rse for the replication
                    type: string
                  files:
                    description: The files to replicate
                    type: array
                    items:
                      type: object
                      properties:
                        name:
                          description: The pfn of the replica.
                          type: string
                        state:
                          description: The pfn of the replica.
                          type: string
                        path:
                          description: The pfn of the replica.
                          type: string
                        error_message:
                          description: The error message if an error occured.
                          type: string
                        broken_rule_id:
                          description: The id of the broken rule if one was found.
                          type: string
                        broken_message:
                          description: The message of the broken rule.
                          type: string
        responses:
          200:
            description: OK
          400:
            description: Cannot decode json parameter list
          401:
            description: Invalid Auth Token
        """
        parameters = json_parameters(parse_response)
        rse = param_get(parameters, 'rse')
        files = param_get(parameters, 'files')

        try:
            update_replicas_states(rse=rse, files=files, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return '', 200

    def delete(self):
        """
        ---
        summary: Delete File Replicas
        description: Delete file replicas at a given RSE.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                  - rse
                  - files
                properties:
                  rse:
                    description: The rse name.
                    type: string
                  files:
                    description: The files to delete.
                    type: array
                    items:
                      type: object
                      required:
                        - name
                      properties:
                        name:
                          description: The name of the replica.
                          type: string
        responses:
          200:
            description: OK
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Rse or Replica not found
        """
        parameters = json_parameters(parse_response)
        rse = param_get(parameters, 'rse')
        files = param_get(parameters, 'files')

        try:
            delete_replicas(
                rse=rse,
                files=files,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
                ignore_availability=param_get(parameters, 'ignore_availability', default=False),
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (RSENotFound, ReplicaNotFound) as error:
            return generate_http_error_flask(404, error)
        except ResourceTemporaryUnavailable as error:
            return generate_http_error_flask(503, error)

        return '', 200


class ListReplicas(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream', 'application/metalink4+xml'])
    def post(self):
        """
        ---
        summary: List Replicas
        description: List all replicas for a DID.
        tags:
          - Replicas
        parameters:
        - name: X-Forwarded-For
          in: header
          description: The client ip address.
          schema:
            type: string
        - name: limit
          in: query
          description: The maximum number pfns per replica to return.
          schema:
            type: integer
        - name: select
          in: query
          description: Requested sorting of the result, e.g., 'geoip', 'closeness', 'dynamic', 'ranking', 'random'.
          schema:
            type: string
        - name: sort
          in: query
          description: Requested sorting of the result, e.g., 'geoip', 'closeness', 'dynamic', 'ranking', 'random'.
          schema:
            type: string
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  client_location:
                    description: The clients location.
                    type: string
                  dids:
                    description: List of Dids.
                    type: array
                    items:
                      type: object
                      properties:
                        scope:
                          description: The scope of the did.
                          type: string
                        name:
                          description: The name of the did.
                          type: string
                  schemes:
                    description: A list of schemes to filter the replicas.
                    type: array
                    items:
                      type: string
                  sort:
                    description: Requested sorting of the result, e.g., 'geoip', 'closeness', 'dynamic', 'ranking', 'random'.
                    type: string
                  unavailable:
                    description: If unavailable rse should be considered.
                    type: boolean
                    deprecated: true
                  ignore_availability:
                    description: If the availability should be ignored.
                    type: boolean
                  rse_expression:
                    description: The RSE expression to restrict on a list of RSEs.
                    type: string
                  all_states:
                    description: Return all replicas whatever state they are in. Adds an extra 'states' entry in the result dictionary.
                    type: boolean
                  domain:
                    description: The network domain for the call, either None, 'wan' or 'lan'. None is fallback to 'wan', 'all' is both ['lan','wan']
                    type: string
                  signature_lifetime:
                    description: If supported, in seconds, restrict the lifetime of the signed PFN.
                    type: integer
                  resolve_archives:
                    description:  When set to True, find archives which contain the replicas.
                    type: boolean
                  resolve_parents:
                    description: When set to True, find all parent datasets which contain the replicas.
                    type: boolean
                  updated_after:
                    description: datetime object (UTC time), only return replicas updated after this time
                    type: string
                  nrandom:
                    description: The maximum number of replicas to return.
                    type: integer
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      scope:
                        description: The scope of the replica.
                        type: string
                      name:
                        description: The name of the replica.
                        type: string
                      bytes:
                        description: The size of the replica in bytes.
                        type: integer
                      md5:
                        description: The md5 checksum.
                        type: string
                      adler32:
                        description: The adler32 checksum.
                        type: string
                      pfns:
                        description: The pfns.
                        type: array
                      rses:
                        description: The RSESs.
                        type: array
              application/metalink4+xml:
                schema:
                  type: object
                  properties:
                    scope:
                      description: The scope of the replica.
                      type: string
                    name:
                      description: The name of the replica.
                      type: string
                    bytes:
                      description: The size of the replica in bytes.
                      type: integer
                    md5:
                      description: The md5 checksum.
                      type: string
                    adler32:
                      description: The adler32 checksum.
                      type: string
                    pfns:
                      description: The pfns.
                      type: array
                    rses:
                      description: The RSESs.
                      type: array
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Did not found.
          406:
            description: Not acceptable
        """
        content_type = request.accept_mimetypes.best_match(['application/x-json-stream', 'application/metalink4+xml'], 'application/x-json-stream')
        metalink = (content_type == 'application/metalink4+xml')

        client_ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        parameters = json_parameters(parse_response)

        client_location = {'ip': client_ip,
                           'fqdn': None,
                           'site': None}
        client_location.update(param_get(parameters, 'client_location', default={}))

        # making sure IP address is not overwritten
        client_location['ip'] = client_ip

        dids = param_get(parameters, 'dids', default=[])
        schemes = param_get(parameters, 'schemes', default=None)
        select = param_get(parameters, 'sort', default=None)
        unavailable = param_get(parameters, 'unavailable', default=False)
        ignore_availability = param_get(parameters, 'ignore_availability', default='unavailable' in parameters)
        rse_expression = param_get(parameters, 'rse_expression', default=None)
        all_states = param_get(parameters, 'all_states', default=False)
        domain = param_get(parameters, 'domain', default=None)
        if 'signature_lifetime' in parameters:
            signature_lifetime = param_get(parameters, 'signature_lifetime')
        else:
            # hardcoded default of 10 minutes if config is not parseable
            signature_lifetime = config_get('credentials', 'signature_lifetime', raise_exception=False, default=600)
        resolve_archives = param_get(parameters, 'resolve_archives', default=True)
        resolve_parents = param_get(parameters, 'resolve_parents', default=False)
        updated_after = param_get(parameters, 'updated_after', default=None)
        if updated_after is not None:
            if isinstance(updated_after, (int, float)):
                # convert from epoch time stamp to datetime object
                updated_after = datetime.utcfromtimestamp(updated_after)
            else:
                # attempt UTC format '%Y-%m-%dT%H:%M:%S' conversion
                updated_after = datetime.strptime(updated_after, '%Y-%m-%dT%H:%M:%S')
        nrandom = param_get(parameters, 'nrandom', default=None)
        if nrandom:
            nrandom = int(nrandom)

        limit = request.args.get('limit', default=None)
        select = request.args.get('select', default=select)
        select = request.args.get('sort', default=select)

        # Resolve all reasonable protocols when doing metalink for maximum access possibilities
        if metalink and schemes is None:
            schemes = SUPPORTED_PROTOCOLS

        content_type = 'application/metalink4+xml' if metalink else 'application/x-json-stream'

        try:
            def _list_and_sort_replicas(request_id, issuer, vo):
                # we need to call list_replicas before starting to reply
                # otherwise the exceptions won't be propagated correctly
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
                                           nrandom=nrandom,
                                           updated_after=updated_after,
                                           issuer=issuer,
                                           vo=vo):

                    # Sort rfile['pfns'] and limit its size according to "limit" parameter
                    lanreplicas = {}
                    wanreplicas = {}
                    for pfn, replica in rfile['pfns'].items():
                        replica_tuple = (replica['domain'], replica['priority'], replica['rse'], replica['client_extract'])
                        if replica_tuple[0] == 'lan':
                            lanreplicas[pfn] = replica_tuple
                        else:
                            wanreplicas[pfn] = replica_tuple

                    rfile['pfns'] = dict(_sorted_with_priorities(replicas=rfile['pfns'],
                                                                 # Lan replicas sorted by priority; followed by wan replicas sorted by selection criteria
                                                                 sorted_pfns=chain(sorted(lanreplicas.keys(), key=lambda pfn: lanreplicas[pfn][1]),
                                                                                   sort_replicas(wanreplicas, client_location, selection=select)),
                                                                 limit=limit))
                    yield rfile

            rfiles = _list_and_sort_replicas(request_id=request.environ.get('request_id'),
                                             issuer=request.environ.get('issuer'),
                                             vo=request.environ.get('vo'))
            if metalink:
                policy_schema = config_get('policy', 'schema', raise_exception=False, default='generic')
                response_generator = _generate_metalink_response(rfiles, policy_schema)
            else:
                response_generator = _generate_json_response(rfiles)
            return try_stream(response_generator, content_type=content_type)
        except InvalidObject as error:
            return generate_http_error_flask(400, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)


class ReplicasDIDs(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """
        ---
        summary: List Replicas Dids
        description: List the DIDs associated to a list of replicas.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - rse
                properties:
                  pfns:
                    description: The list of pfns.
                    type: array
                    items:
                      type: string
                  rse:
                    description: The RSE name.
                    type: string
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: object
                    additionalProperties:
                      x-additionalPropertiesName: mapped PFNs to DIDs
                      description: A mapping from a pfn to a did.
                      type: object
                      properties:
                        scope:
                          description: The scope of the DID.
                          type: str
                        name:
                          description: The name of the DID.
                          type: str
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        parameters = json_parameters()
        pfns = param_get(parameters, 'pfns', default=[])
        rse = param_get(parameters, 'rse')

        try:
            def generate(vo):
                for pfn in get_did_from_pfns(pfns, rse, vo=vo):
                    yield dumps(pfn) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)


class BadReplicas(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self):
        """
        ---
        summary: Declare Bad Replicas
        description: Declares a list of bad replicas.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  replicas:
                    description: The list of pfns or list of dicts with "scope", "name", "rse_id"/"rse"
                    type: array
                    items:
                      type: string
                  pfns:
                    deprecated: true
                    description: The list of pfns, for backward compatibility with older versions of the ReplicaClient
                    type: array
                    items:
                      type: string
                  reason:
                    description: The reason for the declaration.
                    type: string
                  force:
                    description: If true, ignore existing replica status in the bad_replicas table.
                    type: boolean
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  description: Returns the not declared files.
                  type: array
          400:
            description: Can not decode json parameter list.
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        parameters = json_parameters()
        replicas = param_get(parameters, 'replicas', default=[]) or param_get(parameters, 'pfns', default=[])
        reason = param_get(parameters, 'reason', default=None)
        force = param_get(parameters, 'force', default=False)

        try:
            not_declared_files = declare_bad_file_replicas(replicas, reason=reason,
                                                           issuer=request.environ.get('issuer'), vo=request.environ.get('vo'),
                                                           force=force)
            return not_declared_files, 201
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (RSENotFound, ReplicaNotFound) as error:
            return generate_http_error_flask(404, error)


class QuarantineReplicas(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Quarantine replicas
        description: Quarantine replicas.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                    - replicas
                properties:
                  replicas:
                    description: replicas
                    type: array
                    items:
                      type: object
                      required:
                        - path
                      properties:
                            path:
                                description: path
                                type:   string
                            scope:
                                description: scope
                                type:   string
                            name:
                                description: name
                                type:   string
                  rse:
                    description: RSE name
                    type: string
                  rse_id:
                    description: RSE id
                    type: string
        responses:
          200:
            description: OK
          403:
            description: Forbidden.
          404:
            description: Not found
        """

        parameters = json_parameters()
        replicas = param_get(parameters, 'replicas', default=[])
        rse = param_get(parameters, 'rse', default=None)
        rse_id = param_get(parameters, 'rse_id', default=None)
        vo = request.environ.get('vo')
        issuer = request.environ.get('issuer')

        if replicas:
            try:
                quarantine_file_replicas(replicas, issuer, rse=rse, rse_id=rse_id, vo=vo)
            except AccessDenied as error:
                return generate_http_error_flask(403, error)
            except (RSENotFound, ReplicaNotFound) as error:
                return generate_http_error_flask(404, error)

        return '', 200


class SuspiciousReplicas(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self):
        """
        ---
        summary: Declare Suspicious Replicas
        description: Declare a list of suspicious replicas.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  pfns:
                    description: The list of pfns.
                    type: array
                    items:
                      type: string
                  reason:
                    description: The reason for the declaration.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  description: Returns the not declared files.
                  type: array
          400:
            description: Can not decode json parameter list.
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        parameters = json_parameters(parse_response)
        pfns = param_get(parameters, 'pfns', default=[])
        reason = param_get(parameters, 'reason', default=None)

        try:
            not_declared_files = declare_suspicious_file_replicas(pfns=pfns, reason=reason, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            return not_declared_files, 201
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        ---
        summary: List Suspicious Replicas
        description: List the suspicious replicas on a list of RSEs.
        tags:
          - Replicas
        parameters:
        - name: rse_expression
          in: query
          description: The RSE expression to filter for.
          schema:
            type: string
        - name: younger_than
          in: query
          description: Date to filter for.
          schema:
            type: string
        - name: nattempts
          in: query
          description: The maximum number of attempts to make.
          schema:
            type: integer
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      scope:
                        description: The scope of the Replica.
                        type: string
                      name:
                        description: The name of the Replica.
                        type: string
                      rse:
                        description: The rse name.
                        type: string
                      rse_id:
                        description: The id of the rse.
                        type: string
                      cnt:
                        description: The number of replicas.
                        type: integer
                      created_at:
                        description: The time when the replica was created.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        rse_expression, younger_than, nattempts = None, None, None
        if request.query_string:
            query_string = request.query_string.decode(encoding='utf-8')
            try:
                params = loads(unquote(query_string))
            except ValueError:
                params = parse_qs(query_string)

            if 'rse_expression' in params:
                rse_expression = params['rse_expression'][0]
            if 'younger_than' in params and params['younger_than'][0]:
                younger_than = datetime.strptime(params['younger_than'][0], "%Y-%m-%dT%H:%M:%S")
            if 'nattempts' in params:
                nattempts = int(params['nattempts'][0])

        result = get_suspicious_files(rse_expression=rse_expression, younger_than=younger_than, nattempts=nattempts, vo=request.environ.get('vo'))
        return Response(render_json_list(result), 200, content_type='application/json')


class BadReplicasStates(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: List Bad Replicas By States
        description: List the bad or suspicious replicas by states.
        tags:
          - Replicas
        parameters:
        - name: state
          in: query
          description: The state of the file.
          schema:
            type: string
            enum: [SUSPICIOUS, BAD]
        - name: rse
          in: query
          description: The rse name.
          schema:
            type: string
        - name: younger_than
          in: query
          description: Date to select bad replicas younger than this date.
          schema:
            type: string
            format: date-time
        - name: older_than
          in: query
          description: Date to select bad replicas older than this date.
          schema:
            type: string
            format: date-time
        - name: limit
          in: query
          description: The maximum number of replicas returned.
          schema:
            type: integer
        - name: list_pfns
          in: query
          description: Flag to include pfns.
          schema:
            type: boolean
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of all result replicas.
                  type: array
                  items:
                    oneof:
                      - type: object
                        properties:
                          scope:
                            description: The scope fo the replica.
                            type: string
                          name:
                            description: The name of the replica.
                            type: string
                          type:
                            description: The type of the replica.
                            type: string
                      - type: object
                        properties:
                          scope:
                            description: The scope fo the replica.
                            type: string
                          name:
                            description: The name of the replica.
                            type: string
                          rse:
                            description: The name of the associated rse.
                            type: string
                          rse_id:
                            description: The id of the associated rse.
                            type: string
                          state:
                            description: The state of the replica.
                            type: string
                          created_at:
                            description: The date-time the replica was created.
                            type: string
                            format: date-time
                          updated_at:
                            description: The date-time the replica was updated.
                            type: string
                            format: date-time
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
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
            if isinstance(state, str):
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

        def generate(vo):
            for row in list_bad_replicas_status(state=state, rse=rse, younger_than=younger_than,
                                                older_than=older_than, limit=limit, list_pfns=list_pfns,
                                                vo=vo):
                yield dumps(row, cls=APIEncoder) + '\n'

        return try_stream(generate(vo=request.environ.get('vo')))


class BadReplicasSummary(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: Bad Replicas Summary
        description: Return a summary of the bad replicas by incident.
        tags:
          - Replicas
        parameters:
        - name: rse_expression
          in: query
          description: The RSE expression.
          schema:
            type: string
        - name: from_date
          in: query
          description: The start date.
          schema:
            type: string
            format: date-time
        - name: to_date
          in: query
          description: The end date.
          schema:
            type: string
            format: date-time
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of summaries.
                  type: array
                  items:
                    type: object
                    properties:
                      rse:
                        description: The name of the associated RSE.
                        type: string
                      rse_id:
                        description: The id of the associated RSE.
                        type: string
                      created_at:
                        description: The creation date-time.
                        type: string
                        format: date-time
                      reason:
                        description: The reason for the incident.
                        type: string
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
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

        def generate(vo):
            for row in get_bad_replicas_summary(rse_expression=rse_expression, from_date=from_date,
                                                to_date=to_date, vo=vo):
                yield dumps(row, cls=APIEncoder) + '\n'

        return try_stream(generate(vo=request.environ.get('vo')))


class DatasetReplicas(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: List Dataset Replicas
        description: List dataset replicas.
        tags:
          - Replicas
        parameters:
        - name: scope_name
          in: path
          description: data identifier (scope)/(name).
          schema:
            type: string
          style: simple
        - name: deep
          in: query
          description: Flag to ennable lookup at the file level.
          schema:
            type: boolean
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of dataset replicas.
                  type: array
                  items:
                    type: object
                    properties:
                      scope:
                        description: The scope of the replica.
                        type: string
                      name:
                        description: The name of the replica.
                        type: string
                      rse:
                        description: The name of the associated RSE.
                        type: string
                      rse_id:
                        description: The id of the associated RSE.
                        type: string
                      bytes:
                        description: The size of the replica.
                        type: integer
                      length:
                        description: The length of the replica.
                        type: integer
                      available_bytes:
                        description: The number of available bytes of the replica.
                        type: integer
                      available_length:
                        description: The available length of the replica.
                        type: integer
                      state:
                        description: The state of the replica.
                        type: string
                      created_at:
                        description: The date-time the replica was created.
                        type: string
                        format: date-time
                      updated_at:
                        description: The date-time the replica was updated.
                        type: string
                        format: date-time
                      accessed_at:
                        description: The date-time the replica was accessed.
                        type: string
                        format: date-time
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(_deep, vo):
                for row in list_dataset_replicas(scope=scope, name=name, deep=_deep, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            deep = request.args.get('deep', default=False)

            return try_stream(generate(_deep=deep, vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)


class DatasetReplicasBulk(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """
        ---
        summary: List Dataset Replicas for Multiple DIDs
        description: List dataset replicas for multiple dids.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - dids
                properties:
                  dids:
                    description: A list of dids.
                    type: array
                    items:
                      description: A did.
                      type: object
                      properties:
                        scope:
                          description: The scope of the did.
                          type: string
                        name:
                          description: The name of the did.
                          type: string
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of dataset replicas.
                  type: array
                  items:
                    type: object
                    properties:
                      scope:
                        description: The scope of the replica.
                        type: string
                      name:
                        description: The name of the replica.
                        type: string
                      rse:
                        description: The name of the associated RSE.
                        type: string
                      rse_id:
                        description: The id of the associated RSE.
                        type: string
                      bytes:
                        description: The size of the replica.
                        type: integer
                      length:
                        description: The length of the replica.
                        type: integer
                      available_bytes:
                        description: The number of available bytes of the replica.
                        type: integer
                      available_length:
                        description: The available length of the replica.
                        type: integer
                      state:
                        description: The state of the replica.
                        type: string
                      created_at:
                        description: The date-time the replica was created.
                        type: string
                        format: date-time
                      updated_at:
                        description: The date-time the replica was updated.
                        type: string
                        format: date-time
                      accessed_at:
                        description: The date-time the replica was accessed.
                        type: string
                        format: date-time
          400:
            description: Bad Request.
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        parameters = json_parameters(parse_response)
        dids = param_get(parameters, 'dids')
        if len(dids) == 0:
            return generate_http_error_flask(400, ValueError.__name__, 'List of DIDs is empty')

        try:
            def generate(vo):
                for row in list_dataset_replicas_bulk(dids=dids, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except InvalidObject as error:
            return generate_http_error_flask(400, error, f'Cannot validate DIDs: {error}')


class DatasetReplicasVP(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: List Dataset Replicas VP
        description: |
          List dataset replicas using the Virtual Placement service.
          This is an RnD function and might change or go away at any time.
        tags:
          - Replicas
        parameters:
        - name: scope_name
          in: path
          description: data identifier (scope)/(name).
          schema:
            type: string
          style: simple
        - name: deep
          in: query
          description: Flag to ennable lookup at the file level.
          schema:
            type: boolean
        responses:
          200:
            description: OK. This needs documentation!
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(_deep, vo):
                for row in list_dataset_replicas_vp(scope=scope, name=name, deep=_deep, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            deep = request.args.get('deep', default=False)

            return try_stream(generate(_deep=deep, vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)


class ReplicasRSE(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rse):
        """
        ---
        summary: List Dataset Replicas per RSE
        description: List dataset replicas per RSE.
        tags:
          - Replicas
        parameters:
        - name: rse
          in: path
          description: The rse to filter for.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of dataset replicas.
                  type: array
                  items:
                    type: object
                    properties:
                      scope:
                        description: The scope of the replica.
                        type: string
                      name:
                        description: The name of the replica.
                        type: string
                      rse:
                        description: The name of the associated RSE.
                        type: string
                      rse_id:
                        description: The id of the associated RSE.
                        type: string
                      bytes:
                        description: The size of the replica.
                        type: integer
                      length:
                        description: The length of the replica.
                        type: integer
                      available_bytes:
                        description: The number of available bytes of the replica.
                        type: integer
                      available_length:
                        description: The available length of the replica.
                        type: integer
                      state:
                        description: The state of the replica.
                        type: string
                      created_at:
                        description: The date-time the replica was created.
                        type: string
                        format: date-time
                      updated_at:
                        description: The date-time the replica was updated.
                        type: string
                        format: date-time
                      accessed_at:
                        description: The date-time the replica was accessed.
                        type: string
                        format: date-time
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
        """

        def generate(vo):
            for row in list_datasets_per_rse(rse=rse, vo=vo):
                yield dumps(row, cls=APIEncoder) + '\n'

        return try_stream(generate(vo=request.environ.get('vo')))


class BadDIDs(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Mark Bad by DID
        description: Declare a list of bad replicas by DID.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  expires_at:
                    description: The expires at value.
                    type: string
                    format: date-time
                  dids:
                    description: The list of dids associated with the bad replicas.
                    type: array
                    items:
                      type: object
                      properties:
                        scope:
                          description: The scope of the did.
                          type: string
                        name:
                          description: The name of the did.
                          type: string
                  rse:
                    description: The name of the rse.
                    type: string
                  reason:
                    description: The reason for the change.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  description: All files not declared as bad.
                  type: array
                  items:
                    type: string
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Not found
        """
        parameters = json_parameters(parse_response)
        expires_at = param_get(parameters, 'expires_at', default=None)
        if expires_at:
            expires_at = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S.%f")

        try:
            not_declared_files = add_bad_dids(
                dids=param_get(parameters, 'dids', default=[]),
                rse=param_get(parameters, 'rse', default=None),
                issuer=request.environ.get('issuer'),
                state=BadFilesStatus.BAD,
                reason=param_get(parameters, 'reason', default=None),
                expires_at=expires_at,
                vo=request.environ.get('vo'),
            )
        except (ValueError, InvalidType) as error:
            return generate_http_error_flask(400, ValueError.__name__, error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return Response(dumps(not_declared_files), status=201, content_type='application/json')


class BadPFNs(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Declare Bad PFNs
        description: Declare a list of bad PFNs.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  expires_at:
                    description: The expires at value. Only apply to TEMPORARY_UNAVAILABLE.
                    type: string
                    format: date-time
                  pfns:
                    description: The list of pfns associated with the bad PFNs.
                    type: array
                    items:
                      type: string
                  state:
                    description: The state to set the PFNs to.
                    type: string
                    enum: ["BAD", "SUSPICIOUS", "TEMPORARY_UNAVAILABLE"]
                  reason:
                    description: The reason for the change.
                    type: string
        responses:
          201:
            description: Created
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Replica not found
          409:
            description: Duplicate
        """
        parameters = json_parameters(parse_response)
        expires_at = param_get(parameters, 'expires_at', default=None)
        if expires_at:
            expires_at = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S.%f")

        try:
            add_bad_pfns(
                pfns=param_get(parameters, 'pfns', default=[]),
                issuer=request.environ.get('issuer'),
                state=param_get(parameters, 'state', default=None),
                reason=param_get(parameters, 'reason', default=None),
                expires_at=expires_at,
                vo=request.environ.get('vo'),
            )
        except (ValueError, InvalidType) as error:
            return generate_http_error_flask(400, ValueError.__name__, error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return 'Created', 201


class Tombstone(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Set Tombstone
        description: Set a tombstone on a list of replicas.
        tags:
          - Replicas
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  replicas:
                    description: The replicas to set the tombstone to.
                    type: array
                    items:
                      type: object
                      required:
                        - rse
                        - scope
                        - name
                      properties:
                        rse:
                          description: The rse associated with the tombstone.
                          type: string
                        scope:
                          description: The scope of the replica
                          type: string
                        name:
                          description: The name of the replica.
                          type: string
        responses:
          201:
            description: Created
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          423:
            description: Replica is locked.
        """
        parameters = json_parameters(parse_response)
        replicas = param_get(parameters, 'replicas', default=[])

        try:
            for replica in replicas:
                set_tombstone(
                    rse=replica['rse'],
                    scope=replica['scope'],
                    name=replica['name'],
                    issuer=request.environ.get('issuer'),
                    vo=request.environ.get('vo'),
                )
        except ReplicaNotFound as error:
            return generate_http_error_flask(404, error)
        except ReplicaIsLocked as error:
            return generate_http_error_flask(423, error)

        return 'Created', 201


def blueprint(with_doc=False):
    bp = Blueprint('replicas', __name__, url_prefix='/replicas')

    list_replicas_view = ListReplicas.as_view('list_replicas')
    bp.add_url_rule('/list', view_func=list_replicas_view, methods=['post', ])
    replicas_view = Replicas.as_view('replicas')
    if not with_doc:
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('', view_func=replicas_view, methods=['post', 'put', 'delete'])
    bp.add_url_rule('/', view_func=replicas_view, methods=['post', 'put', 'delete'])
    suspicious_replicas_view = SuspiciousReplicas.as_view('suspicious_replicas')
    bp.add_url_rule('/suspicious', view_func=suspicious_replicas_view, methods=['get', 'post'])
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

    quarantine_replicas_view = QuarantineReplicas.as_view('quarantine_replicas')
    bp.add_url_rule('/quarantine', view_func=quarantine_replicas_view, methods=['post', ])

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

    if not with_doc:
        bp.add_url_rule('/list/', view_func=list_replicas_view, methods=['post', ])
        bp.add_url_rule('/suspicious/', view_func=suspicious_replicas_view, methods=['get', 'post'])
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
        bp.add_url_rule('/quarantine/', view_func=quarantine_replicas_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
