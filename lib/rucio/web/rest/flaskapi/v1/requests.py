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

import json
from typing import TYPE_CHECKING, Union, cast

import flask
from flask import Flask, Response

from rucio.common.constants import HTTPMethod, TransferLimitDirection
from rucio.common.exception import AccessDenied, RequestNotFound
from rucio.common.utils import APIEncoder, render_json
from rucio.core.rse import get_rses_with_attribute_value
from rucio.db.sqla.constants import RequestState
from rucio.gateway import request
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, json_parameters, param_get, parse_scope_name, response_headers, try_stream

if TYPE_CHECKING:
    from collections.abc import Iterator


class RequestGet(ErrorHandlingMethodView):
    """ REST API to get requests. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope_name, rse):
        """
        ---
        summary: Get Request
        description: "Get a request for a given DID to a destination RSE."
        tags:
          - Requests
        parameters:
        - name: scope_name
          in: path
          description: "Data identifier (scope)/(name)."
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: "Destination rse."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  description: "The request associated with the DID and destination RSE."
                  type: object
                  properties:
                    id:
                      description: "The id of the request."
                      type: string
                    request_type:
                      description: "The request type."
                      $ref: "#/components/schemas/RequestType"
                    scope:
                      description: "The scope of the transfer."
                      type: string
                    name:
                      description: "The name of the transfer."
                      type: string
                    did_type:
                      description: "The DID type."
                      type: string
                    dest_rse_id:
                      description: "The destination RSE id."
                      type: string
                    source_rse_id:
                      description: "The source RSE id."
                      type: string
                    attributes:
                      description: "All attributes associated with the request."
                      type: string
                    state:
                      description: "The state of the request."
                      $ref: "#/components/schemas/RequestState"
                    external_id:
                      description: "External id of the request."
                      type: string
                    external_host:
                      description: "External host of the request."
                      type: string
                    retry_count:
                      description: "The numbers of attempted retries."
                      type: integer
                    err_msg:
                      description: "An error message if one occurred."
                      type: string
                    previous_attempt_id:
                      description: "The id of the previous attempt."
                      type: string
                    rule_id:
                      description: "The id of the associated replication rule."
                      type: string
                    activity:
                      description: "The activity of the request."
                      type: string
                    bytes:
                      description: "The size of the DID in bytes."
                      type: integer
                    md5:
                      description: "The md5 checksum of the DID to transfer."
                      type: string
                    adler32:
                      description: "The adler32 checksum of the DID to transfer."
                      type: string
                    dest_url:
                      description: "The destination url."
                      type: string
                    submitted_at:
                      description: "The time the request got submitted."
                      type: string
                    started_at:
                      description: "The time the request got started."
                      type: string
                    transferred_at:
                      description: "The time the request got transferred."
                      type: string
                    estimated_at:
                      description: "The time the request got estimated."
                      type: string
                    submitter_id:
                      description: "The id of the submitter."
                      type: string
                    estimated_stated_at:
                      description: "The estimation of the started at value."
                      type: string
                    estimated_transferred_at:
                      description: "The estimation of the transferred at value."
                      type: string
                    staging_started_at:
                      description: "The time the staging got started."
                      type: string
                    staging_finished_at:
                      description: "The time the staging got finished."
                      type: string
                    account:
                      description: "The account which issued the request."
                      type: string
                    requested_at:
                      description: "The time the request got requested."
                      type: string
                    priority:
                      description: "The priority of the request."
                      type: integer
                    transfertool:
                      description: "The transfertool used."
                      type: string
                    source_rse:
                      description: "The name of the source RSE."
                      type: string
                    dest_rse:
                      description: "The name of the destination RSE."
                      type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, flask.request.environ['vo'])
        except ValueError as error:
            return generate_http_error_flask(400, error)

        try:
            request_data = request.get_request_by_did(
                scope=scope,
                name=name,
                rse=rse,
                issuer=flask.request.environ['issuer'],
                vo=flask.request.environ['vo'],
            )
            return Response(json.dumps(request_data, cls=APIEncoder), content_type='application/json')
        except RequestNotFound as error:
            return generate_http_error_flask(404, error.__class__.__name__, f'No request found for DID {scope}:{name} at RSE {rse}')


class RequestHistoryGet(ErrorHandlingMethodView):
    """ REST API to get historical requests. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope_name, rse):
        """
        ---
        summary: Get Historical Request
        description: "List a historical request for a given DID to a destination RSE."
        tags:
          - Requests
        parameters:
        - name: scope_name
          in: path
          description: "Data identifier (scope)/(name)."
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: "Destination rse."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  description: "The request associated with the DID and destination RSE."
                  type: object
                  properties:
                    id:
                      description: "The id of the request."
                      type: string
                    request_type:
                      description: "The request type."
                      $ref: "#/components/schemas/RequestType"
                    scope:
                      description: "The scope of the transfer."
                      type: string
                    name:
                      description: "The name of the transfer."
                      type: string
                    did_type:
                      description: "The DID type."
                      type: string
                    dest_rse_id:
                      description: "The destination RSE id."
                      type: string
                    source_rse_id:
                      description: "The source RSE id."
                      type: string
                    attributes:
                      description: "All attributes associated with the request."
                      type: string
                    state:
                      description: "The state of the request."
                      $ref: "#/components/schemas/RequestState"
                    external_id:
                      description: "External id of the request."
                      type: string
                    external_host:
                      description: "External host of the request."
                      type: string
                    retry_count:
                      description: "The numbers of attempted retries."
                      type: integer
                    err_msg:
                      description: "An error message if one occurred."
                      type: string
                    previous_attempt_id:
                      description: "The id of the previous attempt."
                      type: string
                    rule_id:
                      description: "The id of the associated replication rule."
                      type: string
                    activity:
                      description: "The activity of the request."
                      type: string
                    bytes:
                      description: "The size of the DID in bytes."
                      type: integer
                    md5:
                      description: "The md5 checksum of the DID to transfer."
                      type: string
                    adler32:
                      description: "The adler32 checksum of the DID to transfer."
                      type: string
                    dest_url:
                      description: "The destination url."
                      type: string
                    submitted_at:
                      description: "The time the request got submitted."
                      type: string
                    started_at:
                      description: "The time the request got started."
                      type: string
                    transferred_at:
                      description: "The time the request got transferred."
                      type: string
                    estimated_at:
                      description: "The time the request got estimated."
                      type: string
                    submitter_id:
                      description: "The id of the submitter."
                      type: string
                    estimated_stated_at:
                      description: "The estimation of the started at value."
                      type: string
                    estimated_transferred_at:
                      description: "The estimation of the transferred at value."
                      type: string
                    staging_started_at:
                      description: "The time the staging got started."
                      type: string
                    staging_finished_at:
                      description: "The time the staging got finished."
                      type: string
                    account:
                      description: "The account which issued the request."
                      type: string
                    requested_at:
                      description: "The time the request got requested."
                      type: string
                    priority:
                      description: "The priority of the request."
                      type: integer
                    transfertool:
                      description: "The transfertool used."
                      type: string
                    source_rse:
                      description: "The name of the source RSE."
                      type: string
                    dest_rse:
                      description: "The name of the destination RSE."
                      type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, flask.request.environ['vo'])
        except ValueError as error:
            return generate_http_error_flask(400, error)

        try:
            request_data = request.get_request_history_by_did(
                scope=scope,
                name=name,
                rse=rse,
                issuer=flask.request.environ['issuer'],
                vo=flask.request.environ['vo'],
            )
            return Response(json.dumps(request_data, cls=APIEncoder), content_type='application/json')
        except RequestNotFound as error:
            return generate_http_error_flask(404, error.__class__.__name__, f'No request found for DID {scope}:{name} at RSE {rse}')


class RequestList(ErrorHandlingMethodView):
    """ REST API to get requests. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: List Requests
        description: "List requests for a given source and destination RSE or site."
        tags:
          - Requests
        parameters:
        - name: src_rse
          in: query
          description: "The source rse."
          schema:
            type: array
            items:
              type: object
              required:
                - rse_id
              properties:
                rse_id:
                  description: "The id of the rse."
                  type: string
        - name: dest_rse
          in: query
          description: "The destination rse."
          schema:
            type: array
            items:
              type: object
              required:
                - rse_id
              properties:
                rse_id:
                  description: "The id of the rse."
                  type: string
        - name: src_site
          in: query
          description: "The source site."
          schema:
            type: string
        - name: dest_site
          in: query
          description: "The destination site."
          schema:
            type: string
        - name: request_states
          in: query
          description: "The accepted request states. Delimited by comma."
          schema:
            type: string
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "All requests matching the arguments. Separated by the new line character."
                  type: array
                  items:
                    description: "A request."
                    type: object
                    properties:
                      id:
                        description: "The id of the request."
                        type: string
                      request_type:
                        description: "The request type."
                        $ref: "#/components/schemas/RequestType"
                      scope:
                        description: "The scope of the transfer."
                        type: string
                      name:
                        description: "The name of the transfer."
                        type: string
                      did_type:
                        description: "The DID type."
                        type: string
                      dest_rse_id:
                        description: "The destination RSE id."
                        type: string
                      source_rse_id:
                        description: "The source RSE id."
                        type: string
                      attributes:
                        description: "All attributes associated with the request."
                        type: string
                      state:
                        description: "The state of the request."
                        $ref: "#/components/schemas/RequestState"
                      external_id:
                        description: "External id of the request."
                        type: string
                      external_host:
                        description: "External host of the request."
                        type: string
                      retry_count:
                        description: "The numbers of attempted retries."
                        type: integer
                      err_msg:
                        description: "An error message if one occurred."
                        type: string
                      previous_attempt_id:
                        description: "The id of the previous attempt."
                        type: string
                      rule_id:
                        description: "The id of the associated replication rule."
                        type: string
                      activity:
                        description: "The activity of the request."
                        type: string
                      bytes:
                        description: "The size of the DID in bytes."
                        type: integer
                      md5:
                        description: "The md5 checksum of the DID to transfer."
                        type: string
                      adler32:
                        description: "The adler32 checksum of the DID to transfer."
                        type: string
                      dest_url:
                        description: "The destination url."
                        type: string
                      submitted_at:
                        description: "The time the request got submitted."
                        type: string
                      started_at:
                        description: "The time the request got started."
                        type: string
                      transferred_at:
                        description: "The time the request got transferred."
                        type: string
                      estimated_at:
                        description: "The time the request got estimated."
                        type: string
                      submitter_id:
                        description: "The id of the submitter."
                        type: string
                      estimated_stated_at:
                        description: "The estimation of the started at value."
                        type: string
                      estimated_transferred_at:
                        description: "The estimation of the transferred at value."
                        type: string
                      staging_started_at:
                        description: "The time the staging got started."
                        type: string
                      staging_finished_at:
                        description: "The time the staging got finished."
                        type: string
                      account:
                        description: "The account which issued the request."
                        type: string
                      requested_at:
                        description: "The time the request got requested."
                        type: string
                      priority:
                        description: "The priority of the request."
                        type: integer
                      transfertool:
                        description: "The transfertool used."
                        type: string
                      source_rse:
                        description: "The name of the source RSE."
                        type: string
                      dest_rse:
                        description: "The name of the destination RSE."
                        type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          406:
            description: "Not acceptable"
        """
        src_rse = flask.request.args.get('src_rse', default=None)
        dst_rse = flask.request.args.get('dst_rse', default=None)
        src_site = flask.request.args.get('src_site', default=None)
        dst_site = flask.request.args.get('dst_site', default=None)
        request_states = flask.request.args.get('request_states', default=None)

        if not request_states:
            return generate_http_error_flask(400, 'MissingParameter', 'Request state is missing')
        if src_rse and not dst_rse:
            return generate_http_error_flask(400, 'MissingParameter', 'Destination RSE is missing')
        elif dst_rse and not src_rse:
            return generate_http_error_flask(400, 'MissingParameter', 'Source RSE is missing')
        elif src_site and not dst_site:
            return generate_http_error_flask(400, 'MissingParameter', 'Destination site is missing')
        elif dst_site and not src_site:
            return generate_http_error_flask(400, 'MissingParameter', 'Source site is missing')

        try:
            states = [RequestState(state) for state in request_states.split(',')]
        except ValueError:
            return generate_http_error_flask(400, 'Invalid', 'Request state value is invalid')

        src_rses = []
        dst_rses = []
        if src_site:
            src_rses = get_rses_with_attribute_value(key='site', value=src_site, vo=flask.request.environ['vo'])
            if not src_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {src_site} to RSE')
            src_rses = [rse['rse_name'] for rse in src_rses]
            dst_rses = get_rses_with_attribute_value(key='site', value=dst_site, vo=flask.request.environ['vo'])
            if not dst_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {dst_site} to RSE')
            dst_rses = [rse['rse_name'] for rse in dst_rses]
        else:
            dst_rses = [dst_rse]
            src_rses = [src_rse]

        # Manual cast to list[str] as static code analysis erroneously sees these as list[Optional[str]]
        src_rses = cast("list[str]", src_rses)
        dst_rses = cast("list[str]", dst_rses)

        def generate(issuer, vo):
            for result in request.list_requests(src_rses, dst_rses, states, issuer=issuer, vo=vo):
                yield render_json(**result) + '\n'

        return try_stream(generate(issuer=flask.request.environ['issuer'], vo=flask.request.environ['vo']))


class RequestHistoryList(ErrorHandlingMethodView):
    """ REST API to get requests. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: List Historic Requests
        description: "List historical requests for a given source and destination RSE or site."
        tags:
          - Requests
        parameters:
        - name: src_rse
          in: query
          description: "The source rse."
          schema:
            type: array
            items:
              type: object
              required:
                - rse_id
              properties:
                rse_id:
                  description: "The id of the rse."
                  type: string
        - name: dest_rse
          in: query
          description: "The destination rse."
          schema:
            type: array
            items:
              type: object
              required:
                - rse_id
              properties:
                rse_id:
                  description: "The id of the rse."
                  type: string
        - name: src_site
          in: query
          description: "The source site."
          schema:
            type: string
        - name: dest_site
          in: query
          description: "The destination site."
          schema:
            type: string
        - name: request_states
          in: query
          description: "The accepted request states. Delimited by comma."
          schema:
            type: string
        - name: offset
          in: query
          description: "The offset of the list."
          schema:
            type: integer
            default: 0
        - name: limit
          in: query
          description: "The maximum number of items to return."
          schema:
            type: integer
            default: 100
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "All requests matching the arguments. Separated by a new line character."
                  type: array
                  items:
                    description: "A request."
                    type: object
                    properties:
                      id:
                        description: "The id of the request."
                        type: string
                      request_type:
                        description: "The request type."
                        $ref: "#/components/schemas/RequestType"
                      scope:
                        description: "The scope of the transfer."
                        type: string
                      name:
                        description: "The name of the transfer."
                        type: string
                      did_type:
                        description: "The DID type."
                        type: string
                      dest_rse_id:
                        description: "The destination RSE id."
                        type: string
                      source_rse_id:
                        description: "The source RSE id."
                        type: string
                      attributes:
                        description: "All attributes associated with the request."
                        type: string
                      state:
                        description: "The state of the request."
                        $ref: "#/components/schemas/RequestState"
                      external_id:
                        description: "External id of the request."
                        type: string
                      external_host:
                        description: "External host of the request."
                        type: string
                      retry_count:
                        description: "The numbers of attempted retries."
                        type: integer
                      err_msg:
                        description: "An error message if one occurred."
                        type: string
                      previous_attempt_id:
                        description: "The id of the previous attempt."
                        type: string
                      rule_id:
                        description: "The id of the associated replication rule."
                        type: string
                      activity:
                        description: "The activity of the request."
                        type: string
                      bytes:
                        description: "The size of the DID in bytes."
                        type: integer
                      md5:
                        description: "The md5 checksum of the DID to transfer."
                        type: string
                      adler32:
                        description: "The adler32 checksum of the DID to transfer."
                        type: string
                      dest_url:
                        description: "The destination url."
                        type: string
                      submitted_at:
                        description: "The time the request got submitted."
                        type: string
                      started_at:
                        description: "The time the request got started."
                        type: string
                      transferred_at:
                        description: "The time the request got transferred."
                        type: string
                      estimated_at:
                        description: "The time the request got estimated."
                        type: string
                      submitter_id:
                        description: "The id of the submitter."
                        type: string
                      estimated_stated_at:
                        description: "The estimation of the started at value."
                        type: string
                      estimated_transferred_at:
                        description: "The estimation of the transferred at value."
                        type: string
                      staging_started_at:
                        description: "The time the staging got started."
                        type: string
                      staging_finished_at:
                        description: "The time the staging got finished."
                        type: string
                      account:
                        description: "The account which issued the request."
                        type: string
                      requested_at:
                        description: "The time the request got requested."
                        type: string
                      priority:
                        description: "The priority of the request."
                        type: integer
                      transfertool:
                        description: "The transfertool used."
                        type: string
                      source_rse:
                        description: "The name of the source RSE."
                        type: string
                      dest_rse:
                        description: "The name of the destination RSE."
                        type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "Not found"
          406:
            description: "Not acceptable"
        """
        src_rse = flask.request.args.get('src_rse', default=None)
        dst_rse = flask.request.args.get('dst_rse', default=None)
        src_site = flask.request.args.get('src_site', default=None)
        dst_site = flask.request.args.get('dst_site', default=None)
        request_states = flask.request.args.get('request_states', default=None)
        offset = flask.request.args.get('offset', type=int, default=0)
        limit = flask.request.args.get('limit', type=int, default=100)

        if not request_states:
            return generate_http_error_flask(400, 'MissingParameter', 'Request state is missing')
        if src_rse and not dst_rse:
            return generate_http_error_flask(400, 'MissingParameter', 'Destination RSE is missing')
        elif dst_rse and not src_rse:
            return generate_http_error_flask(400, 'MissingParameter', 'Source RSE is missing')
        elif src_site and not dst_site:
            return generate_http_error_flask(400, 'MissingParameter', 'Destination site is missing')
        elif dst_site and not src_site:
            return generate_http_error_flask(400, 'MissingParameter', 'Source site is missing')

        try:
            states = [RequestState(state) for state in request_states.split(',')]
        except ValueError:
            return generate_http_error_flask(400, 'Invalid', 'Request state value is invalid')

        src_rses = []
        dst_rses = []
        if src_site:
            src_rses = get_rses_with_attribute_value(key='site', value=src_site, vo=flask.request.environ['vo'])
            if not src_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {src_site} to RSE')
            src_rses = [rse['rse_name'] for rse in src_rses]
            dst_rses = get_rses_with_attribute_value(key='site', value=dst_site, vo=flask.request.environ['vo'])
            if not dst_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {dst_site} to RSE')
            dst_rses = [rse['rse_name'] for rse in dst_rses]
        else:
            dst_rses = [dst_rse]
            src_rses = [src_rse]

        # Manual cast to list[str] as static code analysis erroneously sees these as list[Optional[str]]
        src_rses = cast("list[str]", src_rses)
        dst_rses = cast("list[str]", dst_rses)

        def generate(issuer, vo):
            for result in request.list_requests_history(src_rses, dst_rses, states, issuer=issuer, vo=vo, offset=offset, limit=limit):
                yield render_json(**result) + '\n'

        return try_stream(generate(issuer=flask.request.environ['issuer'], vo=flask.request.environ['vo']))


class RequestMetricsGet(ErrorHandlingMethodView):
    """ REST API to get request stats. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: Get Request Statistics
        description: "Get statistics of requests grouped by source, destination, and activity."
        tags:
          - Requests
        parameters:
        - name: dest_rse
          in: query
          description: "The destination RSE name"
          schema:
            type: string
        - name: source_rse
          in: query
          description: "The source RSE name"
          schema:
            type: string
        - name: activity
          in: query
          description: "The activity"
          schema:
            type: string
        - name: group_by_rse_attribute
          in: query
          description: "The parameter to group the RSEs by."
          schema:
            type: string
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "Statistics of requests by source, destination, and activity."
                  type: array
                  items:
                    description: "Statistics of the request group for a given (source, destination, activity) tuple."
                    type: object
                    properties:
                      src_rse:
                        type: string
                        description: "The name of this links source RSE"
                      dst_rse:
                        type: string
                        description: "The name of this links destination RSE"
                      distance:
                        type: integer
                        description: "The distance between the source and destination RSE"
                      files:
                        type: object
                        properties:
                          done-total-1h:
                            type: integer
                            description: "The total number of files successfully transferred in the last 1 hour"
                          done-total-6h:
                            type: integer
                            description: "The total number of files successfully transferred in the last 6 hours"
                          failed-total-1h:
                            type: integer
                            description: "The total number of transfer failures in the last 1 hour"
                          failed-total-6h:
                            type: integer
                            description: "The total number of transfer failures in the last 6 hours"
                          queued-total:
                            type: integer
                            description: "The total number of files queued in rucio"
                          queued:
                            type: object
                            description: "Per-activity number of queued files"
                            additionalProperties:
                              type: integer
                          done:
                            type: object
                            additionalProperties:
                              type: object
                              properties:
                                1h:
                                  type: integer
                                6h:
                                  type: integer
                          failed:
                            type: object
                            description: "Per-activity number of transfer failures in the last 1 and 6 hours"
                            additionalProperties:
                              type: object
                              properties:
                                1h:
                                  type: integer
                                6h:
                                  type: integer
                      bytes:
                        type: object
                        properties:
                          done-total-1h:
                            type: integer
                            description: "The total number of bytes successfully transferred in the last 1 hour"
                          done-total-6h:
                            type: integer
                            description: "The total number of bytes successfully transferred in the last 6 hours"
                          queued-total:
                            type: integer
                            description: "The total number of bytes queued to be transferred by rucio"
                          queued:
                            type: object
                            description: "Per-activity amount of queued bytes"
                            additionalProperties:
                              type: integer
                          done:
                            type: object
                            description: "Per-activity number of transferred bytes in the last 1 and 6 hours"
                            additionalProperties:
                              type: object
                              properties:
                                1h:
                                  type: integer
                                6h:
                                  type: integer
                    required:
                      - distance
                      - src_rse
                      - dst_rse
          401:
            description: "Invalid Auth Token"
        """
        dst_rse = flask.request.args.get('dst_rse', default=None)
        src_rse = flask.request.args.get('src_rse', default=None)
        activity = flask.request.args.get('activity', default=None)
        group_by_rse_attribute = flask.request.args.get('group_by_rse_attribute', default=None)
        format = flask.request.args.get('format', default=None)

        metrics = request.get_request_metrics(
            dst_rse=dst_rse,
            src_rse=src_rse,
            activity=activity,
            group_by_rse_attribute=group_by_rse_attribute,
            issuer=flask.request.environ['issuer'],
            vo=flask.request.environ['vo']
        )

        if format == 'panda':
            return Response(json.dumps(metrics, cls=APIEncoder), content_type='application/json')

        def generate() -> "Iterator[str]":
            for result in metrics.values():
                yield render_json(**result) + '\n'
        return try_stream(generate())


class TransferLimits(ErrorHandlingMethodView):
    """ REST API to get, set or delete transfer limits. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self) -> flask.Response:
        """
        ---
        summary: Get Transfer Limits
        description: "Get all the transfer limits."
        tags:
          - Requests
        responses:
          200:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  description: "All the transfer limits"
                  type: array
                  items:
                    type: object
                    properties:
                      id:
                        description: "The transfer limit id."
                        type: string
                      rse_expression:
                        description: "The RSE expression for which the limit applies."
                        type: string
                      direction:
                        description: "The direction in which this limit applies (source/destination)"
                        type: string
                      max_transfers:
                        description: "Maximum number of transfers allowed."
                        type: integer
                      volume:
                        description: "Maximum transfer volume in bytes."
                        type: integer
                      deadline:
                        description: "Maximum waiting time in hours until a dataset gets released."
                        type: integer
                      strategy:
                        description: "Defines how to handle datasets: `fifo` (each file released separately) or `grouped_fifo` (wait for the entire dataset to fit)"
                        type: string
                      transfers:
                        description: "Current number of active transfers"
                        type: integer
                      waitings:
                        description: "Current number of waiting transfers"
                        type: integer
                      updated_at:
                        description: "Datetime of the last update."
                        type: string
                      created_at:
                        description: "Datetime of the creation of the transfer limit."
                        type: string
          401:
            description: "Invalid Auth Token"
        """
        transfer_limits = request.list_transfer_limits(issuer=flask.request.environ['issuer'], vo=flask.request.environ['vo'])

        def generate() -> "Iterator[str]":
            for limit in transfer_limits:
                yield json.dumps(limit, cls=APIEncoder) + '\n'
        return try_stream(generate())

    def put(self) -> Union[flask.Response, tuple[str, int]]:
        """
        ---
        summary: Set Transfer Limit
        description: "Create or update a transfer limit for a specific RSE expression and activity."
        tags:
          - Requests
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                  - rse_expression
                  - max_transfers
                properties:
                  rse_expression:
                    type: string
                    description: "The RSE expression for which the transfer limit is being set."
                  activity:
                    type: string
                    description: "The activity to which the transfer limit applies."
                  max_transfers:
                    type: integer
                    description: "The maximum number of transfers allowed."
                  direction:
                    type: string
                    description: "The direction of the transfer limit (source or destination)."
                    enum: ["SOURCE", "DESTINATION"]
                    default: "DESTINATION"
                  volume:
                    type: integer
                    description: "The maximum transfer volume in bytes."
                  deadline:
                    type: integer
                    description: "The maximum waiting time in hours until a dataset is released."
                  strategy:
                    type: string
                    description: "The strategy for handling datasets (e.g., `fifo` or `grouped_fifo`)."
                  transfers:
                    type: integer
                    description: "The current number of active transfers."
                  waitings:
                    type: integer
                    description: "The current number of waiting transfers."
        responses:
          201:
            description: "Transfer limit set successfully."
          400:
            description: "Invalid input data."
          401:
            description: "Invalid Auth Token."
          500:
            description: "Internal server error."
        """
        parameters = json_parameters()
        rse_expression = param_get(parameters, 'rse_expression')
        max_transfers = param_get(parameters, 'max_transfers')

        try:
            request.set_transfer_limit(
                rse_expression=rse_expression,
                max_transfers=max_transfers,
                activity=param_get(parameters, 'activity', default=None),
                direction=param_get(parameters, 'direction', default=TransferLimitDirection.DESTINATION),
                volume=param_get(parameters, 'volume', default=None),
                deadline=param_get(parameters, 'deadline', default=None),
                strategy=param_get(parameters, 'strategy', default=None),
                transfers=param_get(parameters, 'transfers', default=None),
                waitings=param_get(parameters, 'waitings', default=None),
                issuer=flask.request.environ['issuer'],
                vo=flask.request.environ['vo']
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return '', 201

    def delete(self) -> Union[flask.Response, tuple[str, int]]:
        """
        ---
        summary: Delete Transfer Limit
        description: "Delete a transfer limit for an RSE expression."
        tags:
          - Requests
        parameters:
          - name: rse_expression
            in: query
            description: "The RSE expression to delete the limit for."
            required: true
            schema:
              type: string
        responses:
          200:
            description: "Transfer limit deleted successfully."
          400:
            description: "Invalid input data."
          401:
            description: "Invalid Auth Token."
          500:
            description: "Internal server error."
        """
        parameters = json_parameters()
        rse_expression = param_get(parameters, 'rse_expression')

        try:
            request.delete_transfer_limit(
                rse_expression=rse_expression,
                activity=param_get(parameters, 'activity', default=None),
                direction=param_get(parameters, 'direction', default=TransferLimitDirection.DESTINATION),
                issuer=flask.request.environ['issuer'],
                vo=flask.request.environ['vo']
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        return '', 200


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint('requests', __name__, url_prefix='/requests')

    request_get_view = RequestGet.as_view('request_get')
    bp.add_url_rule('/<path:scope_name>/<rse>', view_func=request_get_view, methods=[HTTPMethod.GET.value])
    request_history_get_view = RequestHistoryGet.as_view('request_history_get')
    bp.add_url_rule('/history/<path:scope_name>/<rse>', view_func=request_history_get_view, methods=[HTTPMethod.GET.value])
    request_list_view = RequestList.as_view('request_list')
    bp.add_url_rule('/list', view_func=request_list_view, methods=[HTTPMethod.GET.value])
    request_history_list_view = RequestHistoryList.as_view('request_history_list')
    bp.add_url_rule('/history/list', view_func=request_history_list_view, methods=[HTTPMethod.GET.value])
    request_metrics_view = RequestMetricsGet.as_view('request_metrics_get')
    bp.add_url_rule('/metrics', view_func=request_metrics_view, methods=[HTTPMethod.GET.value])
    transfer_limits_view = TransferLimits.as_view('transfer_limits_get')
    bp.add_url_rule('/transfer_limits', view_func=transfer_limits_view, methods=[HTTPMethod.GET.value, HTTPMethod.PUT.value, HTTPMethod.DELETE.value])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
