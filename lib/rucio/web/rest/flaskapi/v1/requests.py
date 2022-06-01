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

import json

import flask
from flask import Flask, Blueprint, Response

from rucio.api import request
from rucio.common.exception import RequestNotFound
from rucio.common.utils import APIEncoder, render_json
from rucio.core.rse import get_rses_with_attribute_value, get_rse_name
from rucio.db.sqla.constants import RequestState
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream, \
    request_auth_env, response_headers, generate_http_error_flask, ErrorHandlingMethodView


class RequestGet(ErrorHandlingMethodView):
    """ REST API to get requests. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope_name, rse):
        """
        ---
        summary: Get Request
        description: Get a request for a given DID to a destinaion RSE.
        tags:
          - Requests
        parameters:
        - name: scope_name
          in: path
          description: Data identifier (scope)/(name).
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: Destination rse.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The request associated with the DID and destination RSE.
                  type: object
                  properties:
                    id:
                      description: The id of the request.
                      type: strig
                    request_type:
                      description: The request type.
                      type: string
                      enum: ["T", "U", "D", "I", "O"]
                    scope:
                      description: The scope of the transfer.
                      type: string
                    name:
                      description: The name of the transfer.
                      type: string
                    did_type:
                      description: The did type.
                      type: string
                    dest_rse_id:
                      description: The destination RSE id.
                      type: string
                    source_rse_id:
                      description: The source RSE id.
                      type: string
                    attributes:
                      description: All attributes associated with the request.
                      type: string
                    state:
                      description: The state of the request.
                      type: string
                      enum: ["Q", "G", "S", "F", "D", "L", "N", "O", "A", "M", "U", "W", "P"]
                    external_id:
                      description: External id of the request.
                      type: string
                    external_host:
                      description: External host of the request.
                      type: string
                    retry_count:
                      description: The numbers of attempted retires.
                      type: integer
                    err_msg:
                      description: An error message if one occured.
                      type: string
                    previous_attempt_id:
                      description: The id of the previous attempt.
                      type: string
                    rule_id:
                      description: The id of the associated replication rule.
                      type: string
                    activity:
                      description: The activity of the request.
                      type: string
                    bytes:
                      description: The size of the did in bytes.
                      type: integer
                    md5:
                      description: The md5 checksum of the did to transfer.
                      type: string
                    adler32:
                      description: The adler32 checksum of the did to transfer.
                      type: string
                    dest_url:
                      description: The destination url.
                      type: string
                    submitted_at:
                      description: The time the request got submitted.
                      type: string
                    started_at:
                      description: The time the request got started.
                      type: string
                    transferred_at:
                      description: The time the request got transfered.
                      type: string
                    estimated_at:
                      description: The time the request got estimated.
                      type: string
                    submitter_id:
                      description: The id of the submitter.
                      type: string
                    estimated_stated_at:
                      description: The estimation of the started at value.
                      type: string
                    estimated_transferred_at:
                      description: The estimation of the transfered at value.
                      type: string
                    staging_started_at:
                      description: The time the staging got started.
                      type: string
                    staging_finished_at:
                      description: The time the staging got finished.
                      type: string
                    account:
                      description: The account which issued the request.
                      type: string
                    requested_at:
                      description: The time the request got requested.
                      type: string
                    priority:
                      description: The priority of the request.
                      type: integer
                    transfertool:
                      description: The transfertool used.
                      type: string
                    source_rse:
                      description: The name of the source RSE.
                      type: string
                    dest_rse:
                      description: The name of the destination RSE.
                      type: string
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, flask.request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        try:
            request_data = request.get_request_by_did(
                scope=scope,
                name=name,
                rse=rse,
                issuer=flask.request.environ.get('issuer'),
                vo=flask.request.environ.get('vo'),
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
        description: List a hostorical request for a given DID to a destination RSE.
        tags:
          - Requests
        parameters:
        - name: scope_name
          in: path
          description: Data identifier (scope)/(name).
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: Destination rse.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The request associated with the DID and destination RSE.
                  type: object
                  properties:
                    id:
                      description: The id of the request.
                      type: strig
                    request_type:
                      description: The request type.
                      type: string
                      enum: ["T", "U", "D", "I", "O"]
                    scope:
                      description: The scope of the transfer.
                      type: string
                    name:
                      description: The name of the transfer.
                      type: string
                    did_type:
                      description: The did type.
                      type: string
                    dest_rse_id:
                      description: The destination RSE id.
                      type: string
                    source_rse_id:
                      description: The source RSE id.
                      type: string
                    attributes:
                      description: All attributes associated with the request.
                      type: string
                    state:
                      description: The state of the request.
                      type: string
                      enum: ["Q", "G", "S", "F", "D", "L", "N", "O", "A", "M", "U", "W", "P"]
                    external_id:
                      description: External id of the request.
                      type: string
                    external_host:
                      description: External host of the request.
                      type: string
                    retry_count:
                      description: The numbers of attempted retires.
                      type: integer
                    err_msg:
                      description: An error message if one occured.
                      type: string
                    previous_attempt_id:
                      description: The id of the previous attempt.
                      type: string
                    rule_id:
                      description: The id of the associated replication rule.
                      type: string
                    activity:
                      description: The activity of the request.
                      type: string
                    bytes:
                      description: The size of the did in bytes.
                      type: integer
                    md5:
                      description: The md5 checksum of the did to transfer.
                      type: string
                    adler32:
                      description: The adler32 checksum of the did to transfer.
                      type: string
                    dest_url:
                      description: The destination url.
                      type: string
                    submitted_at:
                      description: The time the request got submitted.
                      type: string
                    started_at:
                      description: The time the request got started.
                      type: string
                    transferred_at:
                      description: The time the request got transfered.
                      type: string
                    estimated_at:
                      description: The time the request got estimated.
                      type: string
                    submitter_id:
                      description: The id of the submitter.
                      type: string
                    estimated_stated_at:
                      description: The estimation of the started at value.
                      type: string
                    estimated_transferred_at:
                      description: The estimation of the transfered at value.
                      type: string
                    staging_started_at:
                      description: The time the staging got started.
                      type: string
                    staging_finished_at:
                      description: The time the staging got finished.
                      type: string
                    account:
                      description: The account which issued the request.
                      type: string
                    requested_at:
                      description: The time the request got requested.
                      type: string
                    priority:
                      description: The priority of the request.
                      type: integer
                    transfertool:
                      description: The transfertool used.
                      type: string
                    source_rse:
                      description: The name of the source RSE.
                      type: string
                    dest_rse:
                      description: The name of the destination RSE.
                      type: string
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, flask.request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        try:
            request_data = request.get_request_history_by_did(
                scope=scope,
                name=name,
                rse=rse,
                issuer=flask.request.environ.get('issuer'),
                vo=flask.request.environ.get('vo'),
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
        summary: List Historic Requests
        description: List requests for a given source and destination RSE or site.
        tags:
          - Requests
        parameters:
        - name: src_rse
          in: query
          description: The source rse.
          schema:
            type: array
            items:
              type: object
              required:
                - rse_id
              properties:
                rse_id:
                  description: The id of the rse.
                  type: string
        - name: dest_rse
          in: query
          description: The destination rse.
          schema:
            type: array
            items:
              type: object
              required:
                - rse_id
              properties:
                rse_id:
                  description: The id of the rse.
                  type: string
        - name: src_site
          in: query
          description: The source site.
          schema:
            type: string
        - name: dest_site
          in: query
          description: The destination site.
          schema:
            type: string
        - name: request_states
          in: query
          description: The accepted request states. Delimited by comma.
          schema:
            type: string
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: All requests matching the arguments. Seperated by the new line character.
                  type: array
                  items:
                    description: A request.
                    type: object
                    properties:
                      id:
                        description: The id of the request.
                        type: strig
                      request_type:
                        description: The request type.
                        type: string
                        enum: ["T", "U", "D", "I", "O"]
                      scope:
                        description: The scope of the transfer.
                        type: string
                      name:
                        description: The name of the transfer.
                        type: string
                      did_type:
                        description: The did type.
                        type: string
                      dest_rse_id:
                        description: The destination RSE id.
                        type: string
                      source_rse_id:
                        description: The source RSE id.
                        type: string
                      attributes:
                        description: All attributes associated with the request.
                        type: string
                      state:
                        description: The state of the request.
                        type: string
                        enum: ["Q", "G", "S", "F", "D", "L", "N", "O", "A", "M", "U", "W", "P"]
                      external_id:
                        description: External id of the request.
                        type: string
                      external_host:
                        description: External host of the request.
                        type: string
                      retry_count:
                        description: The numbers of attempted retires.
                        type: integer
                      err_msg:
                        description: An error message if one occured.
                        type: string
                      previous_attempt_id:
                        description: The id of the previous attempt.
                        type: string
                      rule_id:
                        description: The id of the associated replication rule.
                        type: string
                      activity:
                        description: The activity of the request.
                        type: string
                      bytes:
                        description: The size of the did in bytes.
                        type: integer
                      md5:
                        description: The md5 checksum of the did to transfer.
                        type: string
                      adler32:
                        description: The adler32 checksum of the did to transfer.
                        type: string
                      dest_url:
                        description: The destination url.
                        type: string
                      submitted_at:
                        description: The time the request got submitted.
                        type: string
                      started_at:
                        description: The time the request got started.
                        type: string
                      transferred_at:
                        description: The time the request got transfered.
                        type: string
                      estimated_at:
                        description: The time the request got estimated.
                        type: string
                      submitter_id:
                        description: The id of the submitter.
                        type: string
                      estimated_stated_at:
                        description: The estimation of the started at value.
                        type: string
                      estimated_transferred_at:
                        description: The estimation of the transfered at value.
                        type: string
                      staging_started_at:
                        description: The time the staging got started.
                        type: string
                      staging_finished_at:
                        description: The time the staging got finished.
                        type: string
                      account:
                        description: The account which issued the request.
                        type: string
                      requested_at:
                        description: The time the request got requested.
                        type: string
                      priority:
                        description: The priority of the request.
                        type: integer
                      transfertool:
                        description: The transfertool used.
                        type: string
                      source_rse:
                        description: The name of the source RSE.
                        type: string
                      dest_rse:
                        description: The name of the destination RSE.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
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
            src_rses = get_rses_with_attribute_value(key='site', value=src_site, lookup_key='site', vo=flask.request.environ.get('vo'))
            if not src_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {src_site} to RSE')
            src_rses = [get_rse_name(rse['rse_id']) for rse in src_rses]
            dst_rses = get_rses_with_attribute_value(key='site', value=dst_site, lookup_key='site', vo=flask.request.environ.get('vo'))
            if not dst_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {dst_site} to RSE')
            dst_rses = [get_rse_name(rse['rse_id']) for rse in dst_rses]
        else:
            dst_rses = [dst_rse]
            src_rses = [src_rse]

        def generate(issuer, vo):
            for result in request.list_requests(src_rses, dst_rses, states, issuer=issuer, vo=vo):
                del result['_sa_instance_state']
                yield render_json(**result) + '\n'

        return try_stream(generate(issuer=flask.request.environ.get('issuer'), vo=flask.request.environ.get('vo')))


class RequestHistoryList(ErrorHandlingMethodView):
    """ REST API to get requests. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: List Historic Requests
        description: List historical requests for a given source and destination RSE or site.
        tags:
          - Requests
        parameters:
        - name: src_rse
          in: query
          description: The source rse.
          schema:
            type: array
            items:
              type: object
              required:
                - rse_id
              properties:
                rse_id:
                  description: The id of the rse.
                  type: string
        - name: dest_rse
          in: query
          description: The destination rse.
          schema:
            type: array
            items:
              type: object
              required:
                - rse_id
              properties:
                rse_id:
                  description: The id of the rse.
                  type: string
        - name: src_site
          in: query
          description: The source site.
          schema:
            type: string
        - name: dest_site
          in: query
          description: The destination site.
          schema:
            type: string
        - name: request_states
          in: query
          description: The accepted request states. Delimited by comma.
          schema:
            type: string
        - name: offset
          in: query
          description: The offset of the list.
          schema:
            type: integer
          default: 0
        - name: limit
          in: query
          description: The maximum number of items to return.
          schema:
            type: integer
          default: 100
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: All requests matching the arguments. Seperated by a new line character.
                  type: array
                  items:
                    description: A request.
                    type: object
                    properties:
                      id:
                        description: The id of the request.
                        type: strig
                      request_type:
                        description: The request type.
                        type: string
                        enum: ["T", "U", "D", "I", "O"]
                      scope:
                        description: The scope of the transfer.
                        type: string
                      name:
                        description: The name of the transfer.
                        type: string
                      did_type:
                        description: The did type.
                        type: string
                      dest_rse_id:
                        description: The destination RSE id.
                        type: string
                      source_rse_id:
                        description: The source RSE id.
                        type: string
                      attributes:
                        description: All attributes associated with the request.
                        type: string
                      state:
                        description: The state of the request.
                        type: string
                        enum: ["Q", "G", "S", "F", "D", "L", "N", "O", "A", "M", "U", "W", "P"]
                      external_id:
                        description: External id of the request.
                        type: string
                      external_host:
                        description: External host of the request.
                        type: string
                      retry_count:
                        description: The numbers of attempted retires.
                        type: integer
                      err_msg:
                        description: An error message if one occured.
                        type: string
                      previous_attempt_id:
                        description: The id of the previous attempt.
                        type: string
                      rule_id:
                        description: The id of the associated replication rule.
                        type: string
                      activity:
                        description: The activity of the request.
                        type: string
                      bytes:
                        description: The size of the did in bytes.
                        type: integer
                      md5:
                        description: The md5 checksum of the did to transfer.
                        type: string
                      adler32:
                        description: The adler32 checksum of the did to transfer.
                        type: string
                      dest_url:
                        description: The destination url.
                        type: string
                      submitted_at:
                        description: The time the request got submitted.
                        type: string
                      started_at:
                        description: The time the request got started.
                        type: string
                      transferred_at:
                        description: The time the request got transfered.
                        type: string
                      estimated_at:
                        description: The time the request got estimated.
                        type: string
                      submitter_id:
                        description: The id of the submitter.
                        type: string
                      estimated_stated_at:
                        description: The estimation of the started at value.
                        type: string
                      estimated_transferred_at:
                        description: The estimation of the transfered at value.
                        type: string
                      staging_started_at:
                        description: The time the staging got started.
                        type: string
                      staging_finished_at:
                        description: The time the staging got finished.
                        type: string
                      account:
                        description: The account which issued the request.
                        type: string
                      requested_at:
                        description: The time the request got requested.
                        type: string
                      priority:
                        description: The priority of the request.
                        type: integer
                      transfertool:
                        description: The transfertool used.
                        type: string
                      source_rse:
                        description: The name of the source RSE.
                        type: string
                      dest_rse:
                        description: The name of the destination RSE.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        src_rse = flask.request.args.get('src_rse', default=None)
        dst_rse = flask.request.args.get('dst_rse', default=None)
        src_site = flask.request.args.get('src_site', default=None)
        dst_site = flask.request.args.get('dst_site', default=None)
        request_states = flask.request.args.get('request_states', default=None)
        offset = flask.request.args.get('offset', default=0)
        limit = flask.request.args.get('limit', default=100)

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
            src_rses = get_rses_with_attribute_value(key='site', value=src_site, lookup_key='site', vo=flask.request.environ.get('vo'))
            if not src_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {src_site} to RSE')
            src_rses = [get_rse_name(rse['rse_id']) for rse in src_rses]
            dst_rses = get_rses_with_attribute_value(key='site', value=dst_site, lookup_key='site', vo=flask.request.environ.get('vo'))
            if not dst_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {dst_site} to RSE')
            dst_rses = [get_rse_name(rse['rse_id']) for rse in dst_rses]
        else:
            dst_rses = [dst_rse]
            src_rses = [src_rse]

        def generate(issuer, vo):
            for result in request.list_requests_history(src_rses, dst_rses, states, issuer=issuer, vo=vo, offset=offset, limit=limit):
                del result['_sa_instance_state']
                yield render_json(**result) + '\n'

        return try_stream(generate(issuer=flask.request.environ.get('issuer'), vo=flask.request.environ.get('vo')))


def blueprint():
    bp = Blueprint('requests', __name__, url_prefix='/requests')

    request_get_view = RequestGet.as_view('request_get')
    bp.add_url_rule('/<path:scope_name>/<rse>', view_func=request_get_view, methods=['get', ])
    request_history_get_view = RequestHistoryGet.as_view('request_history_get')
    bp.add_url_rule('/history/<path:scope_name>/<rse>', view_func=request_history_get_view, methods=['get', ])
    request_list_view = RequestList.as_view('request_list')
    bp.add_url_rule('/list', view_func=request_list_view, methods=['get', ])
    request_history_list_view = RequestHistoryList.as_view('request_history_list')
    bp.add_url_rule('/history/list', view_func=request_history_list_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
