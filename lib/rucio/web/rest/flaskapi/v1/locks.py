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

from flask import Flask, Blueprint, request

from rucio.api.lock import get_dataset_locks_by_rse, get_dataset_locks, get_dataset_locks_bulk
from rucio.common.exception import RSENotFound
from rucio.common.utils import render_json
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream, \
    request_auth_env, response_headers, generate_http_error_flask, ErrorHandlingMethodView, json_parse


class LockByRSE(ErrorHandlingMethodView):
    """ REST APIs for dataset locks. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rse):
        """
        ---
        summary: Get locks by rse
        description: Get all dataset locks for an associated rse.
        tags:
          - Lock
        parameters:
        - name: rse
          in: path
          description: The rse name.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  did_type:
                    description: The did type to filter for.
                    type: string
                    enum: ['dataset']
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: Locks associated with the rse.
                  type: array
                  items:
                    description: A lock
                    type: object
                    properties:
                      rse_id:
                        description: The id of the associated rse.
                        type: string
                      rse:
                        description: The name of the associated rse.
                        type: string
                      scope:
                        description: The scope of the associated rse.
                        type: string
                      name:
                        description: The name of the rule.
                        type: string
                      rule_id:
                        description: The id of the rule.
                        type: string
                      account:
                        description: The associated account.
                        type: string
                      state:
                        description: The state of the rule.
                        type: string
                        enum: ['R', 'O', 'S']
                      length:
                        description: The length of the rule.
                        type: integer
                      bytes:
                        description: The bytes limit for the lock.
                        type: integere
                      accessed_at:
                        description: The last time is was accessed.
                        type: string
          401:
            description: Invalid Auth Token
          500:
            description: Wrong did type
            content:
              application/json:
                schema:
                  type: string
                  enum: ['wrong did_type specified']
          406:
            description: Not acceptable
        """
        did_type = request.args.get('did_type', default=None)
        if did_type != 'dataset':
            return 'Wrong did_type specified', 500

        try:
            def generate(vo):
                for lock in get_dataset_locks_by_rse(rse, vo=vo):
                    yield render_json(**lock) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except RSENotFound as error:
            return generate_http_error_flask(404, error)


class LocksByScopeName(ErrorHandlingMethodView):
    """ REST APIs for dataset locks. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get locks by scope
        description: Get all dataset locks for an associated rse.
        tags:
          - Lock
        parameters:
        - name: scope_name
          in: path
          description: The scope name.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  did_type:
                    description: The did type to filter for.
                    type: string
                    enum: ['dataset']
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: Locks associated with the rse.
                  type: array
                  items:
                    description: A lock
                    type: object
                    properties:
                      rse_id:
                        description: The id of the associated rse.
                        type: string
                      rse:
                        description: The name of the associated rse.
                        type: string
                      scope:
                        description: The scope of the associated rse.
                        type: string
                      name:
                        description: The name of the rule.
                        type: string
                      rule_id:
                        description: The id of the rule.
                        type: string
                      account:
                        description: The associated account.
                        type: string
                      state:
                        description: The state of the rule.
                        type: string
                        enum: ['R', 'O', 'S']
                      length:
                        description: The length of the rule.
                        type: integer
                      bytes:
                        description: The bytes limit for the lock.
                        type: integere
                      accessed_at:
                        description: The last time is was accessed.
                        type: string
          401:
            description: Invalid Auth Token
          500:
            description: Wrong did type
            content:
              application/json:
                schema:
                  type: string
                  enum: ['wrong did_type specified']
          406:
            description: Not acceptable
        """
        did_type = request.args.get('did_type', default=None)
        if did_type != 'dataset':
            return 'Wrong did_type specified', 500

        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for lock in get_dataset_locks(scope, name, vo=vo):
                    yield render_json(**lock) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)


class DatasetLocksForDids(ErrorHandlingMethodView):
    """ REST APIs for multiple dataset locks. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def post(self):
        """ get locks for a given scope, name.

        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 400: Wrong DID type.
        :returns: Line separated list of dictionary with lock information.
        ---
        summary: Get locks by dids
        description: Get all dataset locks for the associated dids.
        tags:
          - Lock
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  dids:
                    description: The dids associated with the locks.
                    type: array
                    items:
                      type: object
                      description: A did
                      required:
                        - scope
                        - name
                      properties:
                        scope:
                          description: The scope of the did.
                          type: string
                        name:
                          description: The name of the did.
                          type: string
                        type:
                          description: The type of the did.
                          type: string
                          enum: ['dataset', 'container']
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: Locks associated with the rse.
                  type: array
                  items:
                    description: A lock
                    type: object
                    properties:
                      rse_id:
                        description: The id of the associated rse.
                        type: string
                      rse:
                        description: The name of the associated rse.
                        type: string
                      scope:
                        description: The scope of the associated rse.
                        type: string
                      name:
                        description: The name of the rule.
                        type: string
                      rule_id:
                        description: The id of the rule.
                        type: string
                      account:
                        description: The associated account.
                        type: string
                      state:
                        description: The state of the rule.
                        type: string
                        enum: ['R', 'O', 'S']
                      length:
                        description: The length of the rule.
                        type: integer
                      bytes:
                        description: The bytes limit for the lock.
                        type: integere
                      accessed_at:
                        description: The last time is was accessed.
                        type: string
          401:
            description: Invalid Auth Token
          400:
            description: Wrong did type
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Can not find the list of DIDs in the data. Use "dids" keyword.']
          406:
            description: Not acceptable

        """

        data = json_parse(types=(dict,))
        try:
            dids = data["dids"]
        except KeyError:
            return 'Can not find the list of DIDs in the data. Use "dids" keyword.', 400
        vo = request.environ.get('vo')
        try:
            locks = get_dataset_locks_bulk(dids, vo)        # removes duplicates

            def generate(locks):
                for lock in locks:
                    lock["scope"] = str(lock["scope"])
                    yield render_json(**lock) + '\n'
            return try_stream(generate(locks))

        except ValueError as error:
            return generate_http_error_flask(400, error)


def blueprint():
    bp = Blueprint('locks', __name__, url_prefix='/locks')

    lock_by_rse_view = LockByRSE.as_view('lock_by_rse')
    bp.add_url_rule('/<rse>', view_func=lock_by_rse_view, methods=['get', ])

    lock_by_scope_name_view = LocksByScopeName.as_view('locks_by_scope_name')
    bp.add_url_rule('/<path:scope_name>', view_func=lock_by_scope_name_view, methods=['get', ])

    locks_for_dids_view = DatasetLocksForDids.as_view('locks_for_dids')
    bp.add_url_rule('/bulk_locks_for_dids', view_func=locks_for_dids_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
