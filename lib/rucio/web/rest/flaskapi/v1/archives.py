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

from json import dumps

from flask import Flask, Blueprint, request

from rucio.api.did import list_archive_content
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    parse_scope_name, try_stream, generate_http_error_flask, ErrorHandlingMethodView


class Archive(ErrorHandlingMethodView):
    """ REST APIs for archive. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: List
        description: List archive contents.
        tags:
          - Archive
        parameters:
        - name: scope_name
          in: path
          description: The data identifier of the scope.
          schema:
            type: string
          style: simple
        responses:
          201:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      scope:
                        description: The scope of the did.
                        type: str
                      name:
                        description: The name of the did.
                        type: str
                      bytes:
                        description: The number of bytes.
                        type: int
                      adler32:
                        description: The adler32 checksum.
                        type: str
                      md5:
                        description: The md5 checksum.
                        type: str
          400:
            description: Invalid value
          406:
            description: Not acceptable
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for file in list_archive_content(scope=scope, name=name, vo=vo):
                    yield dumps(file) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)


def blueprint():
    bp = Blueprint('archives', __name__, url_prefix='/archives')

    archive_view = Archive.as_view('archive')
    bp.add_url_rule('/<path:scope_name>/files', view_func=archive_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
