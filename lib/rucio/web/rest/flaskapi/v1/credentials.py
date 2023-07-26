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

from typing import TYPE_CHECKING

from flask import Flask, request
from werkzeug.datastructures import Headers

from rucio.api.credential import get_signed_url
from rucio.common.exception import CannotAuthenticate
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, extract_vo, \
    generate_http_error_flask, ErrorHandlingMethodView, response_headers

if TYPE_CHECKING:
    from typing import Optional
    from rucio.web.rest.flaskapi.v1.common import HeadersType


class SignURL(ErrorHandlingMethodView):
    """
    Request a signed URL.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return headers

    def options(self):
        """
        ---
        summary: Cross-Site Scripting
        description: Allow cross-site scripting. Explicit for Authentication.
        tags:
          - Credentials
        responses:
          200:
            description: OK
            headers:
              Access-Control-Allow-Origin:
                schema:
                  type: string
                description: The http origin.
              Access-Control-Allow-Headers:
                schema:
                  type: string
                description: The http access controll request headers.
              Access-Control-Allow-Methods:
                schema:
                  type: string
                  enum: ['*']
                description: The allowed methods.
              Access-Control-Allow-Credentials:
                schema:
                  type: string
                  enum: ['true']
                description: If credentials are allowed.
              Access-Control-Expose-Headers:
                schema:
                  type: string
                  enum: ['X-Rucio-Auth-Token']
                description: The exposed access controll header.
          404:
            description: Not found
        """
        return '', 200, self.get_headers()

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        ---
        summary: Sign URL
        description: Sign a url for a limited lifetime for a particular srevice.
        tags:
          - Credentials
        parameters:
        - name: rse
          in: query
          description: The RSE to authenticate against.
          schema:
            type: string
          required: true
        - name: lifetime
          in: query
          description: The lifetime, default 600s.
          schema:
            type: string
          required: false
        - name: svc
          in: query
          description: The service, default gcs.
          schema:
            type: string
          required: false
        - name: op
          in: query
          description: The operation.
          schema:
            type: string
          required: false
        - name: url
          in: query
          description: The Url of the authentification.
          schema:
            type: string
          required: true
        requestBody:
          content:
            'application/octet-stream':
              schema:
                type: object
                properties:
                  X-Rucio-Account:
                    description: Account identifier.
                    type: string
                  X-Rucio-VO:
                    description: VO name (Multi-VO only).
                    type: string
                  X-Rucio-AppID:
                    description: Application identifier.
                    type: string
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    description: An account attribute.
                    properties:
                      key:
                        description: The key of the account attribute.
                        type: string
                      value:
                        description: The value of the account attribute.
                        type: string
          401:
            description: Invalid Auth Token
          400:
            description: bad request, no rse or url found.
          406:
            description: Not acceptable.
        """
        headers = self.get_headers()
        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        if 'rse' not in request.args:
            return generate_http_error_flask(400, ValueError.__name__, 'Parameter "rse" not found', headers=headers)
        rse = request.args.get('rse')

        lifetime = request.args.get('lifetime', type=int, default=600)
        service = request.args.get('svc', default='gcs')
        operation = request.args.get('op', default='read')

        if 'url' not in request.args:
            return generate_http_error_flask(400, ValueError.__name__, 'Parameter "url" not found', headers=headers)
        url = request.args.get('url')

        if service not in ['gcs', 's3', 'swift']:
            return generate_http_error_flask(400, ValueError.__name__, 'Parameter "svc" must be either empty(=gcs), gcs, s3 or swift', headers=headers)

        if operation not in ['read', 'write', 'delete']:
            return generate_http_error_flask(400, ValueError.__name__, 'Parameter "op" must be either empty(=read), read, write, or delete.', headers=headers)

        result = get_signed_url(account, appid, ip, rse=rse, service=service, operation=operation, url=url, lifetime=lifetime, vo=vo)

        if not result:
            return generate_http_error_flask(401, CannotAuthenticate.__name__, f'Cannot generate signed URL for account {account}', headers=headers)

        return str(result), 200, headers


def blueprint(with_doc=False):
    bp = AuthenticatedBlueprint('credentials', __name__, url_prefix='/credentials')

    signurl_view = SignURL.as_view('signurl')
    bp.add_url_rule('/signurl', view_func=signurl_view, methods=['get', 'options'])
    if not with_doc:
        # yes, /signur ~= '/signurl?$'
        bp.add_url_rule('/signur', view_func=signurl_view, methods=['get', 'options'])

    bp.after_request(response_headers)

    return bp


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
