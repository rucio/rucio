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

from flask import Flask, request

from rucio.api.account_limit import set_local_account_limit, delete_local_account_limit, set_global_account_limit, \
    delete_global_account_limit
from rucio.common.exception import RSENotFound, AccessDenied, AccountNotFound
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import response_headers, ErrorHandlingMethodView, \
    generate_http_error_flask, json_parameters, param_get


class LocalAccountLimit(ErrorHandlingMethodView):
    def post(self, account, rse):
        """
        ---
        summary: Create or update a local accont limit
        tags:
          - Account Limit
        parameters:
        - name: account
          in: path
          description: The account for the accountlimit.
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: The rse for the accountlimit.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - bytes
                properties:
                  bytes:
                    description: The new limit in bytes.
                    type: integer
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: Invalid Auth Token
          404:
            description: No RSE or account found for the given id.
        """
        parameters = json_parameters()
        bytes_param = param_get(parameters, 'bytes')
        try:
            set_local_account_limit(account=account, rse=rse, bytes_=bytes_param, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (RSENotFound, AccountNotFound) as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201

    def delete(self, account, rse):
        """
        ---
        summary: Delete a local account limit
        tags:
          - Account Limit
        parameters:
        - name: account
          in: path
          description: The account for the accountlimit.
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: The rse for the accountlimit.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: No RSE or account found for the given id.
        """
        try:
            delete_local_account_limit(account=account, rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (AccountNotFound, RSENotFound) as error:
            return generate_http_error_flask(404, error)

        return '', 200


class GlobalAccountLimit(ErrorHandlingMethodView):
    def post(self, account, rse_expression):
        """
        ---
        summary: Create or update a global account limit
        tags:
          - Account Limit
        parameters:
        - name: account
          in: path
          description: The account for the accountlimit.
          schema:
            type: string
          style: simple
        - name: rse_expression
          in: path
          description: The rse expression for the accountlimit.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - bytes
                properties:
                  bytes:
                    description: The new limit in bytes.
                    type: integer
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: Invalid Auth Token
          404:
            description: No RSE or account found for the given id.
        """
        parameters = json_parameters()
        bytes_param = param_get(parameters, 'bytes')
        try:
            set_global_account_limit(
                account=account,
                rse_expression=rse_expression,
                bytes_=bytes_param,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (RSENotFound, AccountNotFound) as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201

    def delete(self, account, rse_expression):
        """
        ---
        summary: Delete a global account limit
        tags:
          - Account Limit
        parameters:
        - name: account
          in: path
          description: The account for the accountlimit.
          schema:
            type: string
          style: simple
        - name: rse_expression
          in: path
          description: The rse expression for the accountlimit.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: No RSE or account found for the given id.
        """
        try:
            delete_global_account_limit(account=account, rse_expression=rse_expression, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (AccountNotFound, RSENotFound) as error:
            return generate_http_error_flask(404, error)

        return '', 200


def blueprint(with_doc=False):
    bp = AuthenticatedBlueprint('accountlimits', __name__, url_prefix='/accountlimits')

    local_account_limit_view = LocalAccountLimit.as_view('local_account_limit')
    bp.add_url_rule('/local/<account>/<rse>', view_func=local_account_limit_view, methods=['post', 'delete'])
    if not with_doc:
        bp.add_url_rule('/<account>/<rse>', view_func=local_account_limit_view, methods=['post', 'delete'])
    global_account_limit_view = GlobalAccountLimit.as_view('global_account_limit')
    bp.add_url_rule('/global/<account>/<rse_expression>', view_func=global_account_limit_view, methods=['post', 'delete'])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
