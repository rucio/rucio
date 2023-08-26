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
from json import dumps

from flask import Flask, Response, request, redirect, jsonify

from rucio.api.account import add_account, del_account, get_account_info, list_accounts, list_identities, \
    list_account_attributes, add_account_attribute, del_account_attribute, update_account, get_usage_history
from rucio.api.account_limit import get_local_account_limits, get_local_account_limit, get_local_account_usage, \
    get_global_account_limit, get_global_account_limits, get_global_account_usage
from rucio.api.identity import add_account_identity, del_account_identity
from rucio.api.rule import list_replication_rules
from rucio.api.scope import add_scope, get_scopes
from rucio.common.exception import AccountNotFound, Duplicate, AccessDenied, RuleNotFound, RSENotFound, \
    IdentityError, CounterNotFound, ScopeNotFound, InvalidObject
from rucio.common.utils import APIEncoder, render_json
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import response_headers, check_accept_header_wrapper_flask, \
    try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class Attributes(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, account):
        """
        ---
        summary: List attributes
        description: List all attributes for an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
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
          404:
            description: No account found for the given id.
          406:
            description: Not acceptable.
        """
        try:
            attribs = list_account_attributes(account, vo=request.environ.get('vo'))
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)

        return jsonify(attribs)

    def post(self, account, key):
        """
        ---
        summary: Create attribute
        description: Create an attribute to an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        - name: key
          in: path
          description: The key of the account attribute.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - value
                properties:
                  key:
                    description: The key of the attribute. This would override the key defined in path.
                    type: string
                  value:
                    description: The value of the attribute.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: No account found for the given id.
          409:
            description: Attribute already exists
        """
        parameters = json_parameters()
        value = param_get(parameters, 'value')
        try:
            add_account_attribute(key=key, value=value, account=account, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201

    def delete(self, account, key):
        """
        ---
        summary: Delete attribute
        description: Delete an attribute of an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        - name: key
          in: path
          description: The key of the account attribute to remove.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: No account found for the given id.
        """
        try:
            del_account_attribute(account=account, key=key, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200


class Scopes(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, account):
        """
        ---
        summary: List scopes
        description: List all scopse for an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: All scopes for the account.
                  type: array
                  items:
                    description: A scope
                    type: string
          401:
            description: Invalid Auth Token
          404:
            description: No account or scope found for the given id.
          406:
            description: Not acceptable
        """
        try:
            scopes = get_scopes(account, vo=request.environ.get('vo'))
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)

        if not len(scopes):
            return generate_http_error_flask(404, ScopeNotFound.__name__, f"no scopes found for account ID '{account}'")

        return jsonify(scopes)

    def post(self, account, scope):
        """
        ---
        summary: Create scope
        description: Creates a scopse with the given name for an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        - name: scope
          in: path
          description: The scope name.
          schema:
            type: string
          style: simple
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          400:
            description: Not acceptable
          401:
            description: Invalid Auth Token
          404:
            description: No account found.
          409:
            description: Scope already exists.
        """
        try:
            add_scope(scope, account, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except InvalidObject as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201


class AccountParameter(ErrorHandlingMethodView):
    """ create, update, get and disable rucio accounts. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, account):
        """
        ---
        summary: List account parameters
        description: Lists all parameters for an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    account:
                      description: The account identifier.
                      type: string
                    account_type:
                      description: The account type.
                      type: string
                    status:
                      description: The account status.
                      type: string
                    email:
                      description: The email for the account.
                      type: string
                    suspended_at:
                      description: Datetime if the account was suspended.
                      type: string
                    deleted_at:
                      description: Datetime if the account was deleted.
                      type: string
          401:
            description: Invalid Auth Token
          404:
            description: No account found.
          406:
            description: Not acceptable
        """
        if account == 'whoami':
            # Redirect to the account uri
            frontend = request.headers.get('X-Requested-Host', default=None)
            if frontend:
                return redirect(f'{frontend}/accounts/{request.environ.get("issuer")}', code=302)
            return redirect(request.environ.get('issuer'), code=303)

        try:
            acc = get_account_info(account, vo=request.environ.get('vo'))
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        accdict = acc.to_dict()

        for key, value in accdict.items():
            if isinstance(value, datetime):
                accdict[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        return Response(render_json(**accdict), content_type="application/json")

    def put(self, account):
        """
        ---
        summary: Update
        description: Update a parameter for an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                description: Json object with key-value pairs corresponding to the new values of the parameters.
                type: object
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: No account found.
          400:
            description: Unknown status
        """
        parameters = json_parameters()
        for key, value in parameters.items():
            try:
                update_account(account, key=key, value=value, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            except ValueError:
                return generate_http_error_flask(400, ValueError.__name__, f'Unknown value {value}')
            except AccessDenied as error:
                return generate_http_error_flask(401, error)
            except AccountNotFound as error:
                return generate_http_error_flask(404, error)

        return '', 200

    def post(self, account):
        """
        ---
        summary: Create
        description: Create an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                  - type
                  - email
                properties:
                  type:
                    description: The account type.
                    type: string
                    enum: ["USER", "GROUP", "SERVICE"]
                  email:
                    description: The email for the account.
                    type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          409:
            description: Account already exists
          400:
            description: Unknown status
        """
        parameters = json_parameters()
        type_param = param_get(parameters, 'type')
        email = param_get(parameters, 'email')
        try:
            add_account(account, type_param, email, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except InvalidObject as error:
            return generate_http_error_flask(400, error)

        return 'Created', 201

    def delete(self, account):
        """
        ---
        summary: Delete
        description: Delete an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        responses:
          201:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Account not found
        """
        try:
            del_account(account, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200


class Account(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: List
        description: List all accounts.
        tags:
          - Account
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      account:
                        description: The account identifier.
                        type: string
                      type:
                        description: The type.
                        type: string
                      email:
                        description: The email.
                        type: string
          401:
            description: Invalid Auth Token
        """

        def generate(_filter, vo):
            for account in list_accounts(filter_=_filter, vo=vo):
                yield render_json(**account) + "\n"

        return try_stream(generate(_filter=dict(request.args.items(multi=False)), vo=request.environ.get('vo')))


class LocalAccountLimits(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, account, rse=None):
        """
        ---
        summary: Get local limit
        description: Get the current local limits for an account on a specific RSE.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: The rse identifier.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: Json object with rse identifiers as keys and account limits in bytes as values.
                  type: object
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found
          406:
            description: Not Acceptable
        """
        try:
            if rse:
                limits = get_local_account_limit(account=account, rse=rse, vo=request.environ.get('vo'))
            else:
                limits = get_local_account_limits(account=account, vo=request.environ.get('vo'))
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return Response(render_json(**limits), content_type="application/json")


class GlobalAccountLimits(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, account, rse_expression=None):
        """
        ---
        summary: Get gloabl limit
        description: Get the current gloabl limits for an account on a specific RSE expression.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        - name: rse_expression
          in: path
          description: The rse identifier.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: Json object with rse expression as keys and limits in bytes as values.
                  type: object
          401:
            description: Invalid Auth Token
          404:
            description: RSE not found
          406:
            description: Not Acceptable
        """
        try:
            if rse_expression:
                limits = get_global_account_limit(account=account, rse_expression=rse_expression, vo=request.environ.get('vo'))
            else:
                limits = get_global_account_limits(account=account, vo=request.environ.get('vo'))
        except RSENotFound as error:
            return generate_http_error_flask(404, error)

        return Response(render_json(**limits), content_type="application/json")


class Identities(ErrorHandlingMethodView):
    def post(self, account):
        """
        ---
        summary: Create identity
        description: Grant an account identity access to an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                  - identity
                  - authtype
                  - email
                properties:
                  identity:
                    description: The identity.
                    type: string
                  authtype:
                    description: The authtype.
                    type: string
                  email:
                    description: The email.
                    type: string
                  password:
                    description: The password.
                    type: string
                    default: none
                  default:
                    description: Should this be the default account?
                    type: string
                    default: false
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          404:
            description: Account not found
          409:
            description: Already exists
          400:
            description: Parameter missing
        """
        parameters = json_parameters()
        identity = param_get(parameters, 'identity')
        authtype = param_get(parameters, 'authtype')
        email = param_get(parameters, 'email')
        try:
            add_account_identity(
                identity_key=identity,
                id_type=authtype,
                account=account,
                email=email,
                password=param_get(parameters, 'password', default=None),
                issuer=request.environ.get('issuer'),
                default=param_get(parameters, 'default', default=False),
                vo=request.environ.get('vo'),
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)
        except IdentityError as error:
            return generate_http_error_flask(400, error)

        return 'Created', 201

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, account):
        """
        ---
        summary: List identities
        description: Lists all identities for an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: array
                    minItems: 2
                    maxItems: 2
                    items:
                      type: string
          401:
            description: Invalid Auth Token
          404:
            description: Account not found
          406:
            description: Not acceptable
        """
        try:
            def generate(vo):
                for identity in list_identities(account, vo=vo):
                    yield render_json(**identity) + "\n"

            return try_stream(generate(request.environ.get('vo')))
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)

    def delete(self, account):
        """
        ---
        summary: Delete identity
        description: Delete an account identity.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                  - identity
                  - authtype
                properties:
                  identity:
                    description: The identity.
                    type: string
                  authtype:
                    description: The authtype.
                    type: string
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Account or identity not found
        """
        parameters = json_parameters()
        identity = param_get(parameters, 'identity')
        authtype = param_get(parameters, 'authtype')
        try:
            del_account_identity(identity, authtype, account, request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (AccountNotFound, IdentityError) as error:
            return generate_http_error_flask(404, error)

        return '', 200


class Rules(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, account):
        """
        ---
        summary: List rules
        description: Lists all rules for an account.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: string
          401:
            description: Invalid Auth Token
          404:
            description: Account or rule not found
          406:
            description: Not acceptable
        """
        filters = {'account': account}
        filters.update(request.args)
        try:
            def generate(vo):
                for rule in list_replication_rules(filters=filters, vo=vo):
                    yield dumps(rule, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)


class UsageHistory(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, account, rse):
        """
        ---
        summary: Get account usage history
        description: Returns the account usage history.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: The rse identifier.
          schema:
            type: string
          style: simple
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
                      bytes:
                        description: The number of bytes used.
                        type: integer
                      files:
                        description: The files.
                        type: string
                      updated_at:
                        description: When the data was provided.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: Account not found
          406:
            description: Not acceptable
        """
        try:
            usage = get_usage_history(account=account, rse=rse, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (AccountNotFound, CounterNotFound) as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)

        for entry in usage:
            for key, value in entry.items():
                if isinstance(value, datetime):
                    entry[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        return jsonify(usage)


class LocalUsage(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, account, rse=None):
        """
        ---
        summary: Get local account usage
        description: Returns the local account usage.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        - name: rse
          in: path
          description: The rse identifier.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      rse_id:
                        description: The rse id.
                        type: string
                      bytes:
                        description: The number of bytes used.
                        type: integer
                      bytes_limit:
                        description: The maximum number of bytes.
                        type: integer
                      bytes_remaining:
                        description: The remaining number of bytes.
                        type: integer
          401:
            description: Invalid Auth Token
          404:
            description: Account or rse not found
          406:
            description: Not acceptable
        """
        try:
            def generate(issuer, vo):
                for usage in get_local_account_usage(account=account, rse=rse, issuer=issuer, vo=vo):
                    yield dumps(usage, cls=APIEncoder) + '\n'

            return try_stream(generate(issuer=request.environ.get('issuer'), vo=request.environ.get('vo')))
        except (AccountNotFound, RSENotFound) as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)


class GlobalUsage(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, account, rse_expression=None):
        """
        ---
        summary: Get local account usage
        description: Returns the local account usage.
        tags:
          - Account
        parameters:
        - name: account
          in: path
          description: The account identifier.
          schema:
            type: string
          style: simple
        - name: rse_expression
          in: path
          description: The rse expression.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      rse_expression:
                        description: The rse expression.
                        type: string
                      bytes:
                        description: The number of bytes used.
                        type: integer
                      bytes_limit:
                        description: The maximum number of bytes.
                        type: integer
                      bytes_remaining:
                        description: The remaining number of bytes.
                        type: integer
          401:
            description: Invalid Auth Token
          404:
            description: Account or rse not found
          406:
            description: Not acceptable
        """
        try:
            def generate(vo, issuer):
                for usage in get_global_account_usage(account=account, rse_expression=rse_expression, issuer=issuer, vo=vo):
                    yield dumps(usage, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo'), issuer=request.environ.get('issuer')))
        except (AccountNotFound, RSENotFound) as error:
            return generate_http_error_flask(404, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)


def blueprint(with_doc=False):
    bp = AuthenticatedBlueprint('accounts', __name__, url_prefix='/accounts')

    attributes_view = Attributes.as_view('attributes')
    bp.add_url_rule('/<account>/attr/', view_func=attributes_view, methods=['get', ])
    bp.add_url_rule('/<account>/attr/<key>', view_func=attributes_view, methods=['post', 'delete'])
    scopes_view = Scopes.as_view('scopes')
    bp.add_url_rule('/<account>/scopes/', view_func=scopes_view, methods=['get', ])
    bp.add_url_rule('/<account>/scopes/<scope>', view_func=scopes_view, methods=['post', ])
    local_account_limits_view = LocalAccountLimits.as_view('local_account_limit')
    bp.add_url_rule('/<account>/limits/local', view_func=local_account_limits_view, methods=['get', ])
    bp.add_url_rule('/<account>/limits', view_func=local_account_limits_view, methods=['get', ])
    bp.add_url_rule('/<account>/limits/local/<rse>', view_func=local_account_limits_view, methods=['get', ])
    bp.add_url_rule('/<account>/limits/<rse>', view_func=local_account_limits_view, methods=['get', ])
    global_account_limits_view = GlobalAccountLimits.as_view('global_account_limit')
    bp.add_url_rule('/<account>/limits/global', view_func=global_account_limits_view, methods=['get', ])
    bp.add_url_rule('/<account>/limits/global/<rse_expression>', view_func=global_account_limits_view, methods=['get', ])
    identities_view = Identities.as_view('identities')
    bp.add_url_rule('/<account>/identities', view_func=identities_view, methods=['get', 'post', 'delete'])
    rules_view = Rules.as_view('rules')
    bp.add_url_rule('/<account>/rules', view_func=rules_view, methods=['get', ])
    usagehistory_view = UsageHistory.as_view('usagehistory')
    bp.add_url_rule('/<account>/usage/history/<rse>', view_func=usagehistory_view, methods=['get', ])
    usage_view = LocalUsage.as_view('usage')
    bp.add_url_rule('/<account>/usage/local', view_func=usage_view, methods=['get', ])
    bp.add_url_rule('/<account>/usage', view_func=usage_view, methods=['get', ])
    if not with_doc:
        # for backwards-compatibility
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('/<account>/usage/', view_func=usage_view, methods=['get', ])
    bp.add_url_rule('/<account>/usage/local/<rse>', view_func=usage_view, methods=['get', ])
    bp.add_url_rule('/<account>/usage/<rse>', view_func=usage_view, methods=['get', ])
    global_usage_view = GlobalUsage.as_view('global_usage')
    bp.add_url_rule('/<account>/usage/global', view_func=global_usage_view, methods=['get', ])
    bp.add_url_rule('/<account>/usage/global/<rse_expression>', view_func=global_usage_view, methods=['get', ])
    account_parameter_view = AccountParameter.as_view('account_parameter')
    bp.add_url_rule('/<account>', view_func=account_parameter_view, methods=['get', 'put', 'post', 'delete'])
    account_view = Account.as_view('account')
    if not with_doc:
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('', view_func=account_view, methods=['get', ])
    bp.add_url_rule('/', view_func=account_view, methods=['get', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
