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

from flask import Flask, Response, jsonify, request

from rucio.common.constants import HTTPMethod
from rucio.gateway.identity import add_account_identity, add_identity, list_accounts_for_identity
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, response_headers


class UserPass(ErrorHandlingMethodView):
    """ Manage a username/password identity for an account. """

    def put(self, account):
        """
        ---
        summary: Create UserPass identity
        description: "Creates a new UserPass identity and maps it to an account."
        tags:
          - Identity
        parameters:
        - name: account
          in: path
          description: "The account for the identity."
          schema:
            type: string
          style: simple
        - name: X-Rucio-Username
          in: query
          description: "Username for the identity."
          schema:
            type: string
          style: simple
          required: true
        - name: X-Rucio-Password
          in: query
          description: "The password for the identity."
          schema:
            type: string
          style: simple
          required: true
        - name: X-Rucio-Email
          in: query
          description: "The email for the identity."
          schema:
            type: string
          style: simple
          required: false
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: "Invalid Auth Token"
          400:
            description: "Missing username or password."
        """
        username = request.headers.get('X-Rucio-Username', default=None)
        password = request.headers.get('X-Rucio-Password', default=None)
        email = request.headers.get('X-Rucio-Email', default=None)

        if not username or not password or not email:
            return generate_http_error_flask(400, ValueError.__name__, 'Username, Email and Password must be set.')

        issuer = request.environ.get('issuer')
        vo = request.environ.get('vo')

        if not issuer or not vo:
            return generate_http_error_flask(400, ValueError.__name__, 'Issuer and VO must be set.')

        add_identity(username, 'userpass', email, password)

        add_account_identity(
            identity_key=username,
            id_type='userpass',
            account=account,
            email=email,
            password=password,
            issuer=issuer,
            vo=vo,
        )

        return 'Created', 201


class X509(ErrorHandlingMethodView):
    """ Manage an x509 identity for an account. """

    def put(self, account):
        """
        ---
        summary: Create X509 identity
        description: "Creates a new X509 identity and maps it to an account."
        tags:
          - Identity
        parameters:
        - name: account
          in: path
          description: "The account for the identity."
          schema:
            type: string
          style: simple
        - name: X-Rucio-Email
          in: query
          description: "The email for the identity."
          schema:
            type: string
          style: simple
          required: false
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: "Invalid Auth Token"
        """
        dn = request.environ.get('SSL_CLIENT_S_DN')
        email = request.headers.get('X-Rucio-Email', default=None)

        if not dn or not email:
            return generate_http_error_flask(400, ValueError.__name__, 'SSL_CLIENT_S_DN and email must be set.')

        issuer = request.environ.get('issuer')
        vo = request.environ.get('vo')

        if not issuer or not vo:
            return generate_http_error_flask(400, ValueError.__name__, 'Issuer and VO must be set.')

        add_identity(dn, 'x509', email=email)
        add_account_identity(
            identity_key=dn,
            id_type='x509',
            account=account,
            email=email,
            issuer=issuer,
            vo=vo,
        )

        return 'Created', 201


class GSS(ErrorHandlingMethodView):
    """ Manage a GSS identity for an account. """

    def put(self, account):
        """
        ---
        summary: Create GSS identity
        description: "Creates a new GSS identity and maps it to an account."
        tags:
          - Identity
        parameters:
        - name: account
          in: path
          description: "The account for the identity."
          schema:
            type: string
          style: simple
        - name: X-Rucio-Email
          in: query
          description: "The email for the identity."
          schema:
            type: string
          style: simple
          required: false
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: "Invalid Auth Token"
        """
        gsscred = request.environ.get('REMOTE_USER')
        email = request.headers.get('X-Rucio-Email', default=None)

        if not gsscred or not email:
            return generate_http_error_flask(400, ValueError.__name__, 'REMOTE_USER and email must be set.')

        issuer = request.environ.get('issuer')
        vo = request.environ.get('vo')

        if not issuer or not vo:
            return generate_http_error_flask(400, ValueError.__name__, 'Issuer and VO must be set.')

        add_identity(gsscred, 'gss', email=email)
        add_account_identity(
            identity_key=gsscred,
            id_type='gss',
            account=account,
            email=email,
            issuer=issuer,
            vo=vo,
        )

        return 'Created', 201


class Accounts(ErrorHandlingMethodView):
    """ Retrieve list of accounts mapped to an identity. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, identity_key, type_):
        """
        ---
        summary: List
        description: "List all identities mapped to an account."
        tags:
          - Identity
        parameters:
        - name: identity_key
          in: path
          description: "Identity string."
          schema:
            type: string
          style: simple
        - name: type
          in: path
          description: "Identity type."
          schema:
            type: string
          style: simple
          required: false
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    description: "Account for the identity."
          401:
            description: "Invalid Auth Token"
          401:
            description: "Not acceptable"
        """
        accounts = list_accounts_for_identity(identity_key, type_)
        return jsonify(accounts)


class AccountsByIdentity(ErrorHandlingMethodView):
    """ Retrieve list of accounts mapped to an identity using query parameters. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self) -> Response:
        """
        ---
        summary: List accounts by identity
        description: "List all accounts mapped to an identity using query parameters. This endpoint supports identity keys containing special characters like slashes."
        tags:
          - Identity
        parameters:
        - name: identity_key
          in: query
          description: "Identity string. For OIDC identities, use format: SUB=<sub>, ISS=<issuer_url>"
          schema:
            type: string
          required: true
        - name: type
          in: query
          description: "Identity type (e.g., OIDC, X509, USERPASS, GSS)."
          schema:
            type: string
          required: true
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    description: "Account for the identity."
          400:
            description: "Missing required parameter"
          401:
            description: "Invalid Auth Token"
          406:
            description: "Not acceptable"
        """
        identity_key = request.args.get('identity_key')
        type_ = request.args.get('type')

        if not identity_key:
            return generate_http_error_flask(400, ValueError.__name__, 'identity_key parameter is required.')

        if not type_:
            return generate_http_error_flask(400, ValueError.__name__, 'type parameter is required.')

        accounts = list_accounts_for_identity(identity_key, type_)
        return jsonify(accounts)


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint('identities', __name__, url_prefix='/identities')

    userpass_view = UserPass.as_view('userpass')
    bp.add_url_rule('/<account>/userpass', view_func=userpass_view, methods=[HTTPMethod.PUT.value])
    x509_view = X509.as_view('x509')
    bp.add_url_rule('/<account>/x509', view_func=x509_view, methods=[HTTPMethod.PUT.value])
    gss_view = GSS.as_view('gss')
    bp.add_url_rule('/<account>/gss', view_func=gss_view, methods=[HTTPMethod.PUT.value])
    accounts_view = Accounts.as_view('accounts')
    bp.add_url_rule('/<identity_key>/<type>/accounts', view_func=accounts_view, methods=[HTTPMethod.GET.value])
    accounts_by_identity_view = AccountsByIdentity.as_view('accounts_by_identity')
    bp.add_url_rule('/accounts', view_func=accounts_by_identity_view, methods=[HTTPMethod.GET.value])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
