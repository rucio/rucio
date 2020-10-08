# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from traceback import format_exc

from flask import Flask, Blueprint, request, jsonify
from flask.views import MethodView

from rucio.api.scope import add_scope, list_scopes, get_scopes
from rucio.common.exception import AccountNotFound, Duplicate, RucioException
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask


class Scope(MethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """List all scopes.

        .. :quickref: Scopes; Get all scopes.

        **Example request**:

        .. sourcecode:: http

            GET /posts/ HTTP/1.1
            Host: rucio.com

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/json

            ["RSE1", "RSE2", "RSE3", "RSE4", "RSE5"]

        :resheader Content-Type: application/json
        :status 200: scopes found
        :status 406: Not Acceptable
        :returns: :class:`String`
        """
        return jsonify(list_scopes(vo=request.environ.get('vo')))

    def post(self, account, scope):
        """Add a new scope.

        .. :quickref: Scopes; Add a new scope.

        :resheader Location: post url
        :status 201: scope created
        :status 404: account does not exist
        :status 401: unauthorized
        :status 409: scope already exists
        :status 500: internal server error
        """
        try:
            add_scope(scope, account, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return 'Created', 201


class AccountScopeList(MethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, account):
        """List account scopes.

        .. :quickref: Scopes; Get scopes for account.

        :resheader Content-Type: application/json
        :status 200: Scopes found
        :status 404: Account not found
        :status 404: No scopes for this account
        :status 406: Not Acceptable
        :returns: A list containing all scope names for an account.
        """
        try:
            scopes = get_scopes(account, vo=request.environ.get('vo'))
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        if not len(scopes):
            return generate_http_error_flask(404, 'ScopeNotFound', 'no scopes found for account ID \'%s\'' % account)

        return jsonify(scopes)


def blueprint():
    bp = Blueprint('scope', __name__, url_prefix='/scopes')

    scope_view = Scope.as_view('scope')
    bp.add_url_rule('/', view_func=scope_view, methods=['get', ])
    bp.add_url_rule('/<account>/<scope>', view_func=scope_view, methods=['post', ])
    account_scope_list_view = AccountScopeList.as_view('account_scope_list')
    bp.add_url_rule('/<account>/scopes', view_func=account_scope_list_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
