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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

from traceback import format_exc

from flask import Flask, Blueprint, request, jsonify
from flask.views import MethodView

from rucio.api.identity import add_identity, add_account_identity, list_accounts_for_identity
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask


class UserPass(MethodView):
    """ Manage a username/password identity for an account. """

    def put(self, account):
        """
        Create a new identity and map it to an account.

        .. :quickref: UserPass; add new userpass identity.

        :reqheader X-Rucio-Username: the desired username.
        :reqheader X-Rucio-Password: the desired password.
        :reqheader X-Rucio-Email: the desired email.
        :param account: the affected account.
        :status 201: Created.
        :status 400: Missing username or password.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        """
        username = request.headers.get('X-Rucio-Username', default=None)
        password = request.headers.get('X-Rucio-Password', default=None)
        email = request.headers.get('X-Rucio-Email', default=None)

        if not username or not password:
            return 'Username and Password must be set.', 400

        try:
            add_identity(username, 'userpass', email, password)
        except Exception as error:
            print(format_exc())
            return str(error), 500

        try:
            add_account_identity(username, 'userpass', account,
                                 email=email, password=password,
                                 issuer=request.environ.get('issuer'),
                                 vo=request.environ.get('vo'))
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return 'Created', 201


class X509(MethodView):
    """ Manage an x509 identity for an account. """

    def put(self, account):
        """
        Create a new identity and map it to an account.

        .. :quickref: X509; add new x509 identity.

        :param account: the affected account.
        :reqheader X-Rucio-Email: the desired email.
        :status 201: Created.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        """
        dn = request.environ.get('SSL_CLIENT_S_DN')
        email = request.headers.get('X-Rucio-Email', default=None)

        try:
            add_identity(dn, 'x509', email=email)
        except Exception as error:
            print(format_exc())
            return str(error), 500

        try:
            add_account_identity(dn, 'x509', account,
                                 email=email,
                                 issuer=request.environ.get('issuer'),
                                 vo=request.environ.get('vo'))
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return 'Created', 201


class GSS(MethodView):
    """ Manage a GSS identity for an account. """

    def put(self, account):
        """
        Create a new identity and map it to an account.

        .. :quickref: GSS; add new GSS identity.

        :param account: the affected account.
        :reqheader X-Rucio-Email: the desired email.
        :status 201: Created.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        """
        gsscred = request.environ.get('REMOTE_USER')
        email = request.headers.get('X-Rucio-Email', default=None)

        try:
            add_identity(gsscred, 'gss', email=email)
        except Exception as error:
            print(format_exc())
            return str(error), 500

        try:
            add_account_identity(gsscred, 'gss', account,
                                 email=email,
                                 issuer=request.environ.get('issuer'),
                                 vo=request.environ.get('vo'))
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return 'Created', 201


class Accounts(MethodView):
    """ Retrieve list of accounts mapped to an identity. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, identity_key, type):
        """
        Return all identities mapped to an account.

        .. :quickref: Accounts; list account identities.

        :param identity_key: Identity string.
        :param type: Identity type.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: List of identities.
        """
        try:
            accounts = list_accounts_for_identity(identity_key, type)
            return jsonify(accounts)
        except Exception as error:
            print(format_exc())
            return str(error), 500


def blueprint():
    bp = Blueprint('identity', __name__, url_prefix='/identities')

    userpass_view = UserPass.as_view('userpass')
    bp.add_url_rule('/<account>/userpass', view_func=userpass_view, methods=['put', ])
    x509_view = X509.as_view('x509')
    bp.add_url_rule('/<account>/x509', view_func=x509_view, methods=['put', ])
    gss_view = GSS.as_view('gss')
    bp.add_url_rule('/<account>/gss', view_func=gss_view, methods=['put', ])
    accounts_view = Accounts.as_view('accounts')
    bp.add_url_rule('/<identity_key>/<type>/accounts', view_func=accounts_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
