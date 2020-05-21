#!/usr/bin/env python
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin, <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from json import dumps

from rucio.api.scope import add_scope, list_scopes
from rucio.common.exception import AccountNotFound, Duplicate, RucioException
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask

from flask import Flask, Blueprint, request
from flask.views import MethodView


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
        return dumps(list_scopes(vo=request.environ.get('vo')))

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
            return error, 500

        return "OK", 201


bp = Blueprint('scope', __name__)

scope_view = Scope.as_view('scope')
bp.add_url_rule('/', view_func=scope_view, methods=['GET', ])
bp.add_url_rule('/<account>/<scope>', view_func=scope_view, methods=['POST', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/scopes')
    return doc_app


if __name__ == "__main__":
    application.run()
