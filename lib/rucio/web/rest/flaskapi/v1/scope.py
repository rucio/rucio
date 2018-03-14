#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012, 2018
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017

from json import dumps

from rucio.api.scope import add_scope, list_scopes
from rucio.common.exception import AccountNotFound, Duplicate, RucioException
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import before_request, after_request

from flask import Flask, Blueprint, request
from flask.views import MethodView


class Scope(MethodView):
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
        :returns: :class:`String`
        """
        return dumps(list_scopes())

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
            add_scope(scope, account, issuer=request.environ.get('issuer'))
        except Duplicate, e:
            return generate_http_error_flask(409, 'Duplicate', e.args[0][0])
        except AccountNotFound, e:
            return generate_http_error_flask(404, 'AccountNotFound', e.args[0][0])
        except RucioException, e:
            print(e)
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            return e, 500

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
