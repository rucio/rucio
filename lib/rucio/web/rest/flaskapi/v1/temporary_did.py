#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

from json import loads
from traceback import format_exc
from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.api.temporary_did import (add_temporary_dids)
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import before_request, after_request


class BulkDIDS(MethodView):

    def post(self):
        """
        Bulk add temporary data identifiers.

        .. :quickref: BulkDIDS; Bulk add temporary dids.

        :<json list dids: A list of dids.
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        """

        json_data = request.data
        try:
            dids = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_temporary_dids(dids=dids, issuer=request.environ.get('issuer'))
        except RucioException, e:
            return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            return e, 500
        return "Created", 201


class Compose(MethodView):

    def POST(self):
        return "Created", 201


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('temporary_did', __name__)

bulk_dids_view = BulkDIDS.as_view('bulk_dids')
bp.add_url_rule('/', view_func=bulk_dids_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/temporary_dids')
    return doc_app


if __name__ == "__main__":
    application.run()
