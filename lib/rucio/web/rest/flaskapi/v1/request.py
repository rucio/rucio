#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014-2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

import json

from logging import getLogger, StreamHandler, DEBUG

from flask import Flask, Blueprint, Response, request as f_request
from flask.views import MethodView

from rucio.api import request
from rucio.common.utils import generate_http_error_flask, APIEncoder
from rucio.web.rest.flaskapi.v1.common import before_request, after_request


LOGGER = getLogger("rucio.request")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class RequestGet(MethodView):
    """ REST API to get requests. """

    def get(self, scope, name, rse):
        """
        List request for given DID to a destination RSE.

        .. :quickref: RequestGet; list requests

        :param scope: data identifier scope.
        :param name: data identifier name.
        :param rse: destination RSE.
        :reqheader Content-Type: application/json
        :status 200: Request found.
        :status 404: Request not found.
        """

        try:
            res = json.dumps(request.get_request_by_did(scope=scope,
                                                        name=name,
                                                        rse=rse,
                                                        issuer=f_request.environ.get('issuer')),
                             cls=APIEncoder)
            return Response(res, content_type="application/json")
        except Exception:
            return generate_http_error_flask(404, 'RequestNotFound', 'No request found for DID %s:%s at RSE %s' % (scope,
                                                                                                                   name,
                                                                                                                   rse))


"""----------------------
   Web service startup
----------------------"""

bp = Blueprint('request', __name__)
request_get_view = RequestGet.as_view('request_get')
bp.add_url_rule('/<scope>/<name>/<rse>', view_func=request_get_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/requests')
    return doc_app


if __name__ == "__main__":
    application.run()
