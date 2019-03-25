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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE


from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.api.exporter import export_data
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error_flask, render_json
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask


class Export(MethodView):
    """ Export data. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """ Export data from Rucio.

        .. :quickref: Export data

        **Example request**:

        .. sourcecode:: http

            GET /export HTTP/1.1
            Host: rucio.cern.ch

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/json

            {"rses": [{"rse": "MOCK", "rse_type": "TAPE"}], "distances": {}}
        :resheader Content-Type: application/json
        :status 200: DIDs found
        :status 401: Invalid Auth Token
        :status 406: Not Acceptable
        :returns: dictionary with rucio data
        """

        try:
            return render_json(**export_data(issuer=request.environ.get('issuer')))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])


bp = Blueprint('export', __name__)

export_view = Export.as_view('scope')
bp.add_url_rule('', view_func=export_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/export')
    return doc_app


if __name__ == "__main__":
    application.run()
