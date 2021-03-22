# -*- coding: utf-8 -*-
# Copyright 2021 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021
# - Cedric Serfon <cedric.serfon@cern.ch>, 2021

from flask import Flask, Blueprint, request, Response

from rucio.api.exporter import export_data
from rucio.common.utils import render_json
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    ErrorHandlingMethodView


class Export(ErrorHandlingMethodView):
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
        distance = request.args.get('distance', default=True)
        return Response(render_json(**export_data(issuer=request.environ.get('issuer'), distance=distance, vo=request.environ.get('vo'))), content_type='application/json')


def blueprint(no_doc=True):
    bp = Blueprint('export', __name__, url_prefix='/export')

    export_view = Export.as_view('scope')
    if no_doc:
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('', view_func=export_view, methods=['get', ])
    bp.add_url_rule('/', view_func=export_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(no_doc=False))
    return doc_app
