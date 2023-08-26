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

from flask import Flask, request, Response

from rucio.api.exporter import export_data
from rucio.common.utils import render_json
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import response_headers, check_accept_header_wrapper_flask, \
    ErrorHandlingMethodView


class Export(ErrorHandlingMethodView):
    """ Export data. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        ---
        summary: Export data
        description: Export data from rucio.
        tags:
          - Export
        parameters:
        - name: distance
          in: query
          description: Should the distance be enabled?
          schema:
            type: boolean
          required: false
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: object
                  description: Dictionary with rucio data.
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
        """
        distance = request.args.get('distance', default='True') == 'True'
        return Response(render_json(**export_data(issuer=request.environ.get('issuer'), distance=distance, vo=request.environ.get('vo'))), content_type='application/json')


def blueprint(with_doc=False):
    bp = AuthenticatedBlueprint('export', __name__, url_prefix='/export')

    export_view = Export.as_view('scope')
    if not with_doc:
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('', view_func=export_view, methods=['get', ])
    bp.add_url_rule('/', view_func=export_view, methods=['get', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
