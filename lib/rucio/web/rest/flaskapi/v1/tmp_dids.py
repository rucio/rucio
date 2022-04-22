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

from flask import Flask, Blueprint, request

from rucio.api.temporary_did import add_temporary_dids
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, ErrorHandlingMethodView, json_list


class BulkDIDS(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Add Temporary Data Identifiers
        description: Bulk adds temporary data identifiers.
        tags:
          - Temporary Data Identifiers
        requestBody:
          content:
            application/json:
              schema:
                description: A list of temporary dids.
                type: array
                items:
                  description: A temporary did.
                  properties:
                    rse:
                      description: The name of the RSE.
                      type: string
                    rse_id:
                      description: The id of the RSE. Can be specified instead of the RSE name.
                      type: string
                    scope:
                      description: The scope.
                      type: string
                    parent_scope:
                      description: The parent scope.
                      type: string
                    name:
                      description: The name of the DID.
                      type: string
                    path:
                      description: The path of the DID.
                      type: string
                    pfn:
                      description: The pfn of the DID.
                      type: string
                    bytes:
                      description: The size of the DID in bytes.
                      type: integer
                    md5:
                      description: The md5 checksum of the DID.
                      type: string
                    adler32:
                      description: The adler32 checksum of the DID.
                      type: string
                    guid:
                      description: The guid of the DID.
                      type: string
                    events:
                      description: The events of the DID.
                      type: string
                    parent_name:
                      description: The name of the parent.
                      type: string
                    offset:
                      description: The offset of the DID.
                      type: integer
        responses:
          201:
            description: Created
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
        """
        dids = json_list()
        add_temporary_dids(dids=dids, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        return 'Created', 201


def blueprint():
    bp = Blueprint('tmp_dids', __name__, url_prefix='/tmp_dids')

    bulk_dids_view = BulkDIDS.as_view('bulk_dids')
    bp.add_url_rule('', view_func=bulk_dids_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
