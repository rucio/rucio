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

from rucio.api.importer import import_data
from rucio.common.utils import parse_response
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, ErrorHandlingMethodView, json_parameters


class Import(ErrorHandlingMethodView):
    """ Import data. """

    def post(self):
        """
        ---
        summary: Import data
        description: Import data into rucio
        tags:
            - Import
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                properties:
                  rses:
                    description: Rse data with rse name as key.
                    type: object
                    additionalProperties:
                      x-additionalPropertiesName: rse name
                      type: object
                      properties:
                        rse_type:
                          description: The type of an rse.
                          type: string
                          enum: ['DISK', 'TAPE']
                  distances:
                    description: Distances data with src rse name as key.
                    type: object
                    additionalProperties:
                      x-additionalPropertiesName: src rse
                      description: Distances with dest rse as key.
                      type: object
                      additionalProperties:
                        x-additionalPropertiesName: dest rse
                        description: Distance for two rses.
                        type: object
                        properties:
                          ranking:
                            description: The distance between the rses.
                            type: integer
                          agis_distance:
                            description: The agis distance between the rses.
                            type: integer
                          geoip_distance:
                            description: The geoip distance between the rses.
                            type: integer
                          active:
                            description: Active FTS transfer.
                            type: integer
                          submitted:
                            description: Submitted FTS transfer.
                            type: integer
                          transfer_speed:
                            description: FTS transfer speed.
                            type: integer
                          finished:
                            description: Finished FTS transfer.
                            type: integer
                          failed:
                            description: Failed fts transfer.
                            type: integer
                  accounts:
                    description: Account data.
                    type: array
                    items:
                      description: An account.
                      type: object
                      properties:
                        account:
                          description: The account identifier.
                          type: string
                        email:
                          description: The email of an account.
                          type: string
                        identities:
                          description: The identiies accociated with an account. Deletes old identites and adds the newly defined ones.
                          type: array
                          items:
                            description: One identity associated with an account.
                            type: object
                            properties:
                              type:
                                description: The type of the identity.
                                type: string
                                enum: ['X509', 'GSS', 'USERPASS', 'SSH', 'SAML', 'OIDC']
                              identity:
                                description: Identifier of the identity.
                                type: string
                              password:
                                description: The password if the type is USERPASS.
                                type: string
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: Invalid Auth Token
        """
        data = json_parameters(parse_response)
        import_data(data=data, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        return 'Created', 201


def blueprint(with_doc=False):
    bp = Blueprint('import', __name__, url_prefix='/import')

    import_view = Import.as_view('scope')
    if not with_doc:
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('', view_func=import_view, methods=['post', ])
    bp.add_url_rule('/', view_func=import_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
