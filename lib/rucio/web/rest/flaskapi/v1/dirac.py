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

from flask import Flask, request

from rucio.api.dirac import add_files
from rucio.common.exception import AccessDenied, DataIdentifierAlreadyExists, DatabaseException, \
    Duplicate, InvalidPath, ResourceTemporaryUnavailable, RSENotFound, UnsupportedOperation
from rucio.common.utils import parse_response
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import response_headers, generate_http_error_flask, \
    ErrorHandlingMethodView, json_parameters, param_get


class AddFiles(ErrorHandlingMethodView):

    def post(self):
        """
        ---
        summary: Add files
        description: |
          Atomic method used by the RucioFileCatalog plugin in Dirac that:
          - Creates files and their replicas
          - Creates the dataset containing the files and attach the files to the dataset
          - Creates a rule on the dataset with RSE expression ANY and grouping NONE
          - Creates all the container hierarchy containing the dataset
        tags:
          - Dirac
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - lfns
                properties:
                  lfns:
                    description: "List of lfn (dictionary {'lfn': <lfn>, 'rse': <rse>, 'bytes': <bytes>, 'adler32': <adler32>, 'guid': <guid>, 'pfn': <pfn>}."
                    type: array
                    items:
                      type: object
                  ignore_availability:
                    description: If the availability should be ignored.
                    type: boolean
                  parents_metadata:
                    description: "Metadata for selected hierarchy DIDs."
                    type: object
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: DID not found
          405:
            description: Unsupported Operation
          409:
            description: Duplicate
          503:
            description: Temporary error.
        """
        parameters = json_parameters(parse_response)
        lfns = param_get(parameters, 'lfns')
        ignore_availability = param_get(parameters, 'ignore_availability', default=False)
        parents_metadata = param_get(parameters, 'parents_metadata', default=None)
        try:
            add_files(lfns=lfns, issuer=request.environ.get('issuer'), ignore_availability=ignore_availability,
                      parents_metadata=parents_metadata, vo=request.environ.get('vo'))
        except InvalidPath as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except UnsupportedOperation as error:
            return generate_http_error_flask(405, error)
        except (Duplicate, DataIdentifierAlreadyExists) as error:
            return generate_http_error_flask(409, error)
        except RSENotFound as error:
            return generate_http_error_flask(404, error)
        except (DatabaseException, ResourceTemporaryUnavailable) as error:
            return generate_http_error_flask(503, error)

        return 'Created', 201


def blueprint(with_doc=False):
    bp = AuthenticatedBlueprint('dirac', __name__, url_prefix='/dirac')

    add_file_view = AddFiles.as_view('addfiles')
    bp.add_url_rule('/addfiles', view_func=add_file_view, methods=['post', ])
    bp.add_url_rule('/addfiles/', view_func=add_file_view, methods=['post', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
