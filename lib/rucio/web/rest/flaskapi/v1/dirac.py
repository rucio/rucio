# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021

from flask import Flask, Blueprint, request

from rucio.api.dirac import add_files
from rucio.common.exception import AccessDenied, DataIdentifierAlreadyExists, DatabaseException, \
    Duplicate, InvalidPath, ResourceTemporaryUnavailable, RSENotFound, UnsupportedOperation
from rucio.common.utils import parse_response
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, generate_http_error_flask, \
    ErrorHandlingMethodView, json_parameters, param_get


class AddFiles(ErrorHandlingMethodView):

    def post(self):
        """
        Atomic method used by the RucioFileCatalog plugin in Dirac that :
        - Creates files and their replicas
        - Creates the dataset containing the files and attach the files to the dataset
        - Creates a rule on the dataset with RSE expression ANY and grouping NONE
        - Creates all the container hierarchy containing the dataset

        ..:quickref: AddFiles; Method used by the RucioFileCatalog plugin in Dirac.

        :<json list lfns: List of lfn (dictionary {'lfn': <lfn>, 'rse': <rse>, 'bytes': <bytes>, 'adler32': <adler32>, 'guid': <guid>, 'pfn': <pfn>}.
        :<json bool ignore_availability: A boolean to choose if unavailable sites need to be ignored.

        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid auth token.
        :status 404: DID not found.
        :status 405: Unsupported Operation.
        :status 409: Duplicate.
        :status 503: Temporary error.
        """
        parameters = json_parameters(parse_response)
        lfns = param_get(parameters, 'lfns')
        ignore_availability = param_get(parameters, 'ignore_availability', default=False)

        try:
            add_files(lfns=lfns, issuer=request.environ.get('issuer'), ignore_availability=ignore_availability)
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


def blueprint(no_doc=True):
    bp = Blueprint('dirac', __name__, url_prefix='/dirac')

    add_file_view = AddFiles.as_view('addfiles')
    bp.add_url_rule('/addfiles', view_func=add_file_view, methods=['post', ])
    bp.add_url_rule('/addfiles/', view_func=add_file_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(no_doc=False))
    return doc_app
