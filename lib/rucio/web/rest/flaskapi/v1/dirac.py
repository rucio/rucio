# -*- coding: utf-8 -*-
# Copyright 2020 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

from traceback import format_exc

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.api.dirac import add_files
from rucio.common.exception import (AccessDenied, DataIdentifierAlreadyExists, InvalidType,
                                    DatabaseException, Duplicate, InvalidPath,
                                    ResourceTemporaryUnavailable, RucioException,
                                    RSENotFound, UnsupportedOperation)
from rucio.common.utils import parse_response
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask


class AddFiles(MethodView):

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
        :status 500: Internal Error.
        :status 503: Temporary error.
        """
        try:
            parameters = parse_response(request.data)
        except (ValueError, InvalidType):
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_files(lfns=parameters['lfns'], issuer=request.environ.get('issuer'), ignore_availability=parameters.get('ignore_availability', False))
        except InvalidPath as error:
            return generate_http_error_flask(400, 'InvalidPath', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(405, 'UnsupportedOperation', error.args[0])
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except DataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except DatabaseException as error:
            return generate_http_error_flask(503, 'DatabaseException', error.args[0])
        except ResourceTemporaryUnavailable as error:
            return generate_http_error_flask(503, 'ResourceTemporaryUnavailable', error.args[0])
        except RucioException as error:
            print(format_exc())
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
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
