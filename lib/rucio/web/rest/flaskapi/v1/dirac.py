#!/usr/bin/env python
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
#
# PY3K COMPATIBLE

from __future__ import print_function
from traceback import format_exc
from json import loads

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask
from rucio.api.dirac import add_files
from rucio.common.exception import (AccessDenied, DataIdentifierAlreadyExists, InvalidType,
                                    DatabaseException, Duplicate, InvalidPath,
                                    ResourceTemporaryUnavailable, RucioException,
                                    RSENotFound)
from rucio.common.utils import generate_http_error_flask


class AddFiles(MethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def post(self):
        """
        Create file replicas at a given RSE.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            409 Conflict
            500 Internal Error
        """
        try:
            json_data = loads(request.data)
        except (ValueError, InvalidType):
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_files(lfns=json_data['lfns'], issuer=request.environ.get('issuer'), ignore_availability=json_data.get('ignore_availability', False))
        except InvalidPath as error:
            return generate_http_error_flask(400, 'InvalidPath', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RSENotFound as error:
            return generate_http_error_flask(404, 'RSENotFound', error.args[0])
        except DataIdentifierAlreadyExists as error:
            return generate_http_error_flask(409, 'DataIdentifierAlreadyExists', error.args[0])
        except Duplicate as error:
            return generate_http_error_flask(409, 'Duplicate', error.args[0])
        except DatabaseException as error:
            return generate_http_error_flask(500, 'DatabaseException', error.args[0])
        except ResourceTemporaryUnavailable as error:
            return generate_http_error_flask(503, 'ResourceTemporaryUnavailable', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500
        return "Created", 201


"""----------------------
   Web service startup
----------------------"""


bp = Blueprint('dirac', __name__)
URLS = ('/addfiles/?$', 'AddFiles')

add_file_view = AddFiles.as_view('addfiles')
bp.add_url_rule('/addfiles', view_func=add_file_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)
