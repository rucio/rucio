# -*- coding: utf-8 -*-
# Copyright 2014-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from traceback import format_exc

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.api.lock import get_dataset_locks_by_rse, get_dataset_locks
from rucio.common.exception import RucioException, RSENotFound
from rucio.common.utils import render_json
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream, request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask


class LockByRSE(MethodView):
    """ REST APIs for dataset locks. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rse):
        """ get locks for a given rse.

        :param rse: The RSE name.
        :query did_type: The type used to filter, e.g., DATASET, CONTAINER.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: Line separated list of dictionaries with lock information.
        """

        did_type = request.args.get('did_type', None)
        try:
            if did_type == 'dataset':
                def generate(vo):
                    for lock in get_dataset_locks_by_rse(rse, vo=vo):
                        yield render_json(**lock) + '\n'

                return try_stream(generate(vo=request.environ.get('vo')))
            else:
                return 'Wrong did_type specified', 500
        except RSENotFound as error:
            return generate_http_error_flask(404, error.__class__.__name__, error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class LockByScopeName(MethodView):
    """ REST APIs for dataset locks. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """ get locks for a given scope, name.

        :param scope_name: data identifier (scope)/(name).
        :query did_type: The type used to filter, e.g., DATASET, CONTAINER.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: Line separated list of dictionary with lock information.
        """
        did_type = request.args.get('did_type', None)
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))
            if did_type == 'dataset':
                def generate(vo):
                    for lock in get_dataset_locks(scope, name, vo=vo):
                        yield render_json(**lock) + '\n'

                return try_stream(generate(vo=request.environ.get('vo')))
            else:
                return 'Wrong did_type specified', 500
        except ValueError as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


def blueprint():
    bp = Blueprint('lock', __name__, url_prefix='/locks')

    lock_by_rse_view = LockByRSE.as_view('lock_by_rse')
    bp.add_url_rule('/<rse>', view_func=lock_by_rse_view, methods=['get', ])
    lock_by_scope_name_view = LockByScopeName.as_view('lock_by_scope_name')
    bp.add_url_rule('/<path:scope_name>', view_func=lock_by_scope_name_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
