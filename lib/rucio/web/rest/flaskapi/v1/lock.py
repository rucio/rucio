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
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from logging import getLogger, StreamHandler, DEBUG
from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.lock import get_dataset_locks_by_rse, get_dataset_locks
from rucio.common.exception import RucioException, RSENotFound
from rucio.common.utils import generate_http_error_flask, render_json
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask

LOGGER = getLogger("rucio.lock")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


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
                data = ""
                for lock in get_dataset_locks_by_rse(rse):
                    data += render_json(**lock) + '\n'
                return Response(data, content_type="application/x-json-stream")
            else:
                return 'Wrong did_type specified', 500
        except RSENotFound as error:
            return generate_http_error_flask(404, error.__class__.__name__, error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500


class LockByScopeName(MethodView):
    """ REST APIs for dataset locks. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def GET(self, scope, name):
        """ get locks for a given scope, name.

        :param scope: The DID scope.
        :param name: The DID name.
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
            if did_type == 'dataset':
                data = ""
                for lock in get_dataset_locks(scope, name):
                    data += render_json(**lock) + '\n'
                return Response(data, content_type="application/x-json-stream")
            else:
                return 'Wrong did_type specified', 500
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('lifetime_exception', __name__)

lock_by_rse_view = LockByRSE.as_view('lock_by_rse')
bp.add_url_rule('/<rse>', view_func=lock_by_rse_view, methods=['get', ])
lock_by_scope_name_view = LockByScopeName.as_view('lock_by_scope_name')
bp.add_url_rule('/<scope>/<name>', view_func=lock_by_scope_name_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/locks')
    return doc_app


if __name__ == "__main__":
    application.run()
