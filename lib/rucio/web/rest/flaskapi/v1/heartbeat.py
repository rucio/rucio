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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import json
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.heartbeat import list_heartbeats
from rucio.common.exception import RucioException
from rucio.common.utils import APIEncoder
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask
from rucio.web.rest.utils import generate_http_error_flask


class Heartbeat(MethodView):
    """ REST API for Heartbeats. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        List all heartbeats.

        .. :quickref: Heartbeat; List heartbeats.

        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :returns: List of heartbeats.
        """
        try:
            return Response(json.dumps(list_heartbeats(issuer=request.environ.get('issuer'), vo=request.environ.get('vo')),
                                       cls=APIEncoder), content_type='application/json')
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


def blueprint():
    bp = Blueprint('heartbeat', __name__, url_prefix='/heartbeats')

    heartbeat_view = Heartbeat.as_view('heartbeat')
    bp.add_url_rule('', view_func=heartbeat_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
