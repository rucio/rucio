#!/usr/bin/env python
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

import json
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.heartbeat import list_heartbeats
from rucio.common.exception import RucioException
from rucio.common.utils import APIEncoder, generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask

LOGGER = getLogger("rucio.heartbeat")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


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


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('heartbeat', __name__)

heartbeat_view = Heartbeat.as_view('heartbeat')
# FIXME: Replace with '' rule
bp.add_url_rule('/', view_func=heartbeat_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/heartbeats')
    return doc_app


if __name__ == "__main__":
    application.run()
