#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

from logging import getLogger, StreamHandler, DEBUG

from flask import Flask, Blueprint, jsonify, request
from flask.views import MethodView
from werkzeug.datastructures import Headers

from rucio import version
from rucio.web.rest.flaskapi.v1.common import after_request, check_accept_header_wrapper_flask

LOGGER = getLogger("rucio.rucio")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class Ping(MethodView):
    '''
    Ping class
    '''

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        Ping the server and retrieve the server version.

        .. :quickref: Ping; Ping the server.

        **Example request**:

        .. sourcecode:: http

            GET /ping HTTP/1.1
            Host: rucio-server.com
            Accept: application/json

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/json

            {"version": "1.15.0"}

        :status 200: OK.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: JSON dictionary with the version.
        """
        headers = Headers()
        headers.set('Access-Control-Allow-Origin', request.environ.get('HTTP_ORIGIN'))
        headers.set('Access-Control-Allow-Headers', request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        headers.set('Access-Control-Allow-Methods', '*')
        headers.set('Access-Control-Allow-Credentials', 'true')

        headers.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        headers.add('Cache-Control', 'post-check=0, pre-check=0')
        headers.set('Pragma', 'no-cache')

        response = jsonify(version=version.version_string())
        response.headers.extend(headers)
        return response


# ----------------------
#   Web service startup
# ----------------------
bp = Blueprint('ping', __name__)

ping_view = Ping.as_view('ping')
bp.add_url_rule('/', view_func=ping_view, methods=['get', ])
# FIXME: Add '' rule

application = Flask(__name__)
application.register_blueprint(bp)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/ping')
    return doc_app


if __name__ == "__main__":
    application.run()
