#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2017-2020 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function

from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.api.did import list_archive_content
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask, parse_scope_name, try_stream

LOGGER, SH = getLogger("rucio.meta"), StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class Archive(MethodView):
    """ REST APIs for archive. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        List archive content keys.

        .. :quickref: Archive; list archive content keys.

        :param scope_name: data identifier (scope)/(name).
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 400: Invalid value.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        """
        try:
            scope, name = parse_scope_name(scope_name)

            def generate(vo):
                for file in list_archive_content(scope=scope, name=name, vo=vo):
                    yield dumps(file) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


"""----------------------
   Web service startup
----------------------"""

bp = Blueprint('archive', __name__)
archive_view = Archive.as_view('archive')
bp.add_url_rule('/<path:scope_name>/files', view_func=archive_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/archives')
    return doc_app


if __name__ == "__main__":
    application.run()
