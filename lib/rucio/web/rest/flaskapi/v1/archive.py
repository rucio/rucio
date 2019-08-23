#!/usr/bin/env python
# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.did import list_archive_content
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask

LOGGER, SH = getLogger("rucio.meta"), StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class Archive(MethodView):
    """ REST APIs for archive. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
        """
        List archive content keys.

        .. :quickref: Archive; list archive content keys.

        :param scope: data identifier scope.
        :param name: data identifier name.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        """
        try:
            data = ""
            for file in list_archive_content(scope=scope, name=name, vo=request.environ.get('vo')):
                data += dumps(file) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except Exception as error:
            print(format_exc())
            return error, 500


"""----------------------
   Web service startup
----------------------"""

bp = Blueprint('archive', __name__)
archive_view = Archive.as_view('archive')
bp.add_url_rule('/<scope>/<name>', view_func=archive_view, methods=['get', ])

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
