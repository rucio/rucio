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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.api.importer import import_data
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error_flask, parse_response
from rucio.web.rest.flaskapi.v1.common import before_request, after_request


class Import(MethodView):
    """ Import data. """

    def post(self):
        """ Import data into Rucio.

        .. :quickref: Import data into Rucio.

        **Example request**:

        .. sourcecode:: http

            POST /import HTTP/1.1
            Host: rucio.cern.ch

            {
                "rses": [{"rse": "MOCK", "rse_type": "TAPE"}]
            }

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 201 OK
            Vary: Accept
            Content-Type: application/x-json-stream

            Created
        :resheader Content-Type: application/json
        :status 200: DIDs found
        :status 401: Invalid Auth Token
        :returns: dictionary with rucio data
        """
        json_data = request.data
        try:
            data_to_import = json_data and parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter dictionary')

        try:
            import_data(data=data_to_import, issuer=request.environ.get('issuer'))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])

        return 'Created', 201


bp = Blueprint('import', __name__)

import_view = Import.as_view('scope')
bp.add_url_rule('', view_func=import_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/import')
    return doc_app


if __name__ == "__main__":
    application.run()
