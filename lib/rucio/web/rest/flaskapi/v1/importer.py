# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Muhammad Aditya Hilmy <didithilmy@gmail.com>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.api.importer import import_data
from rucio.common.exception import RucioException
from rucio.common.utils import parse_response
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask


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

            Created
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
            import_data(data=data_to_import, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])

        return 'Created', 201


def blueprint(no_doc=True):
    bp = Blueprint('import', __name__, url_prefix='/import')

    import_view = Import.as_view('scope')
    if no_doc:
        # rule without trailing slash needs to be added before rule with trailing slash
        bp.add_url_rule('', view_func=import_view, methods=['post', ])
    bp.add_url_rule('/', view_func=import_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(no_doc=False))
    return doc_app
