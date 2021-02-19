# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from flask import Flask, Blueprint, request

from rucio.api.importer import import_data
from rucio.common.utils import parse_response
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, ErrorHandlingMethodView, json_parameters


class Import(ErrorHandlingMethodView):
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
        data = json_parameters(parse_response)
        import_data(data=data, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
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
