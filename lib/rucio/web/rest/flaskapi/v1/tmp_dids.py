# -*- coding: utf-8 -*-
# Copyright 2016-2021 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Muhammad Aditya Hilmy <didithilmy@gmail.com>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from flask import Flask, Blueprint, request

from rucio.api.temporary_did import add_temporary_dids
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, ErrorHandlingMethodView, json_list


class BulkDIDS(ErrorHandlingMethodView):

    def post(self):
        """
        Bulk add temporary data identifiers.

        .. :quickref: BulkDIDS; Bulk add temporary dids.

        :<json list dids: A list of dids.
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        """
        dids = json_list()
        add_temporary_dids(dids=dids, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        return 'Created', 201


def blueprint():
    bp = Blueprint('tmp_dids', __name__, url_prefix='/tmp_dids')

    bulk_dids_view = BulkDIDS.as_view('bulk_dids')
    bp.add_url_rule('', view_func=bulk_dids_view, methods=['post', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
