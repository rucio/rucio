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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

import json

from logging import getLogger, StreamHandler, DEBUG

from flask import Flask, Blueprint, Response, request as f_request
from flask.views import MethodView

from rucio.api import request
from rucio.db.sqla.constants import RequestState
from rucio.core.rse import get_rses_with_attribute_value, get_rse_name
from rucio.common.utils import generate_http_error_flask, APIEncoder
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask


LOGGER = getLogger("rucio.request")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class RequestGet(MethodView):
    """ REST API to get requests. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope, name, rse):
        """
        List request for given DID to a destination RSE.

        .. :quickref: RequestGet; list requests

        :param scope: data identifier scope.
        :param name: data identifier name.
        :param rse: destination RSE.
        :reqheader Content-Type: application/json
        :status 200: Request found.
        :status 404: Request not found.
        :status 406: Not Acceptable.
        """

        try:
            res = json.dumps(request.get_request_by_did(scope=scope,
                                                        name=name,
                                                        rse=rse,
                                                        issuer=f_request.environ.get('issuer'),
                                                        vo=f_request.environ.get('vo')),
                             cls=APIEncoder)
            return Response(res, content_type="application/json")
        except Exception:
            return generate_http_error_flask(404, 'RequestNotFound', 'No request found for DID %s:%s at RSE %s' % (scope,
                                                                                                                   name,
                                                                                                                   rse))


class RequestsGet(MethodView):
    """ REST API to get requests. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        List requests for a given source and destination RSE or site.

        .. :quickref: RequestsGet; list requests

        :reqheader Content-Type: application/x-json-stream
        :status 200: Request found.
        :status 404: Request not found.
        :status 406: Not Acceptable.
        """

        src_rse = f_request.get('src_rse')
        dst_rse = f_request.get('dst_rse')
        src_site = f_request.get('src_site')
        dst_site = f_request.get('dst_site')
        request_states = f_request.get('request_states')

        if not request_states:
            return generate_http_error_flask(400, 'MissingParameter', 'Request state is missing')
        if src_rse and not dst_rse:
            return generate_http_error_flask(400, 'MissingParameter', 'Destination RSE is missing')
        elif dst_rse and not src_rse:
            return generate_http_error_flask(400, 'MissingParameter', 'Source RSE is missing')
        elif src_site and not dst_site:
            return generate_http_error_flask(400, 'MissingParameter', 'Destination site is missing')
        elif dst_site and not src_site:
            return generate_http_error_flask(400, 'MissingParameter', 'Source site is missing')

        try:
            states = [RequestState.from_string(state) for state in request_states.split(',')]
        except ValueError:
            return generate_http_error_flask(400, 'Invalid', 'Request state value is invalid')

        src_rses = []
        dst_rses = []
        if src_site:
            src_rses = get_rses_with_attribute_value(key='site', value=src_site, lookup_key='site', vo=f_request.environ.get('vo'))
            if not src_rses:
                return generate_http_error_flask(404, 'NotFound', 'Could not resolve site name %s to RSE' % src_site)
            src_rses = [get_rse_name(rse['rse_id']) for rse in src_rses]
            dst_rses = get_rses_with_attribute_value(key='site', value=dst_site, lookup_key='site', vo=f_request.environ.get('vo'))
            if not dst_rses:
                return generate_http_error_flask(404, 'NotFound', 'Could not resolve site name %s to RSE' % dst_site)
            dst_rses = [get_rse_name(rse['rse_id']) for rse in dst_rses]
        else:
            dst_rses = [dst_rse]
            src_rses = [src_rse]

        results = []
        for result in request.list_requests(src_rses, dst_rses, states, issuer=f_request.environ.get('issuer'), vo=f_request.environ.get('vo')):
            del result['_sa_instance_state']
            results.append(result)
        return json.dumps(results, cls=APIEncoder)


"""----------------------
   Web service startup
----------------------"""

bp = Blueprint('request', __name__)
request_get_view = RequestGet.as_view('request_get')
requests_get_view = RequestsGet.as_view('requests_get')
bp.add_url_rule('/<scope>/<name>/<rse>', view_func=request_get_view, methods=['get', ])
bp.add_url_rule('/list', view_func=requests_get_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/requests')
    return doc_app


if __name__ == "__main__":
    application.run()
