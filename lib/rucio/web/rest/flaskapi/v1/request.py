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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2020
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import json
from traceback import format_exc

from flask import Flask, Blueprint, Response, request as f_request
from flask.views import MethodView

from rucio.api import request
from rucio.common.exception import RucioException
from rucio.common.utils import APIEncoder, render_json
from rucio.core.rse import get_rses_with_attribute_value, get_rse_name
from rucio.db.sqla.constants import RequestState
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream, request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask

try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs


class RequestGet(MethodView):
    """ REST API to get requests. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope_name, rse):
        """
        List request for given DID to a destination RSE.

        .. :quickref: RequestGet; list requests

        :param scope_name: data identifier (scope)/(name).
        :param rse: destination RSE.
        :reqheader Content-Type: application/json
        :status 200: Request found.
        :status 404: Request not found.
        :status 406: Not Acceptable.
        """
        try:
            scope, name = parse_scope_name(scope_name, f_request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, 'ValueError', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        try:
            request_data = request.get_request_by_did(scope=scope, name=name, rse=rse, issuer=f_request.environ.get('issuer'), vo=f_request.environ.get('vo'))
            return Response(json.dumps(request_data, cls=APIEncoder), content_type='application/json')
        except Exception:
            return generate_http_error_flask(404, 'RequestNotFound', 'No request found for DID %s:%s at RSE %s' % (scope, name, rse))


class RequestList(MethodView):
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
        try:
            query_string = f_request.query_string.decode(encoding='utf-8')
            params = parse_qs(query_string)
            src_rse = params.get('src_rse', [None])[0]
            dst_rse = params.get('dst_rse', [None])[0]
            src_site = params.get('src_site', [None])[0]
            dst_site = params.get('dst_site', [None])[0]
            request_states = params.get('request_states', [None])[0]

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
                states = [RequestState(state) for state in request_states.split(',')]
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

            def generate(issuer, vo):
                for result in request.list_requests(src_rses, dst_rses, states, issuer=issuer, vo=vo):
                    del result['_sa_instance_state']
                    yield render_json(**result) + '\n'

            return try_stream(generate(issuer=f_request.environ.get('issuer'), vo=f_request.environ.get('vo')))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


def blueprint():
    bp = Blueprint('request', __name__, url_prefix='/requests')

    request_get_view = RequestGet.as_view('request_get')
    bp.add_url_rule('/<path:scope_name>/<rse>', view_func=request_get_view, methods=['get', ])
    request_list_view = RequestList.as_view('request_list')
    bp.add_url_rule('/list', view_func=request_list_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
