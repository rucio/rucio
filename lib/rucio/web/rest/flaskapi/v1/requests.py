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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2020
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import json

import flask
from flask import Flask, Blueprint, Response

from rucio.api import request
from rucio.common.exception import RequestNotFound
from rucio.common.utils import APIEncoder, render_json
from rucio.core.rse import get_rses_with_attribute_value, get_rse_name
from rucio.db.sqla.constants import RequestState
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream, \
    request_auth_env, response_headers, generate_http_error_flask, ErrorHandlingMethodView


class RequestGet(ErrorHandlingMethodView):
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
            scope, name = parse_scope_name(scope_name, flask.request.environ.get('vo'))
        except ValueError as error:
            return generate_http_error_flask(400, error)

        try:
            request_data = request.get_request_by_did(
                scope=scope,
                name=name,
                rse=rse,
                issuer=flask.request.environ.get('issuer'),
                vo=flask.request.environ.get('vo'),
            )
            return Response(json.dumps(request_data, cls=APIEncoder), content_type='application/json')
        except RequestNotFound as error:
            return generate_http_error_flask(404, error.__class__.__name__, f'No request found for DID {scope}:{name} at RSE {rse}')


class RequestList(ErrorHandlingMethodView):
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
        src_rse = flask.request.args.get('src_rse', default=None)
        dst_rse = flask.request.args.get('dst_rse', default=None)
        src_site = flask.request.args.get('src_site', default=None)
        dst_site = flask.request.args.get('dst_site', default=None)
        request_states = flask.request.args.get('request_states', default=None)

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
            src_rses = get_rses_with_attribute_value(key='site', value=src_site, lookup_key='site', vo=flask.request.environ.get('vo'))
            if not src_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {src_site} to RSE')
            src_rses = [get_rse_name(rse['rse_id']) for rse in src_rses]
            dst_rses = get_rses_with_attribute_value(key='site', value=dst_site, lookup_key='site', vo=flask.request.environ.get('vo'))
            if not dst_rses:
                return generate_http_error_flask(404, 'NotFound', f'Could not resolve site name {dst_site} to RSE')
            dst_rses = [get_rse_name(rse['rse_id']) for rse in dst_rses]
        else:
            dst_rses = [dst_rse]
            src_rses = [src_rse]

        def generate(issuer, vo):
            for result in request.list_requests(src_rses, dst_rses, states, issuer=issuer, vo=vo):
                del result['_sa_instance_state']
                yield render_json(**result) + '\n'

        return try_stream(generate(issuer=flask.request.environ.get('issuer'), vo=flask.request.environ.get('vo')))


def blueprint():
    bp = Blueprint('requests', __name__, url_prefix='/requests')

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
