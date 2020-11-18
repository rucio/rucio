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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

from traceback import format_exc

from flask import Flask, Blueprint, request, Response
from flask.views import MethodView

from rucio.api.credential import get_signed_url
from rucio.common.exception import RucioException
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask
from rucio.web.rest.utils import generate_http_error_flask

try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs


class SignURL(MethodView):
    """
    Request a signed URL.
    """

    def options(self):
        """
        Allow cross-site scripting. Explicit for Authentication.

        :resheader Access-Control-Allow-Origin:
        :resheader Access-Control-Allow-Headers:
        :resheader Access-Control-Allow-Methods:
        :resheader Access-Control-Allow-Credentials:
        :resheader Access-Control-Expose-Headers:
        :status 200: OK
        """

        response = Response(status=200)
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return response

    @check_accept_header_wrapper_flask(['application/octet-stream'])
    def get(self):
        """
        Sign a URL for a limited lifetime for a particular service.

        :reqheader X-Rucio-VO: VO name as a string (Multi-VO only).
        :reqheader X-Rucio-Account: Account identifier as a string.
        :reqheader X-Rucio-AppID: Application identifier as a string.
        :status 200: Successfully signed URL
        :status 400: Bad Request
        :status 401: Unauthorized
        :status 406: Not Acceptable
        :status 500: Internal Server Error
        """

        vo = request.headers.get('X-Rucio-VO', default='def')
        account = request.headers.get('X-Rucio-Account', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        rse, svc, operation, url = None, None, None, None
        try:
            query_string = request.query_string.decode(encoding='utf-8')
            params = parse_qs(query_string)
            rse = params.get('rse', [None])[0]
            lifetime = params.get('lifetime', [600])[0]
            service = params.get('svc', ['gcs'])[0]
            operation = params.get('op', ['read'])[0]
            url = params.get('url', [None])[0]
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        if service not in ['gcs', 's3', 'swift']:
            return generate_http_error_flask(400, 'ValueError', 'Parameter "svc" must be either empty(=gcs), gcs, s3 or swift')

        if url is None:
            return generate_http_error_flask(400, 'ValueError', 'Parameter "url" not found')

        if rse is None:
            return generate_http_error_flask(400, 'ValueError', 'Parameter "rse" not found')

        if operation not in ['read', 'write', 'delete']:
            return generate_http_error_flask(400, 'ValueError', 'Parameter "op" must be either empty(=read), read, write, or delete.')

        try:
            result = get_signed_url(account, appid, ip, rse=rse, service=service, operation=operation, url=url, lifetime=lifetime, vo=vo)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot generate signed URL for account %(account)s' % locals())

        return str(result), 200


def blueprint():
    bp = Blueprint('credential', __name__, url_prefix='/credential')

    signurl_view = SignURL.as_view('signurl')
    bp.add_url_rule('/signurl', view_func=signurl_view, methods=['get', 'options'])
    # yes, /signur ~= '/signurl?$'
    bp.add_url_rule('/signur', view_func=signurl_view, methods=['get', 'options'])

    return bp


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
