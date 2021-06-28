# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

from typing import TYPE_CHECKING

from flask import Flask, Blueprint, request
from werkzeug.datastructures import Headers

from rucio.api.credential import get_signed_url
from rucio.common.exception import CannotAuthenticate
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, extract_vo, \
    generate_http_error_flask, ErrorHandlingMethodView

if TYPE_CHECKING:
    from typing import Optional
    from rucio.web.rest.flaskapi.v1.common import HeadersType


class SignURL(ErrorHandlingMethodView):
    """
    Request a signed URL.
    """

    def get_headers(self) -> "Optional[HeadersType]":
        headers = Headers()
        headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        headers['Access-Control-Allow-Methods'] = '*'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'
        return headers

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
        return '', 200, self.get_headers()

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
        """
        headers = self.get_headers()
        vo = extract_vo(request.headers)
        account = request.headers.get('X-Rucio-Account', default=None)
        appid = request.headers.get('X-Rucio-AppID', default='unknown')
        ip = request.headers.get('X-Forwarded-For', default=request.remote_addr)

        if 'rse' not in request.args:
            return generate_http_error_flask(400, ValueError.__name__, 'Parameter "rse" not found', headers=headers)
        rse = request.args.get('rse')

        lifetime = request.args.get('lifetime', type=int, default=600)
        service = request.args.get('svc', default='gcs')
        operation = request.args.get('op', default='read')

        if 'url' not in request.args:
            return generate_http_error_flask(400, ValueError.__name__, 'Parameter "url" not found', headers=headers)
        url = request.args.get('url')

        if service not in ['gcs', 's3', 'swift']:
            return generate_http_error_flask(400, ValueError.__name__, 'Parameter "svc" must be either empty(=gcs), gcs, s3 or swift', headers=headers)

        if operation not in ['read', 'write', 'delete']:
            return generate_http_error_flask(400, ValueError.__name__, 'Parameter "op" must be either empty(=read), read, write, or delete.', headers=headers)

        result = get_signed_url(account, appid, ip, rse=rse, service=service, operation=operation, url=url, lifetime=lifetime, vo=vo)

        if not result:
            return generate_http_error_flask(401, CannotAuthenticate.__name__, f'Cannot generate signed URL for account {account}', headers=headers)

        return str(result), 200, headers


def blueprint(no_doc=True):
    bp = Blueprint('credentials', __name__, url_prefix='/credentials')

    signurl_view = SignURL.as_view('signurl')
    bp.add_url_rule('/signurl', view_func=signurl_view, methods=['get', 'options'])
    if no_doc:
        # yes, /signur ~= '/signurl?$'
        bp.add_url_rule('/signur', view_func=signurl_view, methods=['get', 'options'])

    return bp


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(no_doc=False))
    return doc_app
