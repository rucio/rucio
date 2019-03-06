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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from traceback import format_exc
try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs
from rucio.api.authentication import validate_auth_token
from rucio.api.credential import get_signed_url
from rucio.common.exception import AccessDenied, RucioException
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask

from flask import Flask, Blueprint, request, Response
from flask.views import MethodView


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

        :reqheader X-Rucio-Account: Account identifier as a string.
        :reqheader X-Rucio-AppID: Application identifier as a string.
        :resheader Access-Control-Allow-Origin:
        :resheader Access-Control-Allow-Headers:
        :resheader Access-Control-Allow-Methods:
        :resheader Access-Control-Allow-Credentials:
        :resheader Access-Control-Expose-Headers:
        :resheader X-Rucio-Auth-Token: The authentication token
        :status 200: Successfully signed URL
        :status 400: Bad Request
        :status 401: Unauthorized
        :status 406: Not Acceptable
        :status 500: Internal Server Error
        """

        response = Response()
        response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
        response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
        response.headers['Access-Control-Allow-Methods'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'X-Rucio-Auth-Token'

        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

        account = request.environ.get('HTTP_X_RUCIO_ACCOUNT')
        appid = request.environ.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = request.environ.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = request.remote_addr

        try:
            validate_auth_token(request.environ.get('HTTP_X_RUCIO_AUTH_TOKEN'))
        except AccessDenied:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate to account %(account)s with given credentials' % locals())
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        svc, operation, url = None, None, None
        try:
            params = parse_qs(request.query[1:])
            lifetime = params.get('lifetime', [600])[0]
            service = params.get('svc', ['gcs'])[0]
            operation = params.get('op', ['read'])[0]
            url = params.get('url', [None])[0]
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        if service not in ['gcs']:
            return generate_http_error_flask(400, 'ValueError', 'Parameter "svc" must be either empty(=gcs), or gcs')

        if url is None:
            return generate_http_error_flask(400, 'ValueError', 'Parameter "url" not found')

        if operation not in ['read', 'write', 'delete']:
            return generate_http_error_flask(400, 'ValueError', 'Parameter "op" must be either empty(=read), read, write, or delete.')

        try:
            result = get_signed_url(account, appid, ip, service=service, operation='read', url=url, lifetime=lifetime)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

        if not result:
            return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot generate signed URL for account %(account)s' % locals())

        return response


bp = Blueprint('credential', __name__)

signurl_view = SignURL.as_view('signurl')
bp.add_url_rule('/signurl', view_func=signurl_view, methods=['get', 'options'])
application = Flask(__name__)
application.register_blueprint(bp)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/credential')
    return doc_app


if __name__ == "__main__":
    application.run()
