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
from web import application, ctx, OK, header, InternalError

from rucio.api.authentication import validate_auth_token
from rucio.api.credential import get_signed_url
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error
from rucio.web.rest.common import RucioController, check_accept_header_wrapper

URLS = (
    '/signurl?$', 'SignURL',
)


class SignURL(RucioController):
    """
    Request a signed URL.
    """

    def OPTIONS(self):
        """
        HTTP Success:
            200 OK

        Allow cross-site scripting. Explicit for Authorisation.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')
        header('Access-Control-Expose-Headers', 'X-Rucio-Auth-Token')
        raise OK

    @check_accept_header_wrapper(['application/octet-stream'])
    def GET(self):
        """
        HTTP Success:
            200 OK

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            406 Not Acceptable
            500 Internal Server Error

        :param Rucio-Account: Account identifier as a string.
        :param Rucio-AppID: Application identifier as a string.

        :returns: Signed URL.
        """

        account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
        appid = ctx.env.get('HTTP_X_RUCIO_APPID')
        if appid is None:
            appid = 'unknown'
        ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
        if ip is None:
            ip = ctx.ip

        try:
            validate_auth_token(ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN'))
        except RucioException as e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception as e:
            print(format_exc())
            raise InternalError(e)

        rse, svc, operation, url = None, None, None, None
        try:
            params = parse_qs(ctx.query[1:])
            rse = params.get('rse', [None])[0]
            lifetime = params.get('lifetime', [600])[0]
            service = params.get('svc', ['gcs'])[0]
            operation = params.get('op', ['read'])[0]
            url = params.get('url', [None])[0]
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        if service not in ['gcs', 's3', 'swift']:
            raise generate_http_error(400, 'ValueError', 'Parameter "svc" must be either empty(=gcs), gcs, s3 or swift')

        if url is None:
            raise generate_http_error(400, 'ValueError', 'Parameter "url" not found')

        if rse is None:
            raise generate_http_error(400, 'ValueError', 'Parameter "rse" not found')

        if operation not in ['read', 'write', 'delete']:
            raise generate_http_error(400, 'ValueError', 'Parameter "op" must be either empty(=read), read, write, or delete.')

        try:
            result = get_signed_url(account, appid, ip, rse=rse, service=service, operation=operation, url=url, lifetime=lifetime)
        except RucioException as e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception as e:
            print(format_exc())
            raise InternalError(e)

        if not result:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot generate signed URL for account %(account)s' % locals())

        return result


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
application = APP.wsgifunc()
