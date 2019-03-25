# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from functools import wraps
from flask import request
from time import time
from traceback import format_exc

from rucio.api.authentication import validate_auth_token
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error_flask, generate_uuid


def before_request():
    if request.environ.get('REQUEST_METHOD') == 'OPTIONS':
        return '', 200

    auth_token = request.environ.get('HTTP_X_RUCIO_AUTH_TOKEN')

    try:
        auth = validate_auth_token(auth_token)
    except RucioException as error:
        return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
    except Exception as error:
        print(format_exc())
        return error, 500

    if auth is None:
        return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

    request.environ['issuer'] = auth.get('account')
    request.environ['identity'] = auth.get('identity')
    request.environ['request_id'] = generate_uuid()
    request.environ['start_time'] = time()


def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = request.environ.get('HTTP_ORIGIN')
    response.headers['Access-Control-Allow-Headers'] = request.environ.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'

    if request.environ.get('REQUEST_METHOD') == 'GET':
        response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Cache-Control'] = 'post-check=0, pre-check=0'
        response.headers['Pragma'] = 'no-cache'

    return response


def check_accept_header_wrapper_flask(supported_content_types):
    """ Decorator to check if an endpoint supports the requested content type. """
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            requested_content_type = request.environ.get('HTTP_ACCEPT')
            request_type_allowed = True
            if requested_content_type:
                if ',' in requested_content_type:
                    for content_type in requested_content_type.replace(' ', '').split(','):
                        if content_type in supported_content_types or '*/*' in content_type:
                            request_type_allowed = True
                            break
                        else:
                            request_type_allowed = False
                else:
                    if requested_content_type not in supported_content_types and '*/*' not in requested_content_type:
                        request_type_allowed = False

            if not request_type_allowed:
                return generate_http_error_flask(406, 'UnsupportedRequestedContentType', 'The requested content type %s is not supported. Use %s.' % (requested_content_type, ','.join(supported_content_types)))
            return f(*args, **kwargs)
        return decorated
    return wrapper
