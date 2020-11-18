# -*- coding: utf-8 -*-
# Copyright 2014-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

import itertools
import re
from functools import wraps
from time import time
from traceback import format_exc

from flask import request, Response

from rucio.api.authentication import validate_auth_token
from rucio.common.exception import RucioException
from rucio.common.schema import get_schema_value
from rucio.common.utils import generate_uuid
from rucio.web.rest.utils import generate_http_error_flask


def request_auth_env():
    if request.environ.get('REQUEST_METHOD') == 'OPTIONS':
        return '', 200

    auth_token = request.headers.get('X-Rucio-Auth-Token', default=None)

    try:
        auth = validate_auth_token(auth_token)
    except RucioException as error:
        return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
    except Exception as error:
        print(format_exc())
        return str(error), 500

    if auth is None:
        return generate_http_error_flask(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

    request.environ['vo'] = auth.get('vo', 'def')
    request.environ['issuer'] = auth.get('account')
    request.environ['identity'] = auth.get('identity')
    request.environ['request_id'] = generate_uuid()
    request.environ['start_time'] = time()


def response_headers(response):
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
            if not request.accept_mimetypes.provided:
                # accept anything, if Accept header is not provided
                return f(*args, **kwargs)

            for supported in supported_content_types:
                if supported in request.accept_mimetypes:
                    return f(*args, **kwargs)

            # none matched..
            return generate_http_error_flask(406, 'UnsupportedRequestedContentType', 'The requested content type %s is not supported. Use %s.' % (request.environ.get("HTTP_ACCEPT"), str(supported_content_types)))
        return decorated
    return wrapper


def parse_scope_name(scope_name, vo):
    """
    Parses the given scope_name according to the schema's
    SCOPE_NAME_REGEXP and returns a (scope, name) tuple.

    :param scope_name: the scope_name string to be parsed.
    :param vo: the vo currently in use.
    :raises ValueError: when scope_name could not be parsed.
    :returns: a (scope, name) tuple.
    """
    # why again does that regex start with a slash?
    scope_name = re.match(get_schema_value('SCOPE_NAME_REGEXP', vo), '/' + scope_name)
    if scope_name is None:
        raise ValueError('cannot parse scope and name')
    return scope_name.group(1, 2)


def try_stream(generator, content_type=None):
    """
    Peeks at the first element of the passed generator and raises
    an error, if yielding raises. Otherwise returns
    a flask.Response object.

    :param generator: a generator function or an iterator.
    :param content_type: the response's Content-Type.
                         'application/x-json-stream' by default.
    :returns: a flask.Response object with the specified Content-Type.
    """
    if not content_type:
        content_type = 'application/x-json-stream'

    it = iter(generator)
    try:
        peek = next(it)
        return Response(itertools.chain((peek,), it), content_type=content_type)
    except StopIteration:
        return Response('', content_type=content_type)
