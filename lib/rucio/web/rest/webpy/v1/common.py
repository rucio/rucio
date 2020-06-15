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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function
from json import loads
from time import time
from traceback import format_exc
from web import BadRequest, ctx, data, header, InternalError
from web.webapi import Created, HTTPError, OK, seeother

from rucio.api.authentication import validate_auth_token
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error, generate_uuid
from rucio.core.monitor import record_timer


def rucio_loadhook():
    """ Rucio load Hook to authenticate, timing, etc. """

    # Allow cross-site scripting
    header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
    header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
    header('Access-Control-Allow-Methods', '*')
    header('Access-Control-Allow-Credentials', 'true')

    if ctx.env.get('REQUEST_METHOD') == 'OPTIONS':
        raise OK

    if ctx.env.get('REQUEST_METHOD') == 'GET':
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')
    else:
        header('Content-Type', 'application/octet-stream')

    auth_token = ctx.env.get('HTTP_X_RUCIO_AUTH_TOKEN')
    try:
        auth = validate_auth_token(auth_token)
    except RucioException as error:
        raise generate_http_error(500, error.__class__.__name__, error.args[0])
    except Exception as error:
        print(format_exc())
        raise InternalError(error)

    if auth is None:
        raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

    # Propagate the issuer, request_id and start_time to the controller
    ctx.env['vo'] = auth.get('vo', 'def')
    ctx.env['issuer'] = auth.get('account')
    ctx.env['identity'] = auth.get('identity')
    ctx.env['request_id'] = generate_uuid()
    ctx.env['start_time'] = time()


def rucio_unloadhook():
    """ Rucio unload Hook."""
    duration = time() - ctx.env['start_time']
    ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
    if not ip:
        ip = ctx.ip
    # print ctx.env.get('request_id'), ctx.env.get('REQUEST_METHOD'), ctx.env.get('REQUEST_URI'), ctx.data, duration, ctx.env.get('issuer'), ip
    # Record a time serie for each REST operations
    time_serie_name = '.'.join(('http', 'methods', ctx.env.get('REQUEST_METHOD'), 'resources.'))
    time_serie_name += '.'.join(list(filter(None, ctx.env.get('SCRIPT_NAME').split('/')))[:4])
    if ctx.path == '/list':
        time_serie_name += '.list'
    time_serie_name = time_serie_name.replace('..', '.').lower()
    record_timer(time_serie_name, duration * 1000)


def load_json_data():
    """ Hook to load json data. """
    json_data = data()
    try:
        ctx.env['parameters'] = json_data and loads(json_data)
    except ValueError:
        raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary/list')


def exception_wrapper(f):
    """ Decorator to catch exception. """
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (Created, HTTPError, OK, seeother):
            raise
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(type(error))
            print(format_exc())
            raise InternalError(error)
    return decorated


class RucioController:
    """ Default Rucio Controller class. """

    def POST(self):
        """ Not supported. """
        raise BadRequest()

    def GET(self):
        """ Not supported. """
        raise BadRequest()

    def PUT(self):
        """ Not supported. """
        raise BadRequest()

    def DELETE(self):
        """ Not supported. """
        raise BadRequest()


def check_accept_header_wrapper(supported_content_types):
    """ Decorator to check if an endpoint supports the requested content type. """
    def wrapper(f):
        def decorated(*args, **kwargs):
            requested_content_type = ctx.env.get('HTTP_ACCEPT')
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
                raise generate_http_error(406, 'UnsupportedRequestedContentType', 'The requested content type %s is not supported. Use %s.' % (requested_content_type, ','.join(supported_content_types)))
            return f(*args, **kwargs)
        return decorated
    return wrapper
