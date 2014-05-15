# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""
REST utilities
"""

from json import loads
from traceback import format_exc
from web import BadRequest, ctx, data, header, InternalError
from web.webapi import Created, HTTPError, OK, seeother

from rucio.api.authentication import validate_auth_token
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error


def authenticate():
    """ Hook to authenticate. """

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
    except RucioException, e:
        raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
    except Exception, e:
        print format_exc()
        raise InternalError(e)

    if auth is None:
        raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

    # Propagate the issuer to the controller
    ctx.env['issuer'] = auth.get('account')


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
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print type(e)
            print format_exc()
            raise InternalError(e)
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
