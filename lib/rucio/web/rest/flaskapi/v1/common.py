# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

"""
FLASK REST utilities
"""

from flask import request
from time import time
from traceback import format_exc

from rucio.api.authentication import validate_auth_token
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error_flask, generate_uuid


def before_request():
    if request.environ.get('REQUEST_METHOD') == 'OPTIONS':
        raise "", 200

    auth_token = request.environ.get('HTTP_X_RUCIO_AUTH_TOKEN')

    try:
        auth = validate_auth_token(auth_token)
    except RucioException, e:
        return generate_http_error_flask(500, e.__class__.__name__, e.args[0][0])
    except Exception, e:
        print format_exc()
        return e, 500

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
