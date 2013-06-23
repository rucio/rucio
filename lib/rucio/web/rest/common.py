# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

"""
REST utilities
"""

from web import ctx, header, InternalError
from traceback import format_exc

from rucio.api.authentication import validate_auth_token
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error


def authenticate():
    """ Hook to authenticate
    """
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
