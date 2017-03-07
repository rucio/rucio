#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014


from logging import getLogger, StreamHandler, DEBUG
from urlparse import parse_qs
from web import application, ctx, header, InternalError, loadhook

from rucio.api.lock import get_dataset_locks_by_rse, get_dataset_locks
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error, render_json
from rucio.web.rest.common import rucio_loadhook

LOGGER = getLogger("rucio.lock")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('/(.*)/(.*)', 'LockByScopeName',
        '/(.*)', 'LockByRSE')


class LockByRSE(object):
    """ REST APIs for dataset locks. """

    def GET(self, rse):
        """ get locks for a given rse.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        did_type = None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'did_type' in params:
                did_type = params['did_type'][0]
        try:
            if did_type == 'dataset':
                for lock in get_dataset_locks_by_rse(rse):
                    yield render_json(**lock) + '\n'
            else:
                raise InternalError('Wrong did_type specified')
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            raise InternalError(error)


class LockByScopeName(object):
    """ REST APIs for dataset locks. """

    def GET(self, scope, name):
        """ get locks for a given scope, name.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        did_type = None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'did_type' in params:
                did_type = params['did_type'][0]
        try:
            if did_type == 'dataset':
                for lock in get_dataset_locks(scope, name):
                    yield render_json(**lock) + '\n'
            else:
                raise InternalError('Wrong did_type specified')
        except RucioException, error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception, error:
            raise InternalError(error)


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
