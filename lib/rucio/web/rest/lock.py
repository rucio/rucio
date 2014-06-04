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
from json import dumps
from urlparse import parse_qs
from web import application, ctx, header, InternalError, loadhook

from rucio.api.lock import get_dataset_locks_by_rse, get_dataset_locks
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error, APIEncoder
from rucio.web.rest.common import authenticate

logger = getLogger("rucio.lock")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/(.*)/', 'LockByRSE',
        '/(.*)/(.*)', 'LockByScopeName',)


class LockByRSE:
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
        header('Content-Type', 'application/json')
        did_type = None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'did_type' in params:
                did_type = params['did_type'][0]

        try:
            if did_type == 'dataset':
                locks = get_dataset_locks_by_rse(rse)
            else:
                raise InternalError('Wrong did_type specified')
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            raise InternalError(e)

        for lock in locks:
            yield dumps(lock, cls=APIEncoder) + '\n'


class LockByScopeName:
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
        header('Content-Type', 'application/json')
        did_type = None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'did_type' in params:
                did_type = params['did_type'][0]

        try:
            if did_type == 'dataset':
                locks = get_dataset_locks(scope, name)
            else:
                raise InternalError('Wrong did_type specified')
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            raise InternalError(e)

        for lock in locks:
            yield dumps(lock, cls=APIEncoder) + '\n'


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(authenticate))
application = app.wsgifunc()
