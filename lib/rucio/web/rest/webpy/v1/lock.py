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
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from logging import getLogger, StreamHandler, DEBUG
try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs
from web import application, ctx, header, InternalError, loadhook

from rucio.api.lock import get_dataset_locks_by_rse, get_dataset_locks
from rucio.common.exception import RucioException, RSENotFound
from rucio.common.schema import SCOPE_NAME_REGEXP
from rucio.common.utils import generate_http_error, render_json
from rucio.web.rest.common import rucio_loadhook, check_accept_header_wrapper

LOGGER = getLogger("rucio.lock")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('%s' % SCOPE_NAME_REGEXP, 'LockByScopeName',
        '/(.*)', 'LockByRSE')


class LockByRSE(object):
    """ REST APIs for dataset locks. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, rse):
        """ get locks for a given rse.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
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
        except RSENotFound as error:
            raise generate_http_error(404, error.__class__.__name__, error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)


class LockByScopeName(object):
    """ REST APIs for dataset locks. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """ get locks for a given scope, name.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
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
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
