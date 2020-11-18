#!/usr/bin/env python3
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
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - James Perry <j.perry@epcc.ed.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from logging import getLogger, StreamHandler, DEBUG

from web import application, ctx, header, InternalError, loadhook

from rucio.api.lock import get_dataset_locks_by_rse, get_dataset_locks
from rucio.common.exception import RucioException, RSENotFound
from rucio.common.schema import insert_scope_name
from rucio.common.utils import render_json
from rucio.web.rest.common import rucio_loadhook, check_accept_header_wrapper
from rucio.web.rest.utils import generate_http_error

try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs

LOGGER = getLogger("rucio.lock")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = insert_scope_name(('%s', 'LockByScopeName',
                          '/(.*)', 'LockByRSE'))


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
                for lock in get_dataset_locks_by_rse(rse, vo=ctx.env.get('vo')):
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
                for lock in get_dataset_locks(scope, name, vo=ctx.env.get('vo')):
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
if __name__ != "rucio.web.rest.lock":
    application = APP.wsgifunc()
