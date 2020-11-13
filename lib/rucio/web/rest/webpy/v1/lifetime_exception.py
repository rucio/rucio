#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2016-2020 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2016-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from json import loads, dumps

from web import application, ctx, data, header, BadRequest, Created, InternalError, loadhook

from rucio.api.lifetime_exception import list_exceptions, add_exception, update_exception
from rucio.common.exception import LifetimeExceptionNotFound, UnsupportedOperation, InvalidObject, RucioException, AccessDenied, LifetimeExceptionDuplicate
from rucio.common.utils import APIEncoder
from rucio.web.rest.common import rucio_loadhook, check_accept_header_wrapper
from rucio.web.rest.utils import generate_http_error

URLS = ('/', 'LifetimeException',
        '/(.+)', 'LifetimeExceptionId',)


class LifetimeException:
    """ REST APIs for Lifetime Model exception. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """
        Retrieve all exceptions.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 Internal Error

        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for exception in list_exceptions(vo=ctx.env.get('vo')):
                yield dumps(exception, cls=APIEncoder) + '\n'
        except LifetimeExceptionNotFound as error:
            raise generate_http_error(404, 'LifetimeExceptionNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

    def POST(self):
        """
        Create a new Lifetime Model exception.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            409 Conflict
            500 Internal Error
        """
        json_data = data()
        dids, pattern, comments, expires_at = [], None, None, None
        try:
            params = loads(json_data)
            if 'dids' in params:
                dids = params['dids']
            if 'pattern' in params:
                pattern = params['pattern']
            if 'comments' in params:
                comments = params['comments']
            if 'expires_at' in params:
                expires_at = params['expires_at']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            exception_id = add_exception(dids=dids, account=ctx.env.get('issuer'), vo=ctx.env.get('vo'),
                                         pattern=pattern, comments=comments, expires_at=expires_at)
        except InvalidObject as error:
            raise generate_http_error(400, 'InvalidObject', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except LifetimeExceptionDuplicate as error:
            raise generate_http_error(409, 'LifetimeExceptionDuplicate', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)
        raise Created(dumps(exception_id))


class LifetimeExceptionId:
    """ REST APIs for Lifetime Model exception. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, exception_id):
        """
        Retrieve an exception.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 Internal Error

        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for exception in list_exceptions(exception_id, vo=ctx.env.get('vo')):
                yield dumps(exception, cls=APIEncoder) + '\n'

        except LifetimeExceptionNotFound as error:
            raise generate_http_error(404, 'LifetimeExceptionNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

    def PUT(self, exception_id):
        """
        Approve/Reject an execption.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            500 Internal Error
        """
        json_data = data()
        try:
            params = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')
        try:
            state = params['state']
        except KeyError:
            state = None
        try:
            update_exception(exception_id=exception_id, state=state, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except UnsupportedOperation as error:
            raise generate_http_error(400, 'UnsupportedOperation', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except LifetimeExceptionNotFound as error:
            raise generate_http_error(404, 'LifetimeExceptionNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)
        raise Created()

    def DELETE(self):
        raise BadRequest()


"""
----------------------
   Web service startup
----------------------
"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
if __name__ != "rucio.web.rest.lifetime_exception":
    application = APP.wsgifunc()
