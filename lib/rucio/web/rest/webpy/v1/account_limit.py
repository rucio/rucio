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
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2019
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

from json import loads
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc

from web import application, loadhook, ctx, data, Created, InternalError, OK

from rucio.api.account_limit import set_local_account_limit, delete_local_account_limit, set_global_account_limit, delete_global_account_limit
from rucio.common.exception import RSENotFound, AccessDenied, AccountNotFound
from rucio.web.rest.common import rucio_loadhook, RucioController
from rucio.web.rest.utils import generate_http_error

LOGGER = getLogger("rucio.account_limit")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = (
    '/local/(.+)/(.+)', 'LocalAccountLimit',
    '/global/(.+)/(.+)', 'GlobalAccountLimit',
    '/(.+)/(.+)', 'LocalAccountLimit',
)


class LocalAccountLimit(RucioController):
    '''
    AccountLimit
    '''
    def POST(self, account, rse):
        """ Create or update an account limit.
        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            500 Internal Error

        :param X-Rucio-Auth-Account: Account identifier.
        :param X-Rucio-Auth-Token:   As an 32 character hex string.
        :param account:              Account name.
        :param rse:                  RSE name.
        """
        json_data = data()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')
        try:
            bytes = parameter['bytes']
        except KeyError as exception:
            if exception.args[0] == 'type':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(exception))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            set_local_account_limit(account=account, rse=rse, bytes=bytes, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as exception:
            raise generate_http_error(401, 'AccessDenied', exception.args[0])
        except RSENotFound as exception:
            raise generate_http_error(404, 'RSENotFound', exception.args[0])
        except AccountNotFound as exception:
            raise generate_http_error(404, 'AccountNotFound', exception.args[0])
        except Exception as exception:
            print(format_exc())
            raise InternalError(exception)

        raise Created()

    def DELETE(self, account, rse):
        """ Delete an account limit.
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 Internal Error

        :param X-Rucio-Auth-Account: Account identifier.
        :param X-Rucio-Auth-Token:   As an 32 character hex string.
        :param account:              Account name.
        :param rse:                  RSE name.
        """
        try:
            delete_local_account_limit(account=account, rse=rse, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as exception:
            raise generate_http_error(401, 'AccessDenied', exception.args[0])
        except AccountNotFound as exception:
            raise generate_http_error(404, 'AccountNotFound', exception.args[0])
        except RSENotFound as exception:
            raise generate_http_error(404, 'RSENotFound', exception.args[0])
        except Exception as exception:
            print(format_exc())
            raise InternalError(exception)
        raise OK()


class GlobalAccountLimit(RucioController):
    '''
    AccountLimit
    '''
    def POST(self, account, rse_expression):
        """ Create or update an account limit.
        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            500 Internal Error

        :param X-Rucio-Auth-Account: Account identifier.
        :param X-Rucio-Auth-Token:   As an 32 character hex string.
        :param account:              Account name.
        :param rse_expression:       RSE expression.
        """
        json_data = data()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')
        try:
            bytes = parameter['bytes']
        except KeyError as exception:
            if exception.args[0] == 'type':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(exception))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            set_global_account_limit(account=account, rse_expression=rse_expression, bytes=bytes, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as exception:
            raise generate_http_error(401, 'AccessDenied', exception.args[0])
        except RSENotFound as exception:
            raise generate_http_error(404, 'RSENotFound', exception.args[0])
        except AccountNotFound as exception:
            raise generate_http_error(404, 'AccountNotFound', exception.args[0])
        except Exception as exception:
            print(format_exc())
            raise InternalError(exception)

        raise Created()

    def DELETE(self, account, rse_expression):
        """ Delete an account limit.
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 Internal Error

        :param X-Rucio-Auth-Account: Account identifier.
        :param X-Rucio-Auth-Token:   As an 32 character hex string.
        :param account:              Account name.
        :param rse_expression:       RSE expression.
        """
        try:
            delete_global_account_limit(account=account, rse_expression=rse_expression, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except AccessDenied as exception:
            raise generate_http_error(401, 'AccessDenied', exception.args[0])
        except AccountNotFound as exception:
            raise generate_http_error(404, 'AccountNotFound', exception.args[0])
        except RSENotFound as exception:
            raise generate_http_error(404, 'RSENotFound', exception.args[0])
        except Exception as exception:
            print(format_exc())
            raise InternalError(exception)
        raise OK()

# ----------------------
#   Web service startup
# ----------------------


APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
if __name__ != "rucio.web.rest.account_limit":
    application = APP.wsgifunc()
