#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2020
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG

from web import application, ctx, data, Created, InternalError, loadhook, header

from rucio.api.meta import add_key, add_value, list_keys, list_values
from rucio.common.exception import Duplicate, InvalidValueForKey, KeyNotFound, UnsupportedValueType, RucioException, UnsupportedKeyType
from rucio.web.rest.common import rucio_loadhook, RucioController, check_accept_header_wrapper
from rucio.web.rest.utils import generate_http_error

LOGGER = getLogger("rucio.meta")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('/(.+)/(.+)', 'Values',
        '/(.+)/', 'Values',
        '/(.+)', 'Meta',
        '/', 'Meta',)


class Meta(RucioController):
    """ REST APIs for data identifier attribute keys. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self):
        """
        List all keys.

        HTTP Success:
            200 Success

        HTTP Error:
            406 Not Acceptable
        """
        header('Content-Type', 'application/json')
        return dumps(list_keys())

    def POST(self, key):
        """
        Create a new allowed key (value is NULL).

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :params Rucio-Account: account belonging to the new scope.
        """
        json_data = data().decode()
        try:
            params = json_data and loads(json_data)
            if params and 'value_type' in params:
                value_type = params['value_type']
            if params and 'value_regexp' in params:
                value_regexp = params['value_regexp']
            if params and 'key_type' in params:
                key_type = params['key_type']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_key(key=key, key_type=key_type, value_type=value_type, value_regexp=value_regexp, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except UnsupportedValueType as error:
            raise generate_http_error(400, 'UnsupportedValueType', error.args[0])
        except UnsupportedKeyType as error:
            raise generate_http_error(400, 'UnsupportedKeyType', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

        raise Created()


class Values(RucioController):
    """ REST APIs for data identifier attribute values. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, key):
        """
        List all values for a key.

        HTTP Success:
            200 Success
        HTTP Error:
            406 Not Acceptable
        """
        header('Content-Type', 'application/json')
        return dumps(list_values(key=key))

    def POST(self, key):
        """
        Create a new value for a key.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :params Rucio-Account: account belonging to the new scope.
        """
        json_data = data().decode()
        try:
            params = loads(json_data)
            value = params['value']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_value(key=key, value=value, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except Duplicate as error:
            raise generate_http_error(409, 'Duplicate', error.args[0])
        except InvalidValueForKey as error:
            raise generate_http_error(400, 'InvalidValueForKey', error.args[0])
        except KeyNotFound as error:
            raise generate_http_error(404, 'KeyNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
if __name__ != "rucio.web.rest.meta":
    application = APP.wsgifunc()
