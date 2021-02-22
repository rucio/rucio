#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2020
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021

import json
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc

from web import application, ctx, data, Created, loadhook, header, InternalError

from rucio.api import config
from rucio.common.exception import ConfigurationError
from rucio.web.rest.common import rucio_loadhook, RucioController, exception_wrapper, check_accept_header_wrapper
from rucio.web.rest.utils import generate_http_error

LOGGER = getLogger("rucio.config")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('/(.+)/(.+)/(.*)', 'OptionSet',
        '/(.+)/(.+)', 'OptionGetDel',
        '/(.+)', 'Section',
        '', 'Config')


def _config_items_from_input(input_data):
    """
    extract section, option, value from a dict with format {section: {option: value}}.
    """
    try:
        for section, section_config in input_data.items():
            for option, value in section_config.items():
                return section, option, value
    except ValueError:
        return None, None, None
    return None, None, None


class Config(RucioController):
    """ REST API for full configuration. """

    @exception_wrapper
    @check_accept_header_wrapper(['application/json'])
    def GET(self):
        """
        List full configuration.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
        """

        header('Content-Type', 'application/json')

        res = {}
        for section in config.sections(issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo')):
            res[section] = {}
            for item in config.items(section, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo')):
                res[section][item[0]] = item[1]

        return json.dumps(res)

    @exception_wrapper
    def POST(self):
        """
        Set the value of an option.
        If the option does not exist, create it.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            400 The input data is invalid or incomplete
            500 ConfigurationError

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: 32 character hex string.
        """

        json_data = data().decode()
        try:
            input_data = json.loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter dictionary')

        section, option, value = _config_items_from_input(input_data)
        if section is None or option is None or value is None:
            raise generate_http_error(400, 'ValueError', 'Invalid input data')

        try:
            config.set(section=section, option=option, value=value, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except ConfigurationError:
            raise generate_http_error(500, 'ConfigurationError', 'Could not set value \'%s\' for section \'%s\' option \'%s\'' % (value, section, option))
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


class Section(RucioController):
    """ REST API for the sections in the configuration. """

    @exception_wrapper
    @check_accept_header_wrapper(['application/json'])
    def GET(self, section):
        """
        List configuration of a section

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
            404 NotFound
        """

        header('Content-Type', 'application/json')

        res = {}
        for item in config.items(section, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo')):
            res[item[0]] = item[1]

        if res == {}:
            raise generate_http_error(404, 'ConfigNotFound', 'No configuration found for section \'%s\'' % section)

        return json.dumps(res)


class OptionGetDel(RucioController):
    """ REST API for reading or deleting the options in the configuration. """

    @exception_wrapper
    @check_accept_header_wrapper(['application/json'])
    def GET(self, section, option):
        """
        Retrieve the value of an option.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: 32 character hex string.
        """

        try:
            return json.dumps(config.get(section=section, option=option, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo')))
        except:
            raise generate_http_error(404, 'ConfigNotFound', 'No configuration found for section \'%s\' option \'%s\'' % (section, option))

    @exception_wrapper
    def DELETE(self, section, option):
        """
        Delete an option.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: 32 character hex string.
        """

        config.remove_option(section=section, option=option, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))


class OptionSet(RucioController):
    """ REST API for setting the options in the configuration. """

    @exception_wrapper
    def PUT(self, section, option, value):
        """
        Set the value of an option.
        If the option does not exist, create it.
        TODO: remove this endpoint after migrating all clients to pass input data via a json body

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 ConfigurationError

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: 32 character hex string.
        """

        try:
            config.set(section=section, option=option, value=value, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except ConfigurationError:
            raise generate_http_error(500, 'ConfigurationError', 'Could not set value \'%s\' for section \'%s\' option \'%s\'' % (value, section, option))
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
if __name__ != "rucio.web.rest.config":
    application = APP.wsgifunc()
