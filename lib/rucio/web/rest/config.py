#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

import json

from logging import getLogger, StreamHandler, DEBUG

from web import application, ctx, Created, loadhook, header

from rucio.api import config
from rucio.common.utils import generate_http_error
from rucio.web.rest.common import rucio_loadhook, RucioController, exception_wrapper


logger = getLogger("rucio.config")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/(.+)/(.+)/(.*)', 'OptionSet',
        '/(.+)/(.+)', 'OptionGetDel',
        '/(.+)', 'Section',
        '', 'Config')


class Config(RucioController):
    """ REST API for full configuration. """

    @exception_wrapper
    def GET(self):
        """
        List full configuration.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
        """

        header('Content-Type', 'application/json')

        res = {}
        for section in config.sections(issuer=ctx.env.get('issuer')):
            res[section] = {}
            for item in config.items(section, issuer=ctx.env.get('issuer')):
                res[section][item[0]] = item[1]

        return json.dumps(res)


class Section(RucioController):
    """ REST API for the sections in the configuration. """

    @exception_wrapper
    def GET(self, section):
        """
        List configuration of a section

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 NotFound
        """

        header('Content-Type', 'application/json')

        res = {}
        for item in config.items(section, issuer=ctx.env.get('issuer')):
            res[item[0]] = item[1]

        if res == {}:
            raise generate_http_error(404, 'ConfigNotFound', 'No configuration found for section \'%s\'' % section)

        return json.dumps(res)


class OptionGetDel(RucioController):
    """ REST API for reading or deleting the options in the configuration. """

    @exception_wrapper
    def GET(self, section, option):
        """
        Retrieve the value of an option.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: 32 character hex string.
        """

        try:
            return json.dumps(config.get(section=section, option=option, issuer=ctx.env.get('issuer')))
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

        config.remove_option(section=section, option=option, issuer=ctx.env.get('issuer'))


class OptionSet(RucioController):
    """ REST API for setting the options in the configuration. """

    @exception_wrapper
    def PUT(self, section, option, value):
        """
        Set the value of an option.
        If the option does not exist, create it.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 ConfigurationError

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: 32 character hex string.
        """

        try:
            config.set(section=section, option=option, value=value, issuer=ctx.env.get('issuer'))
        except:
            raise generate_http_error(500, 'ConfigurationError', 'Could not set value \'%s\' for section \'%s\' option \'%s\'' % (value, section, option))
        raise Created()

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(rucio_loadhook))
application = app.wsgifunc()
