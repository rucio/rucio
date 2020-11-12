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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

from json import loads
from traceback import format_exc

from web import application, ctx, data, Created, InternalError, loadhook

from rucio.api.temporary_did import (add_temporary_dids)
from rucio.common.exception import RucioException
from rucio.web.rest.common import rucio_loadhook, RucioController
from rucio.web.rest.utils import generate_http_error

URLS = ('', 'BulkDIDS',)


class BulkDIDS(RucioController):

    def POST(self):
        json_data = data()
        try:
            dids = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_temporary_dids(dids=dids, issuer=ctx.env.get('issuer'), vo=ctx.env.get('vo'))
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)
        raise Created()


class Compose(RucioController):

    def POST(self):
        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
if __name__ != "rucio.web.rest.temporary_did":
    application = APP.wsgifunc()
