#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2016

from json import loads
from traceback import format_exc
from web import application, ctx, data, Created, InternalError, loadhook

from rucio.api.temporary_did import (add_temporary_dids)
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error

from rucio.web.rest.common import rucio_loadhook, RucioController

URLS = ('', 'BulkDIDS',)


class BulkDIDS(RucioController):

    def POST(self):
        json_data = data()
        try:
            dids = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_temporary_dids(dids=dids, issuer=ctx.env.get('issuer'))
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)
        raise Created()


class Compose(RucioController):

    def POST(self):
        raise Created()


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
