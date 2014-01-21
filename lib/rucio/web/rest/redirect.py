#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014

from random import choice
from traceback import format_exc

from web import application, notfound, seeother, InternalError


from logging import getLogger, StreamHandler, DEBUG

from rucio.api.replica import list_replicas
from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error
from rucio.web.rest.common import RucioController


logger = getLogger("rucio.rucio")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/(.*)/(.*)/?$', 'Redirector')


class Redirector(RucioController):

    def GET(self, scope, name):
        """
        Redirect donwload

        HTTP Success:
            303 See Other

        HTTP Error:
            401 Unauthorized
            500 InternalError
            404 Notfound

        :param scope: The scope name of the file.
        :param name: The name of the file.
        """
        try:
            replicas = [r for r in list_replicas(dids=[{'scope': scope, 'name': name, 'type': 'F'}], schemes=['http', 'https'])]

            # Select randomly a replica
            # Todo: geoip on client ip ctx.ip
            for r in replicas:
                if r['rses']:
                    rse = choice(r['rses'].keys())
                    raise seeother(r['rses'][rse][0])

            return notfound("Sorry, the replica you were looking for was not found.")

        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except seeother:
            raise
        except Exception, e:
            print format_exc()
            raise InternalError(e)

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
# app.add_processor(loadhook(authenticate))
application = app.wsgifunc()
