#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014-2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

from traceback import format_exc
from urlparse import parse_qs
from web import application, ctx, header, notfound, found, InternalError


from logging import getLogger, StreamHandler, DEBUG

from rucio.api.replica import list_replicas
from rucio.common import objectstore
from rucio.common.exception import RucioException
from rucio.common.replicas_selector import random_order, geoIP_order, site_selector
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
        Redirect download

        HTTP Success:
            303 See Other

        HTTP Error:
            401 Unauthorized
            500 InternalError
            404 Notfound

        :param scope: The scope name of the file.
        :param name: The name of the file.
        """

        header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        header('Access-Control-Allow-Methods', '*')
        header('Access-Control-Allow-Credentials', 'true')

        try:
            replicas = [r for r in list_replicas(dids=[{'scope': scope, 'name': name, 'type': 'FILE'}], schemes=['http', 'https', 's3+rucio'])]

            select, rse, site = 'random', None, None
            if ctx.query:
                params = parse_qs(ctx.query[1:])
                if 'select' in params:
                    select = params['select'][0]
                if 'rse' in params:
                    rse = params['rse'][0]
                if 'site' in params:
                    site = params['site'][0]

            selected_url, selected_rse = None, None
            for r in replicas:
                if r['rses']:
                    replicadict = {}
                    if rse:
                        if rse in r['rses'] and r['rses'][rse]:
                            selected_url = r['rses'][rse][0]
                            selected_rse = rse
                        else:
                            return notfound("Sorry, the replica you were looking for was not found.")
                    else:

                        for rep in r['rses']:
                            for replica in r['rses'][rep]:
                                replicadict[replica] = rep

                        if not replicadict:
                            return notfound("Sorry, the replica you were looking for was not found.")

                        elif site:
                            rep = site_selector(replicadict, site)
                            if rep:
                                selected_url = rep[0]
                            else:
                                return notfound("Sorry, the replica you were looking for was not found.")
                        else:
                            client_ip = ctx.env.get('HTTP_X_FORWARDED_FOR')
                            if client_ip is None:
                                client_ip = ctx.ip
                            if select == 'geoip':
                                rep = geoIP_order(replicadict, client_ip)
                            else:
                                rep = random_order(replicadict, client_ip)

                            selected_url = rep[0]

                        for rep in r['rses']:
                            for replica in r['rses'][rep]:
                                if selected_url == replica:
                                    selected_rse = rep

            if selected_url:
                if selected_url.startswith('s3+rucio://'):
                    objectstore.connect(selected_rse, selected_url)
                    signed_urls = objectstore.get_signed_urls([selected_url],
                                                              rse=selected_rse,
                                                              operation='read')
                    return found(signed_urls[selected_url])

                return found(selected_url)

            return notfound("Sorry, the replica you were looking for was not found.")

        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
