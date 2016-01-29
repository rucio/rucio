#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2016

import traceback
from web import application, header, data, loadhook, unloadhook, InternalError, OK
# from web import application, ctx, header, data, loadhook, unloadhook, InternalError, found, OK

from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error, parse_response, render_json
from rucio.common import objectstore
from rucio.web.rest.common import rucio_loadhook, rucio_unloadhook, RucioController


urls = ('/info', 'ObjectStoreInfo',
        '/rename', 'ObjectStoreRename',
        '/([a-z]+)/(.+)$', 'ObjectStoreGet',
        '/(.+)$', 'ObjectStore')


class ObjectStoreGet(RucioController):

    def GET(self, operation, url):
        """
        GET redirect URL.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: A URL refering to the file.
        """

        # header('Access-Control-Allow-Origin', ctx.env.get('HTTP_ORIGIN'))
        # header('Access-Control-Allow-Headers', ctx.env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS'))
        # header('Access-Control-Allow-Methods', '*')
        # header('Access-Control-Allow-Credentials', 'true')

        try:
            pos = url.index('/')
            url = ''.join([url[:pos], '/', url[pos:]])

            result = objectstore.get_signed_urls([url], operation=operation)
            if isinstance(result[url], Exception):
                raise result[url]
            # return found(result[url])
            return result[url]
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print traceback.format_exc()
            raise InternalError(e)


class ObjectStore(RucioController):

    def GET(self, url):
        """
        Connect to the url.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :returns: OK.
        """
        header('Content-Type', 'application/json')

        try:
            pos = url.index('/')
            url = ''.join([url[:pos], '/', url[pos:]])

            objectstore.connect(url)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print traceback.format_exc()
            raise InternalError(e)

        raise OK()

    def POST(self, operation):
        """
        Get URLs for files at a given RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 Internal Error
        """
        header('Content-Type', 'application/json')
        json_data = data()
        try:
            parameters = parse_response(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            result = objectstore.get_signed_urls(parameters, operation=operation)
            for url in result:
                if isinstance(result[url], Exception):
                    raise result[url]
            return render_json(**result)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print traceback.format_exc()
            raise InternalError(e)


class ObjectStoreInfo(RucioController):

    def POST(self):
        """
        Get files metadata at a given RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 Internal Error
        """
        header('Content-Type', 'application/json')
        json_data = data()
        try:
            parameters = parse_response(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            result = objectstore.get_metadata(parameters)
            for url in result:
                if isinstance(result[url], Exception):
                    raise result[url]
            return render_json(**result)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print traceback.format_exc()
            raise InternalError(e)


class ObjectStoreRename(RucioController):

    def POST(self):
        """
        Get files metadata at a given RSE.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 Internal Error
        """
        header('Content-Type', 'application/json')
        json_data = data()
        try:
            parameters = parse_response(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            url = parameters['url']
            new_url = parameters['new_url']
            objectstore.rename(url, new_url)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print traceback.format_exc()
            raise InternalError(e)

        raise OK()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(rucio_loadhook))
app.add_processor(unloadhook(rucio_unloadhook))
application = app.wsgifunc()
