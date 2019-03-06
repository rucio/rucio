#!/usr/bin/env python
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Wen Guan <wen.guan@cern.ch>, 2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
import traceback
from web import application, header, data, loadhook, unloadhook, InternalError, OK
# from web import application, ctx, header, data, loadhook, unloadhook, InternalError, found, OK

from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error, parse_response, render_json
from rucio.common import objectstore
from rucio.web.rest.common import rucio_loadhook, rucio_unloadhook, RucioController, check_accept_header_wrapper


URLS = ('/info/(.+)$', 'ObjectStoreInfo',
        '/rename/(.+)$', 'ObjectStoreRename',
        '/(.+)/(.+)/(.+)$', 'ObjectStoreGet',
        '/(.+)/(.+)$', 'ObjectStore')


class ObjectStoreGet(RucioController):

    @check_accept_header_wrapper(['text/plain'])
    def GET(self, url, rse, operation):
        """
        GET redirect URL.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            406 Not Acceptable
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

            if operation == 'connect':
                objectstore.connect(rse, url)
            else:
                result = objectstore.get_signed_urls([url], rse=rse, operation=operation)
                if isinstance(result[url], Exception):
                    raise result[url]
                return result[url]
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(traceback.format_exc())
            raise InternalError(error)
        raise OK()


class ObjectStore(RucioController):

    def POST(self, rse, operation):
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
            result = objectstore.get_signed_urls(parameters, rse=rse, operation=operation)
            for url in result:
                if isinstance(result[url], Exception):
                    raise result[url]
            return render_json(**result)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(traceback.format_exc())
            raise InternalError(error)


class ObjectStoreInfo(RucioController):

    def POST(self, rse):
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
            result = objectstore.get_metadata(parameters, rse=rse)
            for url in result:
                if isinstance(result[url], Exception):
                    raise result[url]
            return render_json(**result)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(traceback.format_exc())
            raise InternalError(error)


class ObjectStoreRename(RucioController):

    def POST(self, rse):
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
            objectstore.rename(url, new_url, rse=rse)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(traceback.format_exc())
            raise InternalError(error)

        raise OK()


# ----------------------
#   Web service startup
# ----------------------

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
APP.add_processor(unloadhook(rucio_unloadhook))
application = APP.wsgifunc()
