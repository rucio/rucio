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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
import traceback
from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.common.exception import RucioException
from rucio.common.utils import generate_http_error_flask, parse_response, render_json
from rucio.common import objectstore
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask


class ObjectStoreGet(MethodView):

    @check_accept_header_wrapper_flask(['text/plain'])
    def get(self, url, rse, operation):
        """
        Pass a url and return the signed url.

        .. :quickref: ObjectStoreGet; get signed url.

        :param url: A URL string.
        :param rse: RSE name.
        :param operation: the request operation (default: 'read').
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :status 500: Internal Error.
        :returns: the signed URL.
        get redirect URL.
        """
        try:
            pos = url.index('/')
            url = ''.join([url[:pos], '/', url[pos:]])

            if operation == 'connect':
                objectstore.connect(rse, url)
            else:
                result = objectstore.get_signed_urls([url], rse=rse, operation=operation)
                if isinstance(result[url], Exception):
                    return Response(result[url])
                return Response(result[url])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(traceback.format_exc())
            return error, 500
        return "OK"


class ObjectStore(MethodView):

    def post(self, rse, operation):
        """
        Get URLs for files at a given RSE.

        .. :quickref: ObjectStore; get signed urls.

        :param rse: RSE name.
        :param operation: the request operation (default: 'read').
        :<json string urls: A list of URL strings.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        :returns: Dictionary of Signed URLs.
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            result = objectstore.get_signed_urls(parameters, rse=rse, operation=operation)
            for url in result:
                if isinstance(result[url], Exception):
                    return Response(result[url])
            return Response(render_json(**result), content_type="application/json")
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(traceback.format_exc())
            return error, 500


class ObjectStoreInfo(MethodView):

    def post(self, rse):
        """
        Pass list of urls and return their metadata.

        .. :quickref: ObjectStoreInfo; Get files metadata at a given RSE.

        :param rse: RSE name.
        :<json string urls: A list of URL string.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        :returns: Dictonary of metadata.
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            result = objectstore.get_metadata(parameters, rse=rse)
            for url in result:
                if isinstance(result[url], Exception):
                    return Response(result[url])
            return Response(render_json(**result), content_type="application/json")
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(traceback.format_exc())
            return error, 500


class ObjectStoreRename(MethodView):

    def post(self, rse):
        """
        Rename object.

        .. :quickref: ObjectStoreRename; Rename object.

        :param rse: the RSE name.
        :<json string url: the URL string.
        :<json string new_url: the new URL string.
        :<json string urls: A list of URL string.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        """
        json_data = request.data
        try:
            parameters = parse_response(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            url = parameters['url']
            new_url = parameters['new_url']
            objectstore.rename(url, new_url, rse=rse)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(traceback.format_exc())
            return error, 500

        return "OK", 200


# ----------------------
#   Web service startup
# ----------------------
bp = Blueprint('objectstore', __name__)

object_store_get_view = ObjectStoreGet.as_view('object_store_get')
bp.add_url_rule('/<url>/<rse>/<operation>', view_func=object_store_get_view, methods=['get', ])
object_store_view = ObjectStore.as_view('object_store')
bp.add_url_rule('/<rse>/<operation>', view_func=object_store_view, methods=['post', ])
object_store_info_view = ObjectStoreInfo.as_view('object_store_info')
bp.add_url_rule('/<rse>', view_func=object_store_info_view, methods=['post', ])
object_store_rename_view = ObjectStoreRename.as_view('object_store_rename')
bp.add_url_rule('/<rse>', view_func=object_store_rename_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/objectstores')
    return doc_app


if __name__ == "__main__":
    application.run()
