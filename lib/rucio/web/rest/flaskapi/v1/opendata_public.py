# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from urllib.parse import unquote_plus

from flask import Blueprint, Flask, request

from rucio.common.exception import DataIdentifierNotFound, ScopeNotFound
from rucio.gateway import opendata
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, json_list, response_headers, try_stream


def _parse_scope_name(scope: str, name: str) -> (str, str):
    # At some point all methods will be updated to have the scope and name as separate parameters, for now just new files
    name = unquote_plus(name)
    return scope, name


class OpenDataPublicView(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        print(f"OpenDataPublicView.get() called")
        try:
            limit = request.args.get('limit', default=None)
            offset = request.args.get('offset', default=None)
            print(f"limit: {limit}, offset: {offset}")
            result = opendata.list_opendata_dids(limit=limit, offset=offset)
            print(f"result: {result}")
            return try_stream(json_list(result))
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (ScopeNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)


class OpenDataPublicDIDsView(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope: str, name: str):
        print(f"OpenDataPublicDIDsView.get() called")
        try:
            scope, name = _parse_scope_name(scope, name)
            return opendata.get_opendata_did(scope=scope, name=name)
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (ScopeNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)


def blueprint():
    bp = Blueprint("opendata_public", __name__, url_prefix='/opendata')

    opendata_public_view = OpenDataPublicView.as_view('opendata')
    bp.add_url_rule('', view_func=opendata_public_view, methods=['get'])

    opendata_private_did_view = OpenDataPublicDIDsView.as_view('opendata_did')
    bp.add_url_rule('/<scope>/<name>', view_func=opendata_private_did_view, methods=['get'])

    bp.after_request(response_headers)

    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
