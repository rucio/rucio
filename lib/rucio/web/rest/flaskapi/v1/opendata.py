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

from json import dumps

from urllib.parse import unquote_plus
from flask import Blueprint, Flask, Response, request

from rucio.common.exception import (
    AccessDenied,
    DatabaseException,
    DataIdentifierAlreadyExists,
    DataIdentifierNotFound,
    Duplicate,
    DuplicateContent,
    FileAlreadyExists,
    FileConsistencyMismatch,
    InvalidMetadata,
    InvalidObject,
    InvalidPath,
    InvalidValueForKey,
    KeyNotFound,
    RSENotFound,
    RuleNotFound,
    ScopeNotFound,
    UnsupportedMetadataPlugin,
    UnsupportedOperation,
    UnsupportedStatus,
)
from rucio.common.utils import APIEncoder, parse_response, render_json
from rucio.db.sqla.constants import DIDType
from rucio.gateway import opendata
from rucio.gateway.rule import list_associated_replication_rules_for_file, list_replication_rules
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, \
    generate_http_error_flask, json_list, json_parameters, json_parse, param_get, parse_scope_name, response_headers, \
    try_stream


def _parse_scope_name(scope: str, name: str) -> (str, str):
    # At some point all methods will be updated to have the scope and name as separate parameters, for now just new files
    name = unquote_plus(name)
    return scope, name


class OpenDataList(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        print(f"OpenDataList.get() called")
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


class OpenDataDIDs(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, scope: str, name: str):
        try:
            scope, name = _parse_scope_name(scope, name)
            return opendata.get_opendata_did(scope=scope, name=name)
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (ScopeNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)

    def post(self, scope: str, name: str):
        try:
            scope, name = _parse_scope_name(scope, name)
            opendata.add_opendata_did(scope=scope, name=name)
        except ValueError as error:
            return generate_http_error_flask(400, error)

        return "Created", 201

    def put(self, scope: str, name: str):
        try:
            scope, name = _parse_scope_name(scope, name)
            raise NotImplementedError("PUT is not implemented yet for OpenDataDIDs")
        except ValueError as error:
            return generate_http_error_flask(400, error)

        return "", 200

    def delete(self, scope: str, name: str):
        try:
            scope, name = _parse_scope_name(scope, name)
            opendata.delete_opendata_did(scope=scope, name=name)
        except ValueError as error:
            return generate_http_error_flask(400, error)
        except (ScopeNotFound, DataIdentifierNotFound) as error:
            return generate_http_error_flask(404, error)

        return "", 200


def blueprint():
    # Some methods need to be behind auth, some need to be public
    bp = Blueprint('opendata', __name__, url_prefix='/opendata')
    # bp2 = AuthenticatedBlueprint('opendata', __name__, url_prefix='/opendata')

    opendata_list_view = OpenDataList.as_view('opendata_list')
    bp.add_url_rule('', view_func=opendata_list_view, methods=['get'])

    opendata_view = OpenDataDIDs.as_view('opendata')
    bp.add_url_rule('/<scope>/<name>', view_func=opendata_view, methods=['get', 'post', 'put', 'delete'])

    bp.after_request(response_headers)

    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
