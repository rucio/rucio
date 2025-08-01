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

from flask import Blueprint, Flask, Response, jsonify

from rucio.common.config import config_get_int
from rucio.gateway.token_issuer import jwks, openid_config_resource
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask


class JWKS(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self) -> Response:
        """
        ---
        summary: jwks info
        description: get jwks info.
        responses:
          200:
            description: OK
          500:
            description: Internal Server Error
        """
        try:
            res_jwks = jwks()
        except ValueError as error:
            generate_http_error_flask(500, str(error))
        response = jsonify(res_jwks)
        jwks_cache_lifetime = config_get_int('oidc', 'jwks_cache_lifetime', raise_exception=False, default=21600)
        response.headers['Cache-Control'] = f'public, max-age={jwks_cache_lifetime}'
        return response


class OPENID_WELLKNOWN(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self) -> Response:
        """
        ---
        summary: jwks info
        description: get jwks info.
        responses:
          200:
            description: OK
          500:
            description: Internal Server Error
        """
        try:
            res = openid_config_resource()
        except ValueError as error:
            generate_http_error_flask(500, str(error))
        return jsonify(res)


def blueprint() -> Blueprint:
    public_bp = Blueprint('token_issuer', __name__)

    # Register JWKS view at /jwks
    jwks_view = JWKS.as_view('jwks')
    public_bp.add_url_rule('/jwks', view_func=jwks_view, methods=['GET'])

    # Register OPENID_WELLKNOWN view at /.well-known/openid-configuration
    wellknown_view = OPENID_WELLKNOWN.as_view('openid_wellknown')
    public_bp.add_url_rule('/.well-known/openid-configuration', view_func=wellknown_view, methods=['GET'])
    return public_bp


def make_doc() -> Flask:
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
