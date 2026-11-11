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

from typing import TYPE_CHECKING

from flask import Flask, jsonify
from flask import request as request

from rucio.common.constants import HTTPMethod
from rucio.gateway import policy
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, response_headers

if TYPE_CHECKING:
    from flask.typing import ResponseReturnValue


class PolicyAlgorithms(ErrorHandlingMethodView):
    """ REST API to discover the policy package algorithms available to a VO. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self) -> 'ResponseReturnValue':
        """
        ---
        summary: List
        description: "List the policy package algorithms registered for the requested VO."
        tags:
          - Plugins
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  description: "A dict with the algorithm types as keys and a dict with the names of the registered algorithms and the default algorithm as value."
                  type: object
          401:
            description: "Invalid Auth Token"
          406:
            description: "Not acceptable"
        """
        res = policy.list_policy_algorithms(issuer=request.environ['issuer'], vo=request.environ['vo'])
        return jsonify(res), 200


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint('plugins', __name__, url_prefix='/plugins')

    policy_algorithms_view = PolicyAlgorithms.as_view('policy_algorithms')
    bp.add_url_rule('/algorithms', view_func=policy_algorithms_view, methods=[HTTPMethod.GET.value])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
