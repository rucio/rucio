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

from flask import Flask, request, Response
from typing import Union

from rucio.common.exception import (
    AccessDenied,
    DuplicateLoadInjectionPlan,
    NoLoadInjectionPlanFound,
)

from rucio.gateway.loadinjection import (
    add_load_injection_plans,
    get_load_injection_plans,
    get_load_injection_plan,
    delete_load_injection_plan,
)
from rucio.common.utils import render_json
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import (
    ErrorHandlingMethodView,
    check_accept_header_wrapper_flask,
    generate_http_error_flask,
    json_list,
    response_headers,
    try_stream,
)


class Plans(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(["application/json"])
    def post(self):
        """
        ---
        summary: Add load injection plans bulk
        description: Add new load injection plans in bulk
        tags:
          - Load Injection Plans
        requestBody:
          content:
            application/json:
              schema:
                type: array
                items:
                  description: One plan to add.
                  type: object
                  required:
                    - src_rse
                    - dest_rse
                    - inject_rate
                    - start_time
                    - end_time
                    - comments
                    - interval
                    - fudge
                    - max_injection
                    - expiration_delay
                    - rule_lifetime
                    - big_first
                    - dry_run
                  properties:
                    src_rse:
                      description: Source RSE name
                      type: string
                    dest_rse:
                      description: Destination RSE name
                      type: string
                    inject_rate:
                      description: Injection rate in MB/s
                      type: integer
                    start_time:
                      description: Start time of the injection plan
                      type: string
                    end_time:
                      description: End time of the injection plan
                      type: string
                    comments:
                      description: Comments for the injection plan
                      type: string
                    interval:
                      description: Time interval between injections in seconds
                      type: integer
                    fudge:
                      description: Fudge factor for the injection plan
                      type: float
                    max_injection:
                      description: Maximum injection rate
                      type: float
                    expiration_delay:
                      description: Expiration delay for the injection plan
                      type: integer
                    rule_lifetime:
                      description: Rule lifetime for the injection plan
                      type: integer
                    big_first:
                      description: Big first flag for the injection plan
                      type: boolean
                    dry_run:
                      description: Dry run flag for the injection plan
                      type: boolean
        responses:
          201:
            description: OK
            content:
              application/json:
                schema:
                  type: string
                  enum: ["Created"]
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable
          409:
            description: Plan conflicts with existing ones
        """
        plans = json_list()

        try:
            add_load_injection_plans(
                injection_plans=plans,
                issuer=request.environ.get("issuer"),
                vo=request.environ.get("vo"),
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except DuplicateLoadInjectionPlan as error:
            return generate_http_error_flask(409, error)
        except Exception as error:
            return generate_http_error_flask(406, error)
        return "Created", 201

    @check_accept_header_wrapper_flask(["application/x-json-stream"])
    def get(self, src_rse=None, dest_rse=None) -> Union[str, Response]:
        """
        ---
        summary: Get load injection plans bulk in all or in specified states
        description: Return a list of load injection plans
        tags:
          - Load Injection Plans
        parameters:
          - name: src_rse
            in: query
            description: Source RSE name
            schema:
              type: string
            required: false
          - name: dest_rse
            in: query
            description: Destination RSE name
            schema:
              type: string
            required: false
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of the load injection plans. Items are seperated by new line characters.
                  type: array
                  items:
                    descriotion: A load injection plan.
                    type: object
                    properties:
                      plan_id:
                        description: ID of the injection plan
                        type: string
                      state:
                        description: State of the injection plan
                        type: string
                      src_rse:
                        description: Source RSE name
                        type: string
                      dest_rse:
                        description: Destination RSE name
                        type: string
                      inject_rate:
                        description: Injection rate in MB/s
                        type: integer
                      start_time:
                        description: Start time of the injection plan
                        type: string
                      end_time:
                        description: End time of the injection plan
                        type: string
                      comments:
                        description: Comments for the injection plan
                        type: string
                      interval:
                        description: Time interval between injections in seconds
                        type: integer
                      fudge:
                        description: Fudge factor for the injection plan
                        type: float
                      max_injection:
                        description: Maximum injection rate
                        type: float
                      expiration_delay:
                        description: Expiration delay for the injection plan
                        type: integer
                      rule_lifetime:
                        description: Rule lifetime for the injection plan
                        type: integer
                      big_first:
                        description: Big first flag for the injection plan
                        type: boolean
                      dry_run:
                        description: Dry run flag for the injection plan
                        type: boolean
          401:
            description: Invalid Auth Token
          404:
            description: Plan not found
          406:
            description: Not acceptable
        """
        try:
            if src_rse and dest_rse:
                return render_json(
                    **get_load_injection_plan(
                        src_rse=src_rse,
                        dest_rse=dest_rse,
                        issuer=request.environ.get("issuer"),
                        vo=request.environ.get("vo"),
                    )
                )
            else:

                def generate(vo):
                    for plan in get_load_injection_plans(
                        issuer=request.environ.get("issuer"), vo=vo
                    ):
                        yield render_json(**plan) + "\n"

                return try_stream(generate(vo=request.environ.get("vo")))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except NoLoadInjectionPlanFound as error:
            return generate_http_error_flask(404, error)
        except Exception as error:
            return generate_http_error_flask(406, error)

    def delete(self, src_rse, dest_rse):
        """
        ---
        summary: Delete load injection plans in bulk
        description: Delete load injection plans in bulk
        tags:
          - Load Injection Plans
        parameters:
          - name: src_rse
            in: query
            description: Source RSE name
            schema:
              type: string
            required: false
          - name: dest_rse
            in: query
            description: Destination RSE name
            schema:
              type: string
            required: false
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Not found
        """
        try:
            delete_load_injection_plan(
                src_rse=src_rse,
                dest_rse=dest_rse,
                issuer=request.environ.get("issuer"),
                vo=request.environ.get("vo"),
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except NoLoadInjectionPlanFound as error:
            return generate_http_error_flask(404, error)
        except Exception as error:
            return generate_http_error_flask(406, error)
        return "OK", 200


def blueprint(with_doc: bool = False) -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint("loadinjection", __name__, url_prefix="/loadinjection")

    plans_view = Plans.as_view("plans")
    bp.add_url_rule("", view_func=plans_view, methods=["post", "get"])
    bp.add_url_rule(
        "/<src_rse>/<dest_rse>", view_func=plans_view, methods=["get", "delete"]
    )
    # bulkplans_view = Plans.as_view("Bulkplans")
    # bp.add_url_rule("/bulkdelete", view_func=bulkplans_view, method=["post"])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """Only used for sphinx documentation"""
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
