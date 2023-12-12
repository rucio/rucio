# -*- coding: utf-8 -*-
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

from flask import Flask, Response, request

from rucio.api.rule import list_replication_rules
from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription, \
    list_subscription_rule_states, get_subscription_by_id
from rucio.common.exception import InvalidObject, SubscriptionDuplicate, SubscriptionNotFound, RuleNotFound, \
    AccessDenied
from rucio.common.utils import render_json, APIEncoder
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, try_stream, \
    response_headers, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class Subscription(ErrorHandlingMethodView):
    """ REST APIs for subscriptions. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, account=None, name=None):
        """
        ---
        summary: Get Subscription
        description: Retrieve a subscription.
        tags:
          - Replicas
        parameters:
        - name: account
          in: path
          description: The account name.
          schema:
            type: string
          style: simple
        - name: name
          in: path
          description: The subscription name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of subscriptions.
                  type: array
                  items:
                    description: A subscription.
                    type: object
                    properties:
                      id:
                        description: The id of the subscription.
                        type: string
                      name:
                        description: The name of the subscription.
                        type: string
                      filter:
                        description: The filter for the subscription.
                        type: string
                      replication_rules:
                        description: The replication rules for the subscription.
                        type: string
                      policyid:
                        description: The policyid for the subscription.
                        type: integer
                      state:
                        description: The state of the subscription.
                        type: string
                        enum: ["A", "I", "N", "U", "B"]
                      last_processed:
                        description: The time the subscription was processed last.
                        type: string
                        format: date-time
                      account:
                        description: The account for the subscription.
                        type: string
                      lifetime:
                        description: The lifetime for the subscription.
                        type: string
                        format: date-time
                      comments:
                        description: The comments for the subscription.
                        type: string
                      retroactive:
                        description: If the subscription is retroactive.
                        type: boolean
                      expired_at:
                        description: The date-time of the expiration for the subscription.
                        type: string
                        format: date-time
          401:
            description: Invalid Auth Token
          404:
            description: Subscription Not found
          406:
            description: Not acceptable
        """
        try:
            def generate(vo):
                for subscription in list_subscriptions(name=name, account=account, vo=vo):
                    yield render_json(**subscription) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, error)

    def put(self, account, name):
        """
        ---
        summary: Update subscription
        description: Update an existing subscription.
        tags:
          - Replicas
        parameters:
        - name: account
          in: path
          description: The account name.
          schema:
            type: string
          style: simple
          required: true
        - name: name
          in: path
          description: The subscription name.
          schema:
            type: string
          style: simple
          required: true
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                  - options
                properties:
                  options:
                    description: The values for the new subcription.
                    type: object
                    properties:
                      filter:
                        description: The filter for the subscription.
                        type: string
                      replication_rules:
                        description: The replication rules for the subscription.
                        type: string
                      comments:
                        description: The comments for the subscription.
                        type: string
                      lifetime:
                        description: The lifetime for the subscription.
                        type: string
                        format: date-time
                      retroactive:
                        description: If the retroactive is actiavted for a subscription.
                        type: boolean
                      priority:
                        description: The priority/policyid for the subscription. Stored as policyid.
                        type: integer
        responses:
          201:
            description: OK
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Not found
        """
        parameters = json_parameters()
        options = param_get(parameters, 'options')
        metadata = {
            'filter': None,
            'replication_rules': None,
            'comments': None,
            'lifetime': None,
            'retroactive': None,
            'priority': None,
        }
        for keyword in list(metadata):
            metadata[keyword] = param_get(options, keyword, default=metadata[keyword])

        try:
            update_subscription(name=name, account=account, metadata=metadata, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (InvalidObject, TypeError) as error:
            return generate_http_error_flask(400, InvalidObject.__name__, error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201

    def post(self, account, name):
        """
        ---
        summary: Create subscription
        description: Create a new subscription
        tags:
          - Replicas
        parameters:
        - name: account
          in: path
          description: The account name.
          schema:
            type: string
          style: simple
          required: true
        - name: name
          in: path
          description: The subscription name.
          schema:
            type: string
          style: simple
          required: true
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                  - options
                properties:
                  options:
                    description: The values for the new subcription.
                    type: object
                    required:
                      - filter
                      - replication_rules
                      - comments
                      - lifetime
                      - retroactive
                    properties:
                      filter:
                        description: The filter for the subscription.
                        type: string
                      replication_rules:
                        description: The replication rules for the subscription.
                        type: string
                      comments:
                        description: The comments for the subscription.
                        type: string
                      lifetime:
                        description: The lifetime for the subscription.
                        type: string
                        format: date-time
                      retroactive:
                        description: If the retroactive is actiavted for a subscription.
                        type: boolean
                      priority:
                        description: The priority/policyid for the subscription. Stored as policyid.
                        type: integer
                      dry_run:
                        description: The priority/policyid for the subscription. Stored as policyid.
                        type: boolean
                        default: false
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The subscription Id for the new subscription.
                  type: string
          400:
            description: Cannot decode json parameter list.
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        parameters = json_parameters()
        options = param_get(parameters, 'options')
        filter_param = param_get(options, 'filter')
        replication_rules = param_get(options, 'replication_rules')
        comments = param_get(options, 'comments')
        lifetime = param_get(options, 'lifetime')
        retroactive = param_get(options, 'retroactive')
        dry_run = param_get(options, 'dry_run', default=False)
        priority = param_get(options, 'priority', default=False)
        if not priority:
            priority = 3

        try:
            subscription_id = add_subscription(
                name=name,
                account=account,
                filter_=filter_param,
                replication_rules=replication_rules,
                comments=comments,
                lifetime=lifetime,
                retroactive=retroactive,
                dry_run=dry_run,
                priority=priority,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
            )
        except (InvalidObject, TypeError) as error:
            return generate_http_error_flask(400, InvalidObject.__name__, error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except SubscriptionDuplicate as error:
            return generate_http_error_flask(409, error)

        return Response(subscription_id, status=201)


class SubscriptionName(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, name=None):
        """
        ---
        summary: Get Subscription by Name
        description: Retrieve a subscription by name.
        tags:
          - Replicas
        parameters:
        - name: name
          in: path
          description: The subscription name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of subscriptions.
                  type: array
                  items:
                    description: A subscription.
                    type: object
                    properties:
                      id:
                        description: The id of the subscription.
                        type: string
                      name:
                        description: The name of the subscription.
                        type: string
                      filter:
                        description: The filter for the subscription.
                        type: string
                      replication_rules:
                        description: The replication rules for the subscription.
                        type: string
                      policyid:
                        description: The policyid for the subscription.
                        type: integer
                      state:
                        description: The state of the subscription.
                        type: string
                        enum: ["A", "I", "N", "U", "B"]
                      last_processed:
                        description: The time the subscription was processed last.
                        type: string
                        format: date-time
                      account:
                        description: The account for the subscription.
                        type: string
                      lifetime:
                        description: The lifetime for the subscription.
                        type: string
                        format: date-time
                      comments:
                        description: The comments for the subscription.
                        type: string
                      retroactive:
                        description: If the subscription is retroactive.
                        type: boolean
                      expired_at:
                        description: The date-time of the expiration for the subscription.
                        type: string
                        format: date-time
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        try:
            def generate(vo):
                for subscription in list_subscriptions(name=name, vo=vo):
                    yield render_json(**subscription) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, error)


class Rules(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, account, name):
        """
        ---
        summary: Get Replication Rules
        description: Return all rules of a given subscription id.
        tags:
          - Replicas
        parameters:
        - name: account
          in: path
          description: The account name.
          schema:
            type: string
          style: simple
          required: true
        - name: name
          in: path
          description: The subscription name.
          schema:
            type: string
          style: simple
          required: true
        - name: state
          in: query
          description: The subscription state to filter for.
          schema:
            type: string
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list with the associated replication rules.
                  type: array
                  items:
                    description: A subscription rule.
          401:
            description: Invalid Auth Token
          404:
            description: Rule or Subscription not found
          406:
            description: Not acceptable
        """
        state = request.args.get('state', default=None)
        try:
            subscriptions = [subscription['id'] for subscription in list_subscriptions(name=name, account=account, vo=request.environ.get('vo'))]

            def generate(vo):
                if len(subscriptions) > 0:
                    if state:
                        for rule in list_replication_rules({'subscription_id': subscriptions[0], 'state': state}, vo=vo):
                            yield render_json(**rule) + '\n'
                    else:
                        for rule in list_replication_rules({'subscription_id': subscriptions[0]}, vo=vo):
                            yield render_json(**rule) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except (RuleNotFound, SubscriptionNotFound) as error:
            return generate_http_error_flask(404, error)


class States(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, account, name=None):
        """
        ---
        summary: Get states
        description: Return a summary of the states of all rules of a given subscription id.
        tags:
          - Replicas
        parameters:
        - name: account
          in: path
          description: The account name.
          schema:
            type: string
          style: simple
          required: true
        - name: name
          in: path
          description: The subscription name.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  description: A list of rule states with counts for each subscription.
                  type: array
                  items:
                    type: object
                    properties:
                      account:
                        description: The account for the subscription.
                        type: string
                      name:
                        description: The name of the subscription.
                        type: string
                      state:
                        description: The state of the rules.
                        type: string
                        enum: ["R", "O", "S", "U", "W", "I"]
                      count:
                        description: The number of rules with that state.
                        type: integer
          401:
            description: Invalid Auth Token
          404:
            description: Not found
          406:
            description: Not acceptable
        """
        def generate(vo):
            for row in list_subscription_rule_states(name=name, account=account, vo=vo):
                yield dumps(row, cls=APIEncoder) + '\n'

        return try_stream(generate(vo=request.environ.get('vo')))


class SubscriptionId(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, subscription_id):
        """
        ---
        summary: Get Subscription from ID
        description: Retrieve a subscription matching the given subscription id.
        tags:
          - Replicas
        parameters:
        - name: subscription_id
          in: path
          description: The subscription id.
          schema:
            type: string
          style: simple
          required: true
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  description: The subscription.
                  type: object
                  properties:
                    id:
                      description: The id of the subscription.
                      type: string
                    name:
                      description: The name of the subscription.
                      type: string
                    filter:
                      description: The filter for the subscription.
                      type: string
                    replication_rules:
                      description: The replication rules for the subscription.
                      type: string
                    policyid:
                      description: The policyid for the subscription.
                      type: integer
                    state:
                      description: The state of the subscription.
                      type: string
                      enum: ["A", "I", "N", "U", "B"]
                    last_processed:
                      description: The time the subscription was processed last.
                      type: string
                      format: date-time
                    account:
                      description: The account for the subscription.
                      type: string
                    lifetime:
                      description: The lifetime for the subscription.
                      type: string
                      format: date-time
                    comments:
                      description: The comments for the subscription.
                      type: string
                    retroactive:
                      description: If the subscription is retroactive.
                      type: boolean
                    expired_at:
                      description: The date-time of the expiration for the subscription.
                      type: string
                      format: date-time
          401:
            description: Invalid Auth Token
          404:
            description: Subscription not found
          406:
            description: Not acceptable
        """
        try:
            subscription = get_subscription_by_id(subscription_id, vo=request.environ.get('vo'))
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, error)

        return Response(render_json(**subscription), content_type="application/json")


def blueprint():
    bp = AuthenticatedBlueprint('subscriptions', __name__, url_prefix='/subscriptions')

    subscription_id_view = SubscriptionId.as_view('subscription_id')
    bp.add_url_rule('/Id/<subscription_id>', view_func=subscription_id_view, methods=['get', ])
    states_view = States.as_view('states')
    bp.add_url_rule('/<account>/<name>/Rules/States', view_func=states_view, methods=['get', ])
    bp.add_url_rule('/<account>/Rules/States', view_func=states_view, methods=['get', ])
    rules_view = Rules.as_view('rules')
    bp.add_url_rule('/<account>/<name>/Rules', view_func=rules_view, methods=['get', ])
    subscription_view = Subscription.as_view('subscription')
    bp.add_url_rule('/<account>/<name>', view_func=subscription_view, methods=['get', 'post', 'put'])
    bp.add_url_rule('/<account>', view_func=subscription_view, methods=['get', ])
    bp.add_url_rule('/', view_func=subscription_view, methods=['get', ])
    subscription_name_view = SubscriptionName.as_view('subscription_name')
    bp.add_url_rule('/Name/<name>', view_func=subscription_name_view, methods=['get', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
