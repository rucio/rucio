# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from json import dumps

from flask import Flask, Blueprint, Response, request

from rucio.api.rule import list_replication_rules
from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription, \
    list_subscription_rule_states, get_subscription_by_id
from rucio.common.exception import InvalidObject, SubscriptionDuplicate, SubscriptionNotFound, RuleNotFound, \
    AccessDenied
from rucio.common.utils import render_json, APIEncoder
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, try_stream, request_auth_env, \
    response_headers, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class Subscription(ErrorHandlingMethodView):
    """ REST APIs for subscriptions. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, account=None, name=None):
        """
        Retrieve a subscription.

        .. :quickref: Subscription; Get subscriptions.

        :param account: The account name.
        :param name: The subscription name.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: Subscription Not Found.
        :status 406: Not Acceptable.
        :returns: Line separated list of dictionaries with subscription information.
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
        Update an existing subscription.

        .. :quickref: Subscription; Update a subscription.

        :param account: The account name.
        :param name: The subscription name.
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        :status 404: Subscription Not Found.
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
        for keyword in metadata:
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
        Create a new subscription.

        .. :quickref: Subscription; Create a subscription.

        :param account: The account name.
        :param name: The subscription name.
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        :status 404: Subscription Not Found.
        :returns: ID if newly created subscription.
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
                filter=filter_param,
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
        Retrieve a subscription by name.

        .. :quickref: SubscriptionName; Get subscriptions by name.

        :param name: The subscription name.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: Subscription Not Found.
        :status 406: Not Acceptable.
        :returns: Line separated list of dictionaries with subscription information.
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
        Return all rules of a given subscription id.

        .. :quickref: Rules; Get subscription rules.

        :param account: The account name.
        :param name: The subscription name.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: Rule Not Found.
        :status 404: Subscription Not Found.
        :status 406: Not Acceptable.
        :returns: Line separated list of dictionaries with rule information.
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
        Return a summary of the states of all rules of a given subscription id.

        .. :quickref: States; Get subscription rule states.

        :param account: The account name.
        :param name: The subscription name.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        :returns: Line separated list of dictionaries with rule information.
        """
        def generate(vo):
            for row in list_subscription_rule_states(account=account, vo=vo):
                yield dumps(row, cls=APIEncoder) + '\n'

        return try_stream(generate(vo=request.environ.get('vo')))


class SubscriptionId(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, subscription_id):
        """
        Retrieve a subscription matching the given subscription id

        .. :quickref: SubscriptionId; Get a subscription by ID.

        :param subscription_id: The subscription id.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: Subscription Not Found.
        :status 406: Not Acceptable.
        :returns: dictionary with subscription information.
        """
        try:
            subscription = get_subscription_by_id(subscription_id, vo=request.environ.get('vo'))
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, error)

        return Response(render_json(**subscription), content_type="application/json")


def blueprint():
    bp = Blueprint('subscriptions', __name__, url_prefix='/subscriptions')

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

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
