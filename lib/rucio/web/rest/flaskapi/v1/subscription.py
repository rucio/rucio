# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from json import loads, dumps
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.rule import list_replication_rules
from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription, list_subscription_rule_states, get_subscription_by_id
from rucio.common.exception import InvalidObject, RucioException, SubscriptionDuplicate, SubscriptionNotFound, RuleNotFound, AccessDenied
from rucio.common.utils import render_json, APIEncoder
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, try_stream, request_auth_env, response_headers
from rucio.web.rest.utils import generate_http_error_flask


class Subscription(MethodView):
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
        :status 500: Internal Error.
        :returns: Line separated list of dictionaries with subscription information.
        """
        try:
            def generate(vo):
                for subscription in list_subscriptions(name=name, account=account, vo=vo):
                    yield render_json(**subscription) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, 'SubscriptionNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

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
        :status 500: Internal Error.
        """
        json_data = request.data.decode()
        try:
            params = loads(json_data)
            params = params['options']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        metadata = {}
        metadata['filter'] = params.get('filter', None)
        metadata['replication_rules'] = params.get('replication_rules', None)
        metadata['comments'] = params.get('comments', None)
        metadata['lifetime'] = params.get('lifetime', None)
        metadata['retroactive'] = params.get('retroactive', None)
        metadata['priority'] = params.get('priority', None)
        try:
            update_subscription(name=name, account=account, metadata=metadata, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (InvalidObject, TypeError) as error:
            return generate_http_error_flask(400, 'InvalidObject', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, 'SubscriptionNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
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
        :status 500: Internal Error.
        :returns: ID if newly created subscription.
        """
        dry_run = 0
        json_data = request.data
        try:
            params = loads(json_data)
            params = params['options']
            filter = params['filter']
            replication_rules = params['replication_rules']
            comments = params['comments']
            lifetime = params['lifetime']
            retroactive = params['retroactive']
            dry_run = params['dry_run']
            priority = params.get('priority', 3) or 3
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            subscription_id = add_subscription(name=name,
                                               account=account,
                                               filter=filter,
                                               replication_rules=replication_rules,
                                               comments=comments,
                                               lifetime=lifetime,
                                               retroactive=retroactive,
                                               dry_run=dry_run,
                                               priority=priority,
                                               issuer=request.environ.get('issuer'),
                                               vo=request.environ.get('vo'))
        except (InvalidObject, TypeError) as error:
            return generate_http_error_flask(400, 'InvalidObject', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except SubscriptionDuplicate as error:
            return generate_http_error_flask(409, 'SubscriptionDuplicate', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return Response(subscription_id, status=201)


class SubscriptionName(MethodView):

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
        :status 500: Internal Error.
        :returns: Line separated list of dictionaries with subscription information.
        """
        try:
            def generate(vo):
                for subscription in list_subscriptions(name=name, vo=vo):
                    yield render_json(**subscription) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, 'SubscriptionNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class Rules(MethodView):

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
        :status 500: Internal Error.
        :returns: Line separated list of dictionaries with rule information.
        """
        state = request.args.get('state', None)
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
        except RuleNotFound as error:
            return generate_http_error_flask(404, 'RuleNotFound', error.args[0])
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, 'SubscriptionNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class States(MethodView):

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
        :status 500: Internal Error.
        :returns: Line separated list of dictionaries with rule information.
        """
        try:
            def generate(vo):
                for row in list_subscription_rule_states(account=account, vo=vo):
                    yield dumps(row, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500


class SubscriptionId(MethodView):

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
        :status 500: Internal Error.
        :returns: dictionary with subscription information.
        """
        try:
            subscription = get_subscription_by_id(subscription_id, vo=request.environ.get('vo'))
        except SubscriptionNotFound as error:
            return generate_http_error_flask(404, 'SubscriptionNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

        return Response(render_json(**subscription), content_type="application/json")


def blueprint():
    bp = Blueprint('subscription', __name__, url_prefix='/subscriptions')

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
