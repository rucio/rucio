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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from json import dumps, loads
try:
    from urllib.parse import parse_qs
except ImportError:
    from urlparse import parse_qs


from web import application, ctx, data, header, BadRequest, Created, InternalError, loadhook

from rucio.api.rule import list_replication_rules
from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription, list_subscription_rule_states, get_subscription_by_id
from rucio.common.exception import InvalidObject, RucioException, SubscriptionDuplicate, SubscriptionNotFound, RuleNotFound, AccessDenied
from rucio.common.utils import generate_http_error, APIEncoder, render_json
from rucio.web.rest.common import rucio_loadhook, RucioController, check_accept_header_wrapper

URLS = (
    '/Id/(.*)', 'SubscriptionId',
    '/(.*)/(.*)/Rules/States', 'States',
    '/(.*)/Rules/States', 'States',
    '/(.*)/(.*)/Rules', 'Rules',
    '/(.*)/(.*)', 'Subscription',
    '/(.*)', 'Subscription',
    '/', 'Subscription',
)


class Subscription:
    """ REST APIs for subscriptions. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, account=None, name=None):
        """
        Retrieve a subscription.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            500 Internal Error
            406 Not Acceptable

        :param account: The account name.
        :param name: The subscription name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for subscription in list_subscriptions(name=name, account=account):
                yield dumps(subscription, cls=APIEncoder) + '\n'
        except SubscriptionNotFound as error:
            raise generate_http_error(404, 'SubscriptionNotFound', error.args[0])
        except Exception as error:
            raise InternalError(error)

    def PUT(self, account, name):
        """
        Update an existing subscription.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            500 Internal Error
        """
        json_data = data()
        try:
            params = loads(json_data)
            params = params['options']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        metadata = {}
        metadata['filter'] = params.get('filter', None)
        metadata['replication_rules'] = params.get('replication_rules', None)
        metadata['comments'] = params.get('comments', None)
        metadata['lifetime'] = params.get('lifetime', None)
        metadata['retroactive'] = params.get('retroactive', None)
        metadata['priority'] = params.get('priority', None)
        try:
            update_subscription(name=name, account=account, metadata=metadata, issuer=ctx.env.get('issuer'))
        except (InvalidObject, TypeError) as error:
            raise generate_http_error(400, 'InvalidObject', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except SubscriptionNotFound as error:
            raise generate_http_error(404, 'SubscriptionNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)
        raise Created()

    def POST(self, account, name):
        """
        Create a new subscription.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            409 Conflict
            500 Internal Error
        """
        dry_run = 0
        json_data = data()
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
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            subscription_id = add_subscription(name=name, account=account, filter=filter, replication_rules=replication_rules, comments=comments, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run, priority=priority, issuer=ctx.env.get('issuer'))
        except (InvalidObject, TypeError) as error:
            raise generate_http_error(400, 'InvalidObject', error.args[0])
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except SubscriptionDuplicate as error:
            raise generate_http_error(409, 'SubscriptionDuplicate', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

        raise Created(subscription_id)

    def DELETE(self):
        raise BadRequest()


class Rules:

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, account, name):
        """
        Return all rules of a given subscription id.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 Internal Error

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        state = None
        if ctx.query:
            params = parse_qs(ctx.query[1:])
            if 'state' in params:
                state = params['state'][0]
        try:
            subscriptions = [subscription['id'] for subscription in list_subscriptions(name=name, account=account)]
            if len(subscriptions) > 0:
                if state:
                    for rule in list_replication_rules({'subscription_id': subscriptions[0], 'state': state}):
                        yield dumps(rule, cls=APIEncoder) + '\n'
                else:
                    for rule in list_replication_rules({'subscription_id': subscriptions[0]}):
                        yield dumps(rule, cls=APIEncoder) + '\n'
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except SubscriptionNotFound as error:
            raise generate_http_error(404, 'SubscriptionNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

    def PUT(self):
        raise BadRequest()

    def DELETE(self):
        raise BadRequest()

    def POST(self):
        raise BadRequest()


class States(RucioController):

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, account, name=None):
        """
        Return a summary of the states of all rules of a given subscription id.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 Internal Error

        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for row in list_subscription_rule_states(account=account):
                yield dumps(row, cls=APIEncoder) + '\n'
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)


class SubscriptionId:

    @check_accept_header_wrapper(['application/json'])
    def GET(self, subscription_id):
        """
        Retrieve a subscription matching the given subscription id

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable

        """
        header('Content-Type', 'application/json')
        try:
            subscription = get_subscription_by_id(subscription_id)
        except SubscriptionNotFound as error:
            raise generate_http_error(404, 'SubscriptionNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

        return render_json(**subscription)


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
