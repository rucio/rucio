#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG

from web import application, ctx, data, header, BadRequest, Created, InternalError, loadhook

from rucio.api.rule import list_replication_rules
from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription
from rucio.common.exception import InvalidObject, RucioException, SubscriptionDuplicate, SubscriptionNotFound, RuleNotFound
from rucio.common.utils import generate_http_error, APIEncoder
from rucio.web.rest.common import rucio_loadhook

logger = getLogger("rucio.subscription")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/(.*)/(.*)/Rules', 'Rules',
    '/(.*)/(.*)', 'Subscription',
    '/(.*)', 'Subscription',
)


class Subscription:
    """ REST APIs for subscriptions. """

    def GET(self, account, name):
        """
        Retrieve a subscription.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 Internal Error

        :param account: The account name.
        :param name: The subscription name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            for subscription in list_subscriptions(name=name, account=account):
                yield dumps(subscription, cls=APIEncoder) + '\n'
        except SubscriptionNotFound, e:
            raise generate_http_error(404, 'SubscriptionNotFound', e[0][0])
        except Exception, e:
            raise InternalError(e)

    def PUT(self, name):
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
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            filter = params['filter']
        except KeyError:
            filter = None
        try:
            replication_rules = params['replication_rules']
        except KeyError:
            replication_rules = None
        try:
            subscription_policy = params['subscription_policy']
        except KeyError:
            subscription_policy = None
        try:
            lifetime = params['lifetime']
        except KeyError:
            lifetime = None
        try:
            retroactive = params['retroactive']
        except KeyError:
            retroactive = None
        try:
            dry_run = params['dry_run']
        except KeyError:
            dry_run = None

        try:
            update_subscription(name=name, account=ctx.env.get('issuer'), filter=filter, replication_rules=replication_rules, subscription_policy=subscription_policy, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run)
        except SubscriptionNotFound, e:
            raise generate_http_error(404, 'SubscriptionNotFound', e[0][0])
        except InvalidObject, e:
            raise generate_http_error(400, 'InvalidObject', e[0][0])
        except Exception, e:
            raise InternalError(e)
        raise Created()

    def POST(self, name):
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
            filter = params['filter']
            replication_rules = params['replication_rules']
            subscription_policy = params['subscription_policy']
            lifetime = params['lifetime']
            retroactive = params['retroactive']
            dry_run = params['dry_run']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            add_subscription(name=name, account=ctx.env.get('issuer'), filter=filter, replication_rules=replication_rules, subscription_policy=subscription_policy, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run)
        except SubscriptionDuplicate as e:
            raise generate_http_error(409, 'SubscriptionDuplicate', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except InvalidObject, e:
            raise generate_http_error(400, 'InvalidObject', e[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def DELETE(self):
        raise BadRequest()


class Rules:

    def GET(self, account, name):
        """
        Return all rules of a given subscription id.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            subscriptions = [subscription['id'] for subscription in list_subscriptions(name=name, account=account)]
            if len(subscriptions) > 0:
                for rule in list_replication_rules({'subscription_id': subscriptions[0]}):
                    yield dumps(rule, cls=APIEncoder) + '\n'
        except RuleNotFound, e:
            raise generate_http_error(404, 'RuleNotFound', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except SubscriptionNotFound, e:
            raise generate_http_error(404, 'SubscriptionNotFound', e[0][0])
        except Exception, e:
            raise InternalError(e)

    def PUT(self):
        raise BadRequest()

    def DELETE(self):
        raise BadRequest()

    def POST(self):
        raise BadRequest()

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(rucio_loadhook))
application = app.wsgifunc()
