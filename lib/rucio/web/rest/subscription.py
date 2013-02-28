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
from web import application, ctx, data, header, BadRequest, Created, InternalError, Unauthorized

from rucio.api.authentication import validate_auth_token
from rucio.api.subscription import get_subscriptions, add_subscription, update_subscription
from rucio.common.exception import SubscriptionDuplicate, SubscriptionNotFound
from rucio.common.utils import generate_http_error, APIEncoder

logger = getLogger("rucio.subscription")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
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
        #header('Content-Type', 'application/json')
        #header('Content-Type', 'application/octet-stream')
        header('Content-Type', 'application/x-json-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            for subscription in get_subscriptions(name=name, account=account):
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
        #header('Content-Type', 'application/octet-stream')
        header('Content-Type', 'application/json')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise Unauthorized()

        json_data = data()
        try:
            params = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        #print params
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
            update_subscription(name=name, account=auth['account'], filter=filter, replication_rules=replication_rules, subscription_policy=subscription_policy, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run)
        except SubscriptionNotFound, e:
            raise generate_http_error(404, 'SubscriptionNotFound', e[0][0])
        #except Exception, e:
        #    print e
        #    raise InternalError(e)
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

        header('Content-Type', 'application/json')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise Unauthorized()

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
            add_subscription(name=name, account=auth['account'], filter=filter, replication_rules=replication_rules, subscription_policy=subscription_policy, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run)
        except SubscriptionDuplicate as e:
            raise generate_http_error(409, 'SubscriptionDuplicate', e.args[0][0])
        #except Duplicate, e:
        #    raise generate_http_error(409, 'Duplicate', e)
        #except Exception, e:
        #    print e
        #    raise InternalError(e)
        raise Created()

    def DELETE(self):
        raise BadRequest()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
