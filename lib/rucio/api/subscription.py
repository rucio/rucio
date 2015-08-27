# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Martin Barisits, <martin.barisits@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

from json import dumps

from rucio.api.permission import has_permission
from rucio.common.exception import InvalidObject, AccessDenied
from rucio.common.schema import validate_schema
from rucio.core import subscription


def add_subscription(name, account, filter, replication_rules, comments, lifetime, retroactive, dry_run, priority=None, issuer=None):
    """
    Adds a new subscription which will be verified against every new added file and dataset

    :param account: Account identifier
    :type account:  String
    :param name: Name of the subscription
    :type:  String
    :param filter: Dictionary of attributes by which the input data should be filtered
                   **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
    :type filter:  Dict
    :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
    :type replication_rules:  Dict
    :param comments: Comments for the subscription
    :type comments:  String
    :param lifetime: Subscription's lifetime (seconds); False if subscription has no lifetime
    :type lifetime:  Integer or False
    :param retroactive: Flag to know if the subscription should be applied on previous data
    :type retroactive:  Boolean
    :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
    :type dry_run:  Boolean
    :param priority: The priority of the subscription
    :type priority: Integer
    :param issuer:  The account issuing this operation.
    :type comments:  String
    :returns: subscription_id
    :rtype:   String
    """
    if not has_permission(issuer=issuer, action='add_subscription', kwargs={'account': account}):
        raise AccessDenied('Account %s can not add subscription' % (issuer))
    try:
        if filter:
            if type(filter) != dict:
                raise TypeError('filter should be a dict')
            validate_schema(name='subscription_filter', obj=filter)
        if replication_rules:
            if type(replication_rules) != list:
                raise TypeError('replication_rules should be a list')
            else:
                for rule in replication_rules:
                    validate_schema(name='activity', obj=rule.get('activity', 'default'))
        else:
            raise InvalidObject('You must specify a rule')
    except ValueError, error:
        raise TypeError(error)

    return subscription.add_subscription(name=name, account=account, filter=dumps(filter), replication_rules=dumps(replication_rules), comments=comments, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run, priority=priority)


def update_subscription(name, account, filter=None, replication_rules=None, comments=None, lifetime=None, retroactive=None, state=None, dry_run=None, priority=None, issuer=None):
    """
    Updates a subscription

    :param name: Name of the subscription
    :type:  String
    :param account: Account identifier
    :type account:  String
    :param filter: Dictionary of attributes by which the input data should be filtered
                   **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
    :type filter:  Dict
    :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
    :type replication_rules:  Dict
    :param comments: Comments for the subscription
    :type comments:  String
    :param lifetime: Subscription's lifetime (seconds); False if subscription has no lifetime
    :type lifetime:  Integer or False
    :param retroactive: Flag to know if the subscription should be applied on previous data
    :type retroactive:  Boolean
    :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
    :type dry_run:  Boolean
    :param state: The state of the subscription
    :param priority: The priority of the subscription
    :type priority: Integer
    :param issuer:  The account issuing this operation.
    :type comments:  String
    :raises: exception.NotFound if subscription is not found
    """
    if not has_permission(issuer=issuer, action='update_subscription', kwargs={'account': account}):
        raise AccessDenied('Account %s can not update subscription' % (issuer))
    try:
        if filter:
            if type(filter) != dict:
                raise TypeError('filter should be a dict')
            validate_schema(name='subscription_filter', obj=filter)
        if replication_rules:
            if type(replication_rules) != list:
                raise TypeError('replication_rules should be a list')
            else:
                for rule in replication_rules:
                    validate_schema(name='activity', obj=rule.get('activity', 'default'))
    except ValueError, error:
        raise TypeError(error)
    return subscription.update_subscription(name=name, account=account, filter=dumps(filter), replication_rules=dumps(replication_rules), comments=comments, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run, state=state, priority=priority)


def list_subscriptions(name=None, account=None, state=None):
    """
    Returns a dictionary with the subscription information :
    Examples: ``{'status': 'INACTIVE/ACTIVE/BROKEN', 'last_modified_date': ...}``

    :param name: Name of the subscription
    :type:  String
    :param account: Account identifier
    :type account:  String
    :returns: Dictionary containing subscription parameter
    :rtype:   Dict
    :raises: exception.NotFound if subscription is not found
    """
    return subscription.list_subscriptions(name, account, state)


def list_subscription_rule_states(name=None, account=None):
    """Returns a list of with the number of rules per state for a subscription.

    :param name: Name of the subscription
    :param account: Account identifier
    :param session: The database session in use.
    :returns: List with tuple (account, name, state, count)
    """
    return subscription.list_subscription_rule_states(name, account)


def delete_subscription(subscription_id):
    """
    Deletes a subscription

    :param subscription_id: Subscription identifier
    :type subscription_id:  String
    """

    raise NotImplementedError


def get_subscription_by_id(subscription_id):
    """
    Get a specific subscription by id.

    :param subscription_id: The subscription_id to select.
    :param session: The database session in use.
    :raises: SubscriptionNotFound if no Subscription can be found.
    """
    return subscription.get_subscription_by_id(subscription_id)
