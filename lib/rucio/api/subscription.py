"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
              http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
 - Martin Barisits, <martin.barisits@cern.ch>, 2012
 - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
 - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015, 2017
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
 - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
 - Patrick Austin, <patrick.austin@stfc.ac.uk>, 2020

 PY3K COMPATIBLE
"""

from json import dumps, loads
from sqlalchemy.util import KeyedTuple

from rucio.api.permission import has_permission
from rucio.common.exception import InvalidObject, AccessDenied
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import subscription


def add_subscription(name, account, filter, replication_rules, comments, lifetime, retroactive, dry_run, priority=None, issuer=None, vo='def'):
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
    :type issuer:  String
    :param vo: The VO to act on.
    :type vo: String
    :returns: subscription_id
    :rtype:   String
    """
    if not has_permission(issuer=issuer, vo=vo, action='add_subscription', kwargs={'account': account}):
        raise AccessDenied('Account %s can not add subscription' % (issuer))
    try:
        if filter:
            if not isinstance(filter, dict):
                raise TypeError('filter should be a dict')
            validate_schema(name='subscription_filter', obj=filter)
        if replication_rules:
            if not isinstance(replication_rules, list):
                raise TypeError('replication_rules should be a list')
            else:
                for rule in replication_rules:
                    validate_schema(name='activity', obj=rule.get('activity', 'default'))
        else:
            raise InvalidObject('You must specify a rule')
    except ValueError as error:
        raise TypeError(error)

    account = InternalAccount(account, vo=vo)

    keys = ['scope', 'account']
    types = [InternalScope, InternalAccount]
    for _key, _type in zip(keys, types):
        if _key in filter:
            if isinstance(filter[_key], list):
                filter[_key] = [_type(val, vo=vo).internal for val in filter[_key]]
            else:
                filter[_key] = _type(filter[_key], vo=vo).internal

    return subscription.add_subscription(name=name, account=account, filter=dumps(filter), replication_rules=dumps(replication_rules), comments=comments, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run, priority=priority)


def update_subscription(name, account, metadata=None, issuer=None, vo='def'):
    """
    Updates a subscription

    :param name: Name of the subscription
    :type:  String
    :param account: Account identifier
    :type account:  String
    :param metadata: Dictionary of metadata to update. Supported keys : filter, replication_rules, comments, lifetime, retroactive, dry_run, priority, last_processed
    :type metadata:  Dict
    :param issuer: The account issuing this operation.
    :type issuer: String
    :param vo: The VO to act on.
    :type vo: String
    :raises: SubscriptionNotFound if subscription is not found
    """
    if not has_permission(issuer=issuer, vo=vo, action='update_subscription', kwargs={'account': account}):
        raise AccessDenied('Account %s can not update subscription' % (issuer))
    try:
        if not isinstance(metadata, dict):
            raise TypeError('metadata should be a dict')
        if 'filter' in metadata and metadata['filter']:
            if not isinstance(metadata['filter'], dict):
                raise TypeError('filter should be a dict')
            validate_schema(name='subscription_filter', obj=metadata['filter'])
        if 'replication_rules' in metadata and metadata['replication_rules']:
            if not isinstance(metadata['replication_rules'], list):
                raise TypeError('replication_rules should be a list')
            else:
                for rule in metadata['replication_rules']:
                    validate_schema(name='activity', obj=rule.get('activity', 'default'))
    except ValueError as error:
        raise TypeError(error)

    account = InternalAccount(account, vo=vo)

    if 'filter' in metadata and metadata['filter'] is not None:
        filter = metadata['filter']
        keys = ['scope', 'account']
        types = [InternalScope, InternalAccount]

        for _key, _type in zip(keys, types):
            if _key in filter and filter[_key] is not None:
                if isinstance(filter[_key], list):
                    filter[_key] = [_type(val, vo=vo).internal for val in filter[_key]]
                else:
                    filter[_key] = _type(filter[_key], vo=vo).internal

    return subscription.update_subscription(name=name, account=account, metadata=metadata)


def list_subscriptions(name=None, account=None, state=None, vo='def'):
    """
    Returns a dictionary with the subscription information :
    Examples: ``{'status': 'INACTIVE/ACTIVE/BROKEN', 'last_modified_date': ...}``

    :param name: Name of the subscription
    :type:  String
    :param account: Account identifier
    :type account:  String
    :param state: Filter for subscription state
    :type state: String
    :param vo: The VO to act on.
    :type vo: String
    :returns: Dictionary containing subscription parameter
    :rtype:   Dict
    :raises: exception.NotFound if subscription is not found
    """

    if account:
        account = InternalAccount(account, vo=vo)
    else:
        account = InternalAccount('*', vo=vo)

    subs = subscription.list_subscriptions(name, account, state)

    for sub in subs:
        sub['account'] = sub['account'].external

        if 'filter' in sub:
            fil = loads(sub['filter'])
            if 'account' in fil:
                fil['account'] = [InternalAccount(acc, fromExternal=False).external for acc in fil['account']]
            if 'scope' in fil:
                fil['scope'] = [InternalScope(sco, fromExternal=False).external for sco in fil['scope']]
            sub['filter'] = dumps(fil)

        yield sub


def list_subscription_rule_states(name=None, account=None, vo='def'):
    """Returns a list of with the number of rules per state for a subscription.

    :param name: Name of the subscription
    :param account: Account identifier
    :param vo: The VO to act on.
    :returns: List with tuple (account, name, state, count)
    """
    if account is not None:
        account = InternalAccount(account, vo=vo)
    else:
        account = InternalAccount('*', vo=vo)
    subs = subscription.list_subscription_rule_states(name, account)
    for sub in subs:
        # sub is an immutable KeyedTuple so return new KeyedTuple with edited entries
        labels = sub._fields
        d = sub._asdict()
        d['account'] = d['account'].external
        yield KeyedTuple([d[l] for l in labels], labels=labels)


def delete_subscription(subscription_id, vo='def'):
    """
    Deletes a subscription

    :param subscription_id: Subscription identifier
    :param vo: The VO of the user issuing command
    :type subscription_id:  String
    """

    raise NotImplementedError


def get_subscription_by_id(subscription_id, vo='def'):
    """
    Get a specific subscription by id.

    :param subscription_id: The subscription_id to select.
    :param vo: The VO of the user issuing command.

    :raises: SubscriptionNotFound if no Subscription can be found.
    """
    sub = subscription.get_subscription_by_id(subscription_id)
    if sub['account'].vo != vo:
        raise AccessDenied('Unable to get subscription')

    sub['account'] = sub['account'].external

    if 'filter' in sub:
        fil = loads(sub['filter'])
        if 'account' in fil:
            fil['account'] = [InternalAccount(acc, fromExternal=False).external for acc in fil['account']]
        if 'scope' in fil:
            fil['scope'] = [InternalScope(sco, fromExternal=False).external for sco in fil['scope']]
        sub['filter'] = dumps(fil)

    return sub
