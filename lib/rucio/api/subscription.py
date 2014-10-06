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
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

from json import dumps

from rucio.common.exception import InvalidMetadata
from rucio.common.schema import validate_schema
from rucio.core import subscription


def add_subscription(name, account, filter, replication_rules, comments, lifetime, retroactive, dry_run):
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
    :returns: subscription_id
    :rtype:   String
    """
    accepted_keys = ['datatype', 'prod_step', 'stream_name', 'project', 'scope', 'pattern', 'type', 'account', 'excluded_pattern', 'grouping', 'group', 'provenance']
    try:
        if filter:
            if type(filter) != dict:
                raise TypeError('filter should be a dict')
            else:
                for key in filter:
                    if key not in accepted_keys:
                        raise InvalidMetadata('Invalid metadata <%s>' % (key))
            validate_schema(name='subscription_filter', obj=filter)
        if replication_rules and type(replication_rules) != list:
            raise TypeError('replication_rules should be a list')
    except ValueError, e:
        raise TypeError(e)

    return subscription.add_subscription(name=name, account=account, filter=dumps(filter), replication_rules=dumps(replication_rules), comments=comments, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run)


def update_subscription(name, account, filter=None, replication_rules=None, comments=None, lifetime=None, retroactive=None, dry_run=None):
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
    :raises: exception.NotFound if subscription is not found
    """
    accepted_keys = ['datatype', 'prod_step', 'stream_name', 'project', 'scope', 'pattern', 'type', 'account', 'excluded_pattern', 'grouping', 'group', 'provenance']
    try:
        if filter:
            if type(filter) != dict:
                raise TypeError('filter should be a dict')
            else:
                for key in filter:
                    if key not in accepted_keys:
                        raise InvalidMetadata('Invalid metadata <%s>' % (key))
            validate_schema(name='subscription_filter', obj=filter)
        if replication_rules and type(replication_rules) != list:
            raise TypeError('replication_rules should be a list')
    except ValueError, e:
        raise TypeError(e)
    return subscription.update_subscription(name=name, account=account, filter=dumps(filter), replication_rules=dumps(replication_rules), comments=comments, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run)


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


class SubscriptionPolicy():
    """
    Abstract class for advanced subscription policies; Each time a subscription with a set subscription policy is called the specifically designed process function is called to return the replication_rules and transfer_requests for the input dataset/file
    """

    def process(lfn, dsn, meta_data):
        """
        Specifically selects and returns the replication_rules and transfer_requests

        :param lfn: Logical file name
        :type lfn:  String
        :param dsn: Dataset name the file belongs to
        :type dsn:  String
        :param meta_data: Meta data dictionary of this file
        :type meta_data:  Dict
        :returns: Tuple holding the List of replication_rules and List of transfer_requests: (replication_rules, transfer_requests)
                  **Example**: ``([(1, 'T1-DATADISKS', True, True), (3, 'T2-DATADISKS', False, False)], [(1, 'T1-DATADISKS', True), (2, 'T2-DATADISKS', False)])``
        :rtype:   List
        """

        raise NotImplementedError
