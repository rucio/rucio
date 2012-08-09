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


def add_subscription(account, filter, replication_rules, transfer_requests, subscription_policy, lifetime, retroactive, dry_run):
    """
    Adds a new subscription which will be verified against every new added file and dataset

    :param account: Account identifier
    :type account:  String
    :param filter: Dictionary of attributes by which the input data should be filtered
                   **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
    :type filter:  Dict
    :param replication_rules: Replication rules to be set. List of tuples holding count, RSE-tag, lock, group;
                              The lock flag tells rucio that this is a locked replication rule;
                              If the group flag is set to ``true``, this rule will resolve to the same RSE for all files in the same dataset
                              **Example**: ``[(1, 'T1-DATADISKS', True, True), (3, 'T2-DATADISKS', False, False)]``
    :type replication_rules:  List
    :param transfer_requests: Transfer requests to be issued. List of tuples holding count, RSE-tag, group; If the group flag is set to ``true``, this transfer_request will resolve to the same RSE for all files in the same dataset
                              **Example**: ``[(1, 'T1-DATADISKS', True), (2, 'T2-DATADISKS', False)]``
    :type transfer_requests:  List
    :param subscription_policy: Name of an advanced subscription policy, which allows more advanced operations
                                **Example**: ``'data_export'``
    :type subscription_policy:  String
    :param lifetime: Subscription's lifetime (seconds); False if subscription has no lifetime
    :type lifetime:  Integer or False
    :param retroactive: Flag to know if the subscription should be applied on previous data
    :type retroactive:  Boolean
    :param dry_run: Just print the subsecriptions actions without actually executing them (Useful if retroactive flag is set)
    :type dry_run:  Boolean
    :returns: subscription_id
    :rtype:   String
    """

    pass


def update_subscription(subscription_id, account=None, filter=None, replication_rules=None, transfer_requests=None, subscription_policy=None, lifetime=None, retroactive=None, dry_run=None):
    """
    Updates a subscription

    :param subscription_id: Subscription identifier
    :type subscription_id:  String
    :param account: Account identifier
    :type account:  String
    :param filter: Dictionary of attributes by which the input data should be filtered
                   **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
    :type filter:  Dict
    :param replication_rules: Replication rules to be set. List of tuples holding count, RSE-tag, lock, group;
                              The lock flag tells rucio that this is a locked replication rule;
                              If the group flag is set to ``true``, this rule will resolve to the same RSE for all files in the same dataset
                              **Example**: ``[(1, 'T1-DATADISKS', True, True), (3, 'T2-DATADISKS', False, False)]``
    :type replication_rules:  List
    :param transfer_requests: Transfer requests to be issued. List of tuples holding count, RSE-tag, group; If the group flag is set to ``true``, this transfer_request will resolve to the same RSE for all files in the same dataset
                              **Example**: ``[(1, 'T1-DATADISKS', True), (2, 'T2-DATADISKS', False)]``
    :type transfer_requests:  List
    :param subscription_policy: Name of an advanced subscription policy, which allows more advanced operations
                                **Example**: ``'data_export'``
    :type subscription_policy:  String
    :param lifetime: Subscription's lifetime (seconds); False if subscription has no lifetime
    :type lifetime:  Integer or False
    :param retroactive: Flag to know if the subscription should be applied on previous data
    :type retroactive:  Boolean
    :param dry_run: Just print the subsecriptions actions without actually executing them (Useful if retroactive flag is set)
    :type dry_run:  Boolean
    :raises: exception.NotFound if subscription is not found
    """

    pass


def get_subscription(subscription_id):
    """
    Returns a dictionary with the subscription and completeness information(total/waiting/done/broken replication rules)
    Examples: ``{'status': 'INACTIVE/ACTIVE/BROKEN', 'last_modified_date': ...}``

    :param subscription_id: Subscription identifier
    :type subscription_id:  String
    :returns: Dictionary containing {subscription_meta: subscription_value}
    :rtype:   Dict
    :raises: exception.NotFound if subscription is not found
    """

    pass


def delete_subscription(subscription_id):
    """
    Deletes a subscription

    :param subscription_id: Subscription identifier
    :type subscription_id:  String
    """

    pass


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

        pass
