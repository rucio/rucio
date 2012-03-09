# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2012


def add_subscription(account, **kwargs):
    """
    Adds a new subscription

    :param account: Account identifier.
    :param filters: Dictionary of attributes by which the input data should be filtered.
                          Example: {'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}
    :param destinations: List of rse tags. Examples: T1s@DATADISKS, T2s@DATADISKS.
    :param selection_policy: Selection policy name. Examples: "data_export".
    :param group_by: Unit of replication on rse (File, Dataset, Meta-data) on which will be applied the selection_policy method.
    :param lifetime: Subscription's lifetime.
    :param retroactive: True/False. Flag to know if the subscription should be applied on previous data.
    :param dry_run: True/False. Don't actually execute the command, just print the amount of data moved, replication rules, etc.
    :returns: subscription_id
    """
    pass


def data_export(lfn, dsn, destinations):
    """
    Selection policy for tzero data export. Method which generates replication rules(account, lfn, rse, replication_factor=1) for each new
    file described by the filters parameter of the subscription. This function checks the placement of the previous files in the dataset
    to consolidate them in one rse, the mou shares and the site rse tag(t1/t2) category.

    :param lfn:     The file name.
    :param dsn:     The dataset name.
    :param destinations: List of rse tags. Examples: T1s@DATADISKS, T2s@DATADISKS.
    """
    pass


def update_subscription(subscription_id, subscription_meta):
    """
    Updates a subscription

    :param subscription_id:  Subscription identifier.
    :param subscription_meta: Mapping of information about the subscription.
                              Examples: {'dsns': ['data11_900GeV*','data11_7TeV*','data11_8TeV*']}
    """
    pass


def get_subscription(subscription_id):
    """
    Returns a dictionary with the subscription and completeness information(total/waiting/done/broken replication rules).
    Examples: {'status': 'INACTIVE/ACTIVE/BROKEN', 'last_modified_date': ...}

    :param subscription_id: The subscription identifier
    :retval: Dictionary containing {subscription_meta: subscription_value}.
    :raises: exception.NotFound if subscription is not found
    """
    pass


def delete_subscription(subscription_id):
    """
    Deletes a subscription
    """
    pass
