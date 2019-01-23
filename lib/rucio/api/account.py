# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011-2013
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2011
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015-2019
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

import rucio.api.permission
import rucio.common.exception
import rucio.core.identity

from rucio.core import account as account_core
from rucio.core.rse import get_rse_id
from rucio.common.schema import validate_schema
from rucio.db.sqla.constants import AccountType


def add_account(account, type, email, issuer):
    """
    Creates an account with the provided account name, contact information, etc.

    :param account: The account name.
    :param type: The account type
    :param email: The Email address associated with the account.

    :param issuer: The issuer account_core.

    """

    validate_schema(name='account', obj=account)

    kwargs = {'account': account, 'type': type}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add account' % (issuer))

    account_core.add_account(account, AccountType.from_sym(type), email)


def del_account(account, issuer):
    """
    Disables an account with the provided account name.

    :param account: The account name.
    :param issuer: The issuer account_core.

    """
    kwargs = {'account': account}
    if not rucio.api.permission.has_permission(issuer=issuer, action='del_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete account' % (issuer))

    account_core.del_account(account)


def get_account_info(account):
    """
    Returns the info like the statistics information associated to an account_core.

    :param account: The account name.
    :returns: A list with all account information.
    """
    return account_core.get_account(account)


def update_account(account, key, value, issuer='root'):
    """ Update a property of an account_core.

    :param account: Name of the account_core.
    :param key: Account property like status.
    :param value: Property value.
    """
    validate_schema(name='account', obj=account)
    kwargs = {}
    if not rucio.api.permission.has_permission(issuer=issuer, action='update_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not change %s  of the account' % (issuer, key))
    return account_core.update_account(account, key, value)


def list_accounts(filter={}):
    """
    Lists all the Rucio account names.

    REST API: http://<host>:<port>/rucio/accounts

    :param filter: Dictionary of attributes by which the input data should be filtered

    :returns: List of all accounts.
    """
    return account_core.list_accounts(filter=filter)


def account_exists(account):
    """
    Checks to see if account exists. This procedure does not check it's status.

    :param account: Name of the account_core.
    :returns: True if found, otherwise false.
    """
    return account_core.account_exists(account)


def list_identities(account):
    """
    List all identities on an account_core.

    :param account: The account name.
    """
    return account_core.list_identities(account)


def list_account_attributes(account):
    """
    Returns all the attributes for the given account.

    :param account: The account name.
    """
    return account_core.list_account_attributes(account)


def add_account_attribute(key, value, account, issuer):
    """
    Add an attribute to an account.

    :param key: attribute key.
    :param value: attribute value.
    :param account: The account name.
    :param issuer: The issuer account_core.
    """
    validate_schema(name='account_attribute', obj=key)
    validate_schema(name='account_attribute', obj=value)

    kwargs = {'account': account, 'key': key, 'value': value}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_attribute', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add attributes' % (issuer))
    account_core.add_account_attribute(account, key, value)


def del_account_attribute(key, account, issuer):
    """
    Delete an attribute to an account.

    :param key: attribute key.
    :param account: The account name.
    :param issuer: The issuer account_core.
    """
    kwargs = {'account': account, 'key': key}
    if not rucio.api.permission.has_permission(issuer=issuer, action='del_attribute', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete attribute' % (issuer))
    account_core.del_account_attribute(account, key)


def get_usage(rse, account, issuer):
    """
    Returns current values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse:              The RSE.
    :param account:          The account name.
    :param issuer:           The issuer account.
    :returns:                A dictionary with total and bytes.
    """
    rse_id = get_rse_id(rse=rse)
    return account_core.get_usage(rse_id, account)


def get_usage_history(rse, account, issuer):
    """
    Returns historical values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse:              The RSE.
    :param account:          The account name.
    :param issuer:           The issuer account.
    :returns:                A dictionary with total and bytes.
    """
    rse_id = get_rse_id(rse=rse)
    return account_core.get_usage_history(rse_id, account)
