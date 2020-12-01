# -*- coding: utf-8 -*-
# Copyright 2012-2020 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2020
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2015
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012
# - Martin Barisits <martin.barisits@cern.ch>, 2014
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

import rucio.api.permission
import rucio.common.exception
import rucio.core.identity

from rucio.core import account as account_core
from rucio.core.rse import get_rse_id
from rucio.common.schema import validate_schema
from rucio.common.utils import api_update_return_dict
from rucio.common.types import InternalAccount
from rucio.db.sqla.constants import AccountType


def add_account(account, type, email, issuer, vo='def'):
    """
    Creates an account with the provided account name, contact information, etc.

    :param account: The account name.
    :param type: The account type
    :param email: The Email address associated with the account.

    :param issuer: The issuer account_core.
    :param vo: The VO to act on.

    """

    validate_schema(name='account', obj=account, vo=vo)

    kwargs = {'account': account, 'type': type}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='add_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add account' % (issuer))

    account = InternalAccount(account, vo=vo)

    account_core.add_account(account, AccountType[type.upper()], email)


def del_account(account, issuer, vo='def'):
    """
    Disables an account with the provided account name.

    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    """
    kwargs = {'account': account}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='del_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete account' % (issuer))

    account = InternalAccount(account, vo=vo)

    account_core.del_account(account)


def get_account_info(account, vo='def'):
    """
    Returns the info like the statistics information associated to an account_core.

    :param account: The account name.
    :returns: A list with all account information.
    :param vo: The VO to act on.
    """

    account = InternalAccount(account, vo=vo)

    acc = account_core.get_account(account)
    acc.account = acc.account.external
    return acc


def update_account(account, key, value, issuer='root', vo='def'):
    """ Update a property of an account_core.

    :param account: Name of the account_core.
    :param key: Account property like status.
    :param value: Property value.
    :param issuer: The issuer account
    :param vo: The VO to act on.
    """
    validate_schema(name='account', obj=account, vo=vo)
    kwargs = {}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='update_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not change %s  of the account' % (issuer, key))

    account = InternalAccount(account, vo=vo)

    return account_core.update_account(account, key, value)


def list_accounts(filter={}, vo='def'):
    """
    Lists all the Rucio account names.

    REST API: http://<host>:<port>/rucio/accounts

    :param filter: Dictionary of attributes by which the input data should be filtered
    :param vo: The VO to act on.

    :returns: List of all accounts.
    """
    # If filter is empty, create a new dict to avoid overwriting the function's default
    if not filter:
        filter = {}

    if 'account' in filter:
        filter['account'] = InternalAccount(filter['account'], vo=vo)
    else:
        filter['account'] = InternalAccount(account='*', vo=vo)
    for result in account_core.list_accounts(filter=filter):
        yield api_update_return_dict(result)


def account_exists(account, vo='def'):
    """
    Checks to see if account exists. This procedure does not check it's status.

    :param account: Name of the account.
    :param vo: The VO to act on.
    :returns: True if found, otherwise false.
    """

    account = InternalAccount(account, vo=vo)

    return account_core.account_exists(account)


def list_identities(account, vo='def'):
    """
    List all identities on an account_core.

    :param account: The account name.
    :param vo: The VO to act on.
    """

    account = InternalAccount(account, vo=vo)

    return account_core.list_identities(account)


def list_account_attributes(account, vo='def'):
    """
    Returns all the attributes for the given account.

    :param account: The account name.
    :param vo: The VO to act on
    """

    account = InternalAccount(account, vo=vo)

    return account_core.list_account_attributes(account)


def add_account_attribute(key, value, account, issuer, vo='def'):
    """
    Add an attribute to an account.

    :param key: attribute key.
    :param value: attribute value.
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    validate_schema(name='account_attribute', obj=key, vo=vo)
    validate_schema(name='account_attribute', obj=value, vo=vo)

    kwargs = {'account': account, 'key': key, 'value': value}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='add_attribute', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add attributes' % (issuer))

    account = InternalAccount(account, vo=vo)

    account_core.add_account_attribute(account, key, value)


def del_account_attribute(key, account, issuer, vo='def'):
    """
    Delete an attribute to an account.

    :param key: attribute key.
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    kwargs = {'account': account, 'key': key}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='del_attribute', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete attribute' % (issuer))

    account = InternalAccount(account, vo=vo)

    account_core.del_account_attribute(account, key)


def get_usage(rse, account, issuer, vo='def'):
    """
    Returns current values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse:              The RSE.
    :param account:          The account name.
    :param issuer:           The issuer account.
    :param vo:               The VO to act on.
    :returns:                A dictionary with total and bytes.
    """
    rse_id = get_rse_id(rse=rse, vo=vo)
    account = InternalAccount(account, vo=vo)

    return account_core.get_usage(rse_id, account)


def get_usage_history(rse, account, issuer, vo='def'):
    """
    Returns historical values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse:              The RSE.
    :param account:          The account name.
    :param issuer:           The issuer account.
    :param vo:               The VO to act on.
    :returns:                A dictionary with total and bytes.
    """
    rse_id = get_rse_id(rse=rse, vo=vo)
    account = InternalAccount(account, vo=vo)

    return account_core.get_usage_history(rse_id, account)
