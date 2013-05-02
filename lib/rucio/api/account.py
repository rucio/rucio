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

import rucio.api.permission
import rucio.common.exception
import rucio.core.identity

from rucio.core import account as account_core
from rucio.common.schema import validate_schema

# Expose status through API
account_status = account_core.account_status


def add_account(account, type, issuer):
    """
    Creates an account with the provided account name, contact information, etc.

    :param account: The account name.
    :param type: The account type
    :param issuer: The issuer account_core.

    """

    validate_schema(name='account', obj=account)

    kwargs = {'account': account, 'type': type}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add account' % (issuer))
    account_core.add_account(account, type)


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


def set_account_limits(account, limitationName, limitationValue):
    """
    Set's account's quota limit of account_core.

    :param account:     The account name.
    :param limitationName:  The limitation name.
    :param limitationValue: The limitation value.

    :returns: A Response code is returned and if successful is a "0". If an error occurs, the error message text is also returned.
    """
    raise NotImplementedError


def get_account_limits(account):
    """
    Lists the limitation names/values for the specified account name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.

    :returns: A Response code is returned and if successful is a "0". If an error occurs, the error message text is also returned.
    """
    raise NotImplementedError


def get_account_status(account):
    """
    Returns the state of the account_core.

    :param account: Name of the account_core.
    """
    return account_core.get_account_status(account)


def set_account_status(account, status):
    """ Set the status of an account_core.

    :param account: Name of the account_core.
    :param status: The status for the account_core.
    """
    account_core.set_account_status(account, status)


def list_accounts():
    """
    Lists all the Rucio account names.

    REST API: http://<host>:<port>/rucio/accounts

    :returns: List of all accounts.
    """
    return account_core.list_accounts()


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
