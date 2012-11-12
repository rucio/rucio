# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2011
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012

import rucio.api.permission
import rucio.common.exception
import rucio.core.identity

from rucio.core import account


# Expose status through API
account_status = account.account_status


def add_account(account_name, account_type, issuer):
    """
    Creates an account with the provided account name, contact information, etc.

    :param account_name: The account name.
    :param account_type: The account type
    :param issuer: The issuer account.

    """
    kwargs = {'account_name': account_name, 'account_type': account_type}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add account' % (issuer))
    account.add_account(account_name, account_type)


def del_account(account_name, issuer):
    """
    Disables an account with the provided account name.

    :param account_name: The account name.
    :param issuer: The issuer account.

    """
    kwargs = {'account_name': account_name}
    if not rucio.api.permission.has_permission(issuer=issuer, action='del_account', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete account' % (issuer))

    account.del_account(account_name)


def get_account_info(account_name):
    """
    Returns the info like the statistics information associated to an account.

    :param account_name: The account name.
    :returns: A list with all account information.
    """
    return account.get_account(account_name)


def set_account_limits(account_name, limitationName, limitationValue):
    """
    Set's account's quota limit of account.

    :param account_name:     The account name.
    :param limitationName:  The limitation name.
    :param limitationValue: The limitation value.

    :returns: A Response code is returned and if successful is a "0". If an error occurs, the error message text is also returned.
    """
    raise NotImplementedError


def get_account_limits(account_name):
    """
    Lists the limitation names/values for the specified account name.

    REST API: http://<host>:<port>/rucio/account/<account_name>/limits

    :param account_name:     The account name.

    :returns: A Response code is returned and if successful is a "0". If an error occurs, the error message text is also returned.
    """
    raise NotImplementedError


def get_account_status(account_name):
    """
    Returns the state of the account.

    :param account_name: Name of the account.
    """
    return account.get_account_status(account_name)


def set_account_status(account_name, status):
    """ Set the status of an account.

    :param account_name: Name of the account.
    :param status: The status for the account.
    """
    account.set_account_status(account_name, status)


def list_accounts():
    """
    Lists all the Rucio account names.

    REST API: http://<host>:<port>/rucio/accounts

    :returns: List of all accounts.
    """
    return account.list_accounts()


def account_exists(account_name):
    """
    Checks to see if account exists. This procedure does not check it's status.

    :param account_name: Name of the account.
    :returns: True if found, otherwise false.
    """
    return account.account_exists(account_name)


def list_identities(account_name):
    """
    List all identities on an account.

    :param account_name: The account name.
    """
    return account.list_identities(account_name)
