# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015
#
# PY3K COMPATIBLE

import rucio.api.permission
import rucio.common.exception

from rucio.core import account_limit as account_limit_core
from rucio.core.account import account_exists
from rucio.core.rse import get_rse_id, get_rse_name


def get_rse_account_usage(rse):
    """
    Returns the account limit and usage for all for all accounts on a RSE.

    :param rse:      The RSE name.
    :return:         List of dictionnaries.
    """
    return account_limit_core.get_rse_account_usage(rse=rse)


def get_account_limits(account):
    """
    Lists the limitation names/values for the specified account name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.

    :returns: The account limits.
    """

    rse_instead_id = {}
    for elem in account_limit_core.get_account_limits(account=account).items():
        rse_instead_id[get_rse_name(elem[0])] = elem[1]
    return rse_instead_id


def get_account_limit(account, rse):
    """
    Lists the limitation names/values for the specified account name and rse name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.
    :param rse:         The rse name.

    :returns: The account limit.
    """

    rse_id = get_rse_id(rse=rse)
    return {rse: account_limit_core.get_account_limit(account=account, rse_id=rse_id)}


def set_account_limit(account, rse, bytes, issuer):
    """
    Set an account limit..

    :param account: The account name.
    :param rse:     The rse name.
    :param bytes:   The limit in bytes.
    :param issuer:  The issuer account_core.
    """

    kwargs = {'account': account, 'rse': rse, 'bytes': bytes}
    if not rucio.api.permission.has_permission(issuer=issuer, action='set_account_limit', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits.' % (issuer))

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    rse_id = get_rse_id(rse=rse)
    account_limit_core.set_account_limit(account=account, rse_id=rse_id, bytes=bytes)


def delete_account_limit(account, rse, issuer):
    """
    Delete an account limit..

    :param account: The account name.
    :param rse:     The rse name.
    :param issuer:  The issuer account_core.

    :returns: True if successful; False otherwise.
    """

    kwargs = {'account': account, 'rse': rse}
    if not rucio.api.permission.has_permission(issuer=issuer, action='delete_account_limit', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete account limits.' % (issuer))

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    rse_id = get_rse_id(rse=rse)
    return account_limit_core.delete_account_limit(account=account, rse_id=rse_id)


def get_account_usage(account, rse, issuer):
    """
    Get the account usage and connect it with (if available) the account limits of the account.

    :param account:  The account to read.
    :param rse:      The rse to read (If none, get all).
    :param issuer:   The issuer account.

    :returns:        List of dicts {'rse_id', 'bytes_used', 'files_used', 'bytes_limit'}
    """

    kwargs = {'account': account, 'rse': rse}
    if not rucio.api.permission.has_permission(issuer=issuer, action='get_account_usage', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not list account usage.' % (issuer))

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    rse_id = None
    if rse:
        rse_id = get_rse_id(rse=rse)
    return account_limit_core.get_account_usage(account=account, rse_id=rse_id)
