# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
# - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin, <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

import rucio.api.permission
import rucio.common.exception

from rucio.common.utils import api_update_return_dict
from rucio.common.types import InternalAccount

from rucio.core import account_limit as account_limit_core
from rucio.core.account import account_exists
from rucio.core.rse import get_rse_id, get_rse_name


def get_rse_account_usage(rse, vo='def'):
    """
    Returns the account limit and usage for all for all accounts on a RSE.

    :param rse:      The RSE name.
    :param vo:       The VO to act on.
    :return:         List of dictionnaries.
    """
    rse_id = get_rse_id(rse=rse, vo=vo)

    return [api_update_return_dict(d) for d in account_limit_core.get_rse_account_usage(rse_id=rse_id)]


def get_local_account_limits(account, vo='def'):
    """
    Lists the limitation names/values for the specified account name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.
    :param vo:          The VO to act on.

    :returns: The account limits.
    """

    account = InternalAccount(account, vo=vo)

    rse_instead_id = {}
    for elem in account_limit_core.get_local_account_limits(account=account).items():
        rse_instead_id[get_rse_name(rse_id=elem[0])] = elem[1]
    return rse_instead_id


def get_local_account_limit(account, rse, vo='def'):
    """
    Lists the limitation names/values for the specified account name and rse name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.
    :param rse:         The rse name.
    :param vo:          The VO to act on.

    :returns: The account limit.
    """

    account = InternalAccount(account, vo=vo)

    rse_id = get_rse_id(rse=rse, vo=vo)
    return {rse: account_limit_core.get_local_account_limit(account=account, rse_id=rse_id)}


def get_global_account_limits(account, vo='def'):
    """
    Lists the limitation names/values for the specified account name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.
    :param vo:          The VO to act on.

    :returns: The account limits.
    """
    if account:
        account = InternalAccount(account, vo=vo)
    else:
        account = InternalAccount('*', vo=vo)

    return account_limit_core.get_global_account_limits(account=account)


def get_global_account_limit(account, rse_expression, vo='def'):
    """
    Lists the limitation names/values for the specified account name and rse expression.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:         The account name.
    :param rse_expression:  The rse expression.
    :param vo:              The VO to act on.

    :returns: The account limit.
    """

    account = InternalAccount(account, vo=vo)

    return {rse_expression: account_limit_core.get_global_account_limit(account=account, rse_expression=rse_expression)}


def set_local_account_limit(account, rse, bytes, issuer, vo='def'):
    """
    Set an account limit..

    :param account: The account name.
    :param rse:     The rse name.
    :param bytes:   The limit in bytes.
    :param issuer:  The issuer account_core.
    :param vo:      The VO to act on.
    """
    rse_id = get_rse_id(rse=rse, vo=vo)

    kwargs = {'account': account, 'rse': rse, 'rse_id': rse_id, 'bytes': bytes}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='set_local_account_limit', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    account_limit_core.set_local_account_limit(account=account, rse_id=rse_id, bytes=bytes)


def set_global_account_limit(account, rse_expression, bytes, issuer, vo='def'):
    """
    Set a global account limit.

    :param account:         The account name.
    :param rse_expression:  The rse expression.
    :param bytes:           The limit in bytes.
    :param issuer:          The issuer account_core.
    :param vo:              The VO to act on.
    """

    kwargs = {'account': account, 'rse_expression': rse_expression, 'bytes': bytes}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='set_global_account_limit', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    account_limit_core.set_global_account_limit(account=account, rse_expression=rse_expression, bytes=bytes)


def delete_local_account_limit(account, rse, issuer, vo='def'):
    """
    Delete an account limit..

    :param account: The account name.
    :param rse:     The rse name.
    :param issuer:  The issuer account_core.
    :param vo:      The VO to act on.

    :returns: True if successful; False otherwise.
    """

    rse_id = get_rse_id(rse=rse, vo=vo)
    kwargs = {'account': account, 'rse': rse, 'rse_id': rse_id}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='delete_local_account_limit', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete account limits.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    return account_limit_core.delete_local_account_limit(account=account, rse_id=rse_id)


def delete_global_account_limit(account, rse_expression, issuer, vo='def'):
    """
    Delete a global account limit..

    :param account:        The account name.
    :param rse_expression: The rse expression.
    :param issuer:         The issuer account_core.
    :param vo:             The VO to act on.

    :returns: True if successful; False otherwise.
    """

    kwargs = {'account': account, 'rse_expression': rse_expression}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='delete_global_account_limit', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not delete global account limits.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    return account_limit_core.delete_global_account_limit(account=account, rse_expression=rse_expression)


def get_local_account_usage(account, rse, issuer, vo='def'):
    """
    Get the account usage and connect it with (if available) the account limits of the account.

    :param account:  The account to read.
    :param rse:      The rse to read (If none, get all).
    :param issuer:   The issuer account.
    :param vo:       The VO to act on.

    :returns:        List of dicts {'rse_id', 'bytes_used', 'files_used', 'bytes_limit'}
    """

    rse_id = None

    if rse:
        rse_id = get_rse_id(rse=rse, vo=vo)
    kwargs = {'account': account, 'rse': rse, 'rse_id': rse_id}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='get_local_account_usage', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not list account usage.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    return [api_update_return_dict(d) for d in account_limit_core.get_local_account_usage(account=account, rse_id=rse_id)]


def get_global_account_usage(account, rse_expression, issuer, vo='def'):
    """
    Get the account usage and connect it with (if available) the account limits of the account.

    :param account:         The account to read.
    :param rse_expression:  The rse expression to read (If none, get all).
    :param issuer:          The issuer account.
    :param vo:              The VO to act on.

    :returns:        List of dicts {'rse_id', 'bytes_used', 'files_used', 'bytes_limit'}
    """

    kwargs = {'account': account, 'rse_expression': rse_expression}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='get_global_account_usage', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not list global account usage.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    return [api_update_return_dict(d) for d in account_limit_core.get_global_account_usage(account=account, rse_expression=rse_expression)]
