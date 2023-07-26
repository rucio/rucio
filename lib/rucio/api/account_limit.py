# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from typing import TYPE_CHECKING

import rucio.api.permission
import rucio.common.exception
from rucio.common.types import InternalAccount
from rucio.common.utils import api_update_return_dict
from rucio.core import account_limit as account_limit_core
from rucio.core.account import account_exists
from rucio.core.rse import get_rse_id, get_rse_name
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@read_session
def get_rse_account_usage(rse, vo='def', *, session: "Session"):
    """
    Returns the account limit and usage for all for all accounts on a RSE.

    :param rse:      The RSE name.
    :param vo:       The VO to act on.
    :param session:  The database session in use.
    :return:         List of dictionnaries.
    """
    rse_id = get_rse_id(rse=rse, vo=vo, session=session)

    return [api_update_return_dict(d, session=session) for d in account_limit_core.get_rse_account_usage(rse_id=rse_id, session=session)]


@read_session
def get_local_account_limits(account, vo='def', *, session: "Session"):
    """
    Lists the limitation names/values for the specified account name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.
    :param vo:          The VO to act on.
    :param session:     The database session in use.

    :returns: The account limits.
    """

    account = InternalAccount(account, vo=vo)

    rse_instead_id = {}
    for elem in account_limit_core.get_local_account_limits(account=account, session=session).items():
        rse_instead_id[get_rse_name(rse_id=elem[0], session=session)] = elem[1]
    return rse_instead_id


@read_session
def get_local_account_limit(account, rse, vo='def', *, session: "Session"):
    """
    Lists the limitation names/values for the specified account name and rse name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.
    :param rse:         The rse name.
    :param vo:          The VO to act on.
    :param session:     The database session in use.

    :returns: The account limit.
    """

    account = InternalAccount(account, vo=vo)

    rse_id = get_rse_id(rse=rse, vo=vo, session=session)
    return {rse: account_limit_core.get_local_account_limit(account=account, rse_id=rse_id, session=session)}


@read_session
def get_global_account_limits(account, vo='def', *, session: "Session"):
    """
    Lists the limitation names/values for the specified account name.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:     The account name.
    :param vo:          The VO to act on.
    :param session:     The database session in use.

    :returns: The account limits.
    """
    if account:
        account = InternalAccount(account, vo=vo)
    else:
        account = InternalAccount('*', vo=vo)

    return account_limit_core.get_global_account_limits(account=account, session=session)


@read_session
def get_global_account_limit(account, rse_expression, vo='def', *, session: "Session"):
    """
    Lists the limitation names/values for the specified account name and rse expression.

    REST API: http://<host>:<port>/rucio/account/<account>/limits

    :param account:         The account name.
    :param rse_expression:  The rse expression.
    :param vo:              The VO to act on.
    :param session:         The database session in use.

    :returns: The account limit.
    """

    account = InternalAccount(account, vo=vo)

    return {rse_expression: account_limit_core.get_global_account_limit(account=account, rse_expression=rse_expression, session=session)}


@transactional_session
def set_local_account_limit(account, rse, bytes_, issuer, vo='def', *, session: "Session"):
    """
    Set an account limit..

    :param account: The account name.
    :param rse:     The rse name.
    :param bytes_:   The limit in bytes.
    :param issuer:  The issuer account_core.
    :param vo:      The VO to act on.
    :param session: The database session in use.
    """
    rse_id = get_rse_id(rse=rse, vo=vo, session=session)

    kwargs = {'account': account, 'rse': rse, 'rse_id': rse_id, 'bytes': bytes_}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='set_local_account_limit', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account, session=session):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    account_limit_core.set_local_account_limit(account=account, rse_id=rse_id, bytes_=bytes_, session=session)


@transactional_session
def set_global_account_limit(account, rse_expression, bytes_, issuer, vo='def', *, session: "Session"):
    """
    Set a global account limit.

    :param account:         The account name.
    :param rse_expression:  The rse expression.
    :param bytes_:           The limit in bytes.
    :param issuer:          The issuer account_core.
    :param vo:              The VO to act on.
    :param session:         The database session in use.
    """

    kwargs = {'account': account, 'rse_expression': rse_expression, 'bytes': bytes_}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='set_global_account_limit', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not set account limits.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account, session=session):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    account_limit_core.set_global_account_limit(account=account, rse_expression=rse_expression, bytes_=bytes_, session=session)


@transactional_session
def delete_local_account_limit(account, rse, issuer, vo='def', *, session: "Session"):
    """
    Delete an account limit..

    :param account: The account name.
    :param rse:     The rse name.
    :param issuer:  The issuer account_core.
    :param vo:      The VO to act on.
    :param session: The database session in use.

    :returns: True if successful; False otherwise.
    """

    rse_id = get_rse_id(rse=rse, vo=vo, session=session)
    kwargs = {'account': account, 'rse': rse, 'rse_id': rse_id}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='delete_local_account_limit', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not delete account limits.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account, session=session):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    return account_limit_core.delete_local_account_limit(account=account, rse_id=rse_id, session=session)


@transactional_session
def delete_global_account_limit(account, rse_expression, issuer, vo='def', *, session: "Session"):
    """
    Delete a global account limit..

    :param account:        The account name.
    :param rse_expression: The rse expression.
    :param issuer:         The issuer account_core.
    :param vo:             The VO to act on.
    :param session:        The database session in use.

    :returns: True if successful; False otherwise.
    """

    kwargs = {'account': account, 'rse_expression': rse_expression}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='delete_global_account_limit', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not delete global account limits.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account, session=session):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    return account_limit_core.delete_global_account_limit(account=account, rse_expression=rse_expression, session=session)


@read_session
def get_local_account_usage(account, rse, issuer, vo='def', *, session: "Session"):
    """
    Get the account usage and connect it with (if available) the account limits of the account.

    :param account:  The account to read.
    :param rse:      The rse to read (If none, get all).
    :param issuer:   The issuer account.
    :param vo:       The VO to act on.
    :param session:  The database session in use.

    :returns:        List of dicts {'rse_id', 'rse', 'bytes', 'files', 'bytes_limit', 'bytes_remaining'}
    """

    rse_id = None

    if rse:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)
    kwargs = {'account': account, 'rse': rse, 'rse_id': rse_id}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='get_local_account_usage', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not list account usage.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account, session=session):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    return [api_update_return_dict(d, session=session) for d in account_limit_core.get_local_account_usage(account=account, rse_id=rse_id, session=session)]


@read_session
def get_global_account_usage(account, rse_expression, issuer, vo='def', *, session: "Session"):
    """
    Get the account usage and connect it with (if available) the account limits of the account.

    :param account:         The account to read.
    :param rse_expression:  The rse expression to read (If none, get all).
    :param issuer:          The issuer account.
    :param vo:              The VO to act on.
    :param session:         The database session in use.

    :returns:               List of dicts {'rse_id', 'rse', 'bytes', 'files', 'bytes_limit', 'bytes_remaining'}
    """

    kwargs = {'account': account, 'rse_expression': rse_expression}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='get_global_account_usage', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not list global account usage.' % (issuer))

    account = InternalAccount(account, vo=vo)

    if not account_exists(account=account, session=session):
        raise rucio.common.exception.AccountNotFound('Account %s does not exist' % (account))

    return [api_update_return_dict(d, session=session) for d in account_limit_core.get_global_account_usage(account=account, rse_expression=rse_expression, session=session)]
