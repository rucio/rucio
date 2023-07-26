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
import rucio.core.identity
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount
from rucio.common.utils import api_update_return_dict
from rucio.core import account as account_core
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import AccountType
from rucio.db.sqla.session import read_session, stream_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def add_account(account, type_, email, issuer, vo='def', *, session: "Session"):
    """
    Creates an account with the provided account name, contact information, etc.

    :param account: The account name.
    :param type_: The account type
    :param email: The Email address associated with the account.

    :param issuer: The issuer account_core.
    :param vo: The VO to act on.
    :param session: The database session in use.

    """

    validate_schema(name='account', obj=account, vo=vo)

    kwargs = {'account': account, 'type': type_}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='add_account', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not add account' % (issuer))

    account = InternalAccount(account, vo=vo)

    account_core.add_account(account, AccountType[type_.upper()], email, session=session)


@transactional_session
def del_account(account, issuer, vo='def', *, session: "Session"):
    """
    Disables an account with the provided account name.

    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.

    """
    kwargs = {'account': account}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='del_account', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not delete account' % (issuer))

    account = InternalAccount(account, vo=vo)

    account_core.del_account(account, session=session)


@read_session
def get_account_info(account, vo='def', *, session: "Session"):
    """
    Returns the info like the statistics information associated to an account_core.

    :param account: The account name.
    :returns: A list with all account information.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """

    account = InternalAccount(account, vo=vo)

    acc = account_core.get_account(account, session=session)
    acc.account = acc.account.external
    return acc


@transactional_session
def update_account(account, key, value, issuer='root', vo='def', *, session: "Session"):
    """ Update a property of an account_core.

    :param account: Name of the account_core.
    :param key: Account property like status.
    :param value: Property value.
    :param issuer: The issuer account
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    validate_schema(name='account', obj=account, vo=vo)
    kwargs = {}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='update_account', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not change %s  of the account' % (issuer, key))

    account = InternalAccount(account, vo=vo)

    return account_core.update_account(account, key, value, session=session)


@stream_session
def list_accounts(filter_={}, vo='def', *, session: "Session"):
    """
    Lists all the Rucio account names.

    REST API: http://<host>:<port>/rucio/accounts

    :param filter_: Dictionary of attributes by which the input data should be filtered
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: List of all accounts.
    """
    # If filter is empty, create a new dict to avoid overwriting the function's default
    if not filter_:
        filter_ = {}

    if 'account' in filter_:
        filter_['account'] = InternalAccount(filter_['account'], vo=vo)
    else:
        filter_['account'] = InternalAccount(account='*', vo=vo)
    for result in account_core.list_accounts(filter_=filter_, session=session):
        yield api_update_return_dict(result, session=session)


@read_session
def account_exists(account, vo='def', *, session: "Session"):
    """
    Checks to see if account exists. This procedure does not check it's status.

    :param account: Name of the account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: True if found, otherwise false.
    """

    account = InternalAccount(account, vo=vo)

    return account_core.account_exists(account, session=session)


@read_session
def list_identities(account, vo='def', *, session: "Session"):
    """
    List all identities on an account_core.

    :param account: The account name.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """

    account = InternalAccount(account, vo=vo)

    return account_core.list_identities(account, session=session)


@read_session
def list_account_attributes(account, vo='def', *, session: "Session"):
    """
    Returns all the attributes for the given account.

    :param account: The account name.
    :param vo: The VO to act on
    :param session: The database session in use.
    """

    account = InternalAccount(account, vo=vo)

    return account_core.list_account_attributes(account, session=session)


@transactional_session
def add_account_attribute(key, value, account, issuer, vo='def', *, session: "Session"):
    """
    Add an attribute to an account.

    :param key: attribute key.
    :param value: attribute value.
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    validate_schema(name='account_attribute', obj=key, vo=vo)
    validate_schema(name='account_attribute', obj=value, vo=vo)

    kwargs = {'account': account, 'key': key, 'value': value}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='add_attribute', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not add attributes' % (issuer))

    account = InternalAccount(account, vo=vo)

    account_core.add_account_attribute(account, key, value, session=session)


@transactional_session
def del_account_attribute(key, account, issuer, vo='def', *, session: "Session"):
    """
    Delete an attribute to an account.

    :param key: attribute key.
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    kwargs = {'account': account, 'key': key}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='del_attribute', kwargs=kwargs, session=session):
        raise rucio.common.exception.AccessDenied('Account %s can not delete attribute' % (issuer))

    account = InternalAccount(account, vo=vo)

    account_core.del_account_attribute(account, key, session=session)


@read_session
def get_usage(rse, account, issuer, vo='def', *, session: "Session"):
    """
    Returns current values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse:              The RSE.
    :param account:          The account name.
    :param issuer:           The issuer account.
    :param vo:               The VO to act on.
    :param session:          The database session in use.
    :returns:                A dictionary with total and bytes.
    """
    rse_id = get_rse_id(rse=rse, vo=vo, session=session)
    account = InternalAccount(account, vo=vo)

    return account_core.get_usage(rse_id, account, session=session)


@read_session
def get_usage_history(rse, account, issuer, vo='def', *, session: "Session"):
    """
    Returns historical values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse:              The RSE.
    :param account:          The account name.
    :param issuer:           The issuer account.
    :param vo:               The VO to act on.
    :param session:          The database session in use.
    :returns:                A dictionary with total and bytes.
    """
    rse_id = get_rse_id(rse=rse, vo=vo, session=session)
    account = InternalAccount(account, vo=vo)

    return account_core.get_usage_history(rse_id, account, session=session)
