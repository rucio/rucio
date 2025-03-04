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

from typing import TYPE_CHECKING, Any, Optional

import rucio.common.exception
import rucio.core.identity
import rucio.gateway.permission
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount
from rucio.common.utils import gateway_update_return_dict
from rucio.core import account as account_core
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import AccountType
from rucio.db.sqla.session import read_session, stream_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.orm import Session

    from rucio.common.types import AccountAttributesDict, IdentityDict, UsageDict
    from rucio.db.sqla.models import Account


@transactional_session
def add_account(
    account: str,
    type_: str,
    email: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> None:
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
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_account', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not add account. %s' % (issuer, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    account_core.add_account(internal_account, AccountType[type_.upper()], email, session=session)


@transactional_session
def del_account(
    account: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> None:
    """
    Disables an account with the provided account name.

    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.

    """
    kwargs = {'account': account}
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='del_account', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not delete account. %s' % (issuer, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    account_core.del_account(internal_account, session=session)


@read_session
def get_account_info(
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> "Account":
    """
    Returns the info like the statistics information associated to an account_core.

    :param account: The account name.
    :returns: A list with all account information.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """

    internal_account = InternalAccount(account, vo=vo)

    acc = account_core.get_account(internal_account, session=session)
    acc.account = acc.account.external
    return acc


@transactional_session
def update_account(
    account: str,
    key: str,
    value: Any,
    issuer: str = 'root',
    vo: str = 'def',
    *,
    session: "Session"
) -> None:
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
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='update_account', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not change %s  of the account. %s' % (issuer, key, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    return account_core.update_account(internal_account, key, value, session=session)


@stream_session
def list_accounts(filter_: Optional[dict[str, Any]] = None, vo: str = 'def', *, session: "Session") -> 'Iterator[dict[str, Any]]':
    """
    Lists all the Rucio account names.

    REST API: http://<host>:<port>/rucio/accounts

    :param filter_: Dictionary of attributes by which the input data should be filtered
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: List of all accounts.
    """
    # If filter is empty, create a new dict to avoid overwriting the function's default
    filter_ = filter_ or {}

    if 'account' in filter_:
        filter_['account'] = InternalAccount(filter_['account'], vo=vo)
    else:
        filter_['account'] = InternalAccount(account='*', vo=vo)
    for result in account_core.list_accounts(filter_=filter_, session=session):
        yield gateway_update_return_dict(result, session=session)


@read_session
def account_exists(
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> bool:
    """
    Checks to see if account exists. This procedure does not check it's status.

    :param account: Name of the account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: True if found, otherwise false.
    """

    internal_account = InternalAccount(account, vo=vo)

    return account_core.account_exists(internal_account, session=session)


@read_session
def list_identities(
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> list["IdentityDict"]:
    """
    List all identities on an account_core.

    :param account: The account name.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """

    internal_account = InternalAccount(account, vo=vo)

    return account_core.list_identities(internal_account, session=session)


@read_session
def list_account_attributes(
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> list["AccountAttributesDict"]:
    """
    Returns all the attributes for the given account.

    :param account: The account name.
    :param vo: The VO to act on
    :param session: The database session in use.
    """

    internal_account = InternalAccount(account, vo=vo)

    return account_core.list_account_attributes(internal_account, session=session)


@transactional_session
def add_account_attribute(
    key: str,
    value: Any,
    account: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> None:
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
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_attribute', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not add attributes. %s' % (issuer, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    account_core.add_account_attribute(internal_account, key, value, session=session)


@transactional_session
def del_account_attribute(
    key: str,
    account: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> None:
    """
    Delete an attribute to an account.

    :param key: attribute key.
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    kwargs = {'account': account, 'key': key}
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='del_attribute', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not delete attribute. %s' % (issuer, auth_result.message))

    internal_account = InternalAccount(account, vo=vo)

    account_core.del_account_attribute(internal_account, key, session=session)


@read_session
def get_usage(
    rse: str,
    account: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> "UsageDict":
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
    internal_account = InternalAccount(account, vo=vo)

    return account_core.get_usage(rse_id, internal_account, session=session)


@read_session
def get_usage_history(
    rse: str,
    account: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> list["UsageDict"]:
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
    internal_account = InternalAccount(account, vo=vo)

    return account_core.get_usage_history(rse_id, internal_account, session=session)
