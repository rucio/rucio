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
from rucio.common.constants import DEFAULT_VO
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount
from rucio.common.utils import gateway_update_return_dict
from rucio.core import account as account_core
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import AccountType, DatabaseOperationType
from rucio.db.sqla.session import db_session

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rucio.common.types import AccountAttributesDict, IdentityDict, UsageDict
    from rucio.db.sqla.models import Account


def add_account(
    account: str,
    type_: str,
    email: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Creates an account with the provided account name, contact information, etc.

    :param account: The account name.
    :param type_: The account type
    :param email: The Email address associated with the account.

    :param issuer: The issuer account_core.
    :param vo: The VO to act on.

    """

    validate_schema(name='account', obj=account, vo=vo)

    kwargs = {'account': account, 'type': type_}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_account', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise rucio.common.exception.AccessDenied('Account %s can not add account. %s' % (issuer, auth_result.message))

        internal_account = InternalAccount(account, vo=vo)

        account_core.add_account(internal_account, AccountType[type_.upper()], email, session=session)


def del_account(
    account: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Disables an account with the provided account name.

    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    """
    kwargs = {'account': account}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='del_account', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise rucio.common.exception.AccessDenied('Account %s can not delete account. %s' % (issuer, auth_result.message))

        internal_account = InternalAccount(account, vo=vo)

        account_core.del_account(internal_account, session=session)


def get_account_info(
    account: str,
    vo: str = DEFAULT_VO,
) -> "Account":
    """
    Returns the info like the statistics information associated to an account_core.

    :param account: The account name.
    :returns: A list with all account information.
    :param vo: The VO to act on.

    """

    internal_account = InternalAccount(account, vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        acc = account_core.get_account(internal_account, session=session)
        acc.account = acc.account.external
        return acc


def update_account(
    account: str,
    key: str,
    value: Any,
    issuer: str = 'root',
    vo: str = DEFAULT_VO,
) -> None:
    """ Update a property of an account_core.

    :param account: Name of the account_core.
    :param key: Account property like status.
    :param value: Property value.
    :param issuer: The issuer account
    :param vo: The VO to act on.

    """
    validate_schema(name='account', obj=account, vo=vo)
    kwargs = {}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='update_account', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise rucio.common.exception.AccessDenied('Account %s can not change %s  of the account. %s' % (issuer, key, auth_result.message))

        internal_account = InternalAccount(account, vo=vo)

        return account_core.update_account(internal_account, key, value, session=session)


def list_accounts(filter_: Optional[dict[str, Any]] = None, vo: str = DEFAULT_VO) -> 'Iterator[dict[str, Any]]':
    """
    Lists all the Rucio account names.

    REST API: http://<host>:<port>/rucio/accounts

    :param filter_: Dictionary of attributes by which the input data should be filtered
    :param vo: The VO to act on.

    :returns: List of all accounts.
    """
    # If filter is empty, create a new dict to avoid overwriting the function's default
    filter_ = filter_ or {}

    if 'account' in filter_:
        filter_['account'] = InternalAccount(filter_['account'], vo=vo)
    else:
        filter_['account'] = InternalAccount(account='*', vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        for result in account_core.list_accounts(filter_=filter_, session=session):
            yield gateway_update_return_dict(result, session=session)


def account_exists(
    account: str,
    vo: str = DEFAULT_VO,
) -> bool:
    """
    Checks to see if account exists. This procedure does not check it's status.

    :param account: Name of the account.
    :param vo: The VO to act on.

    :returns: True if found, otherwise false.
    """

    internal_account = InternalAccount(account, vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        return account_core.account_exists(internal_account, session=session)


def list_identities(
    account: str,
    vo: str = DEFAULT_VO,
) -> list["IdentityDict"]:
    """
    List all identities on an account_core.

    :param account: The account name.
    :param vo: The VO to act on.

    """

    internal_account = InternalAccount(account, vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        return account_core.list_identities(internal_account, session=session)


def list_account_attributes(
    account: str,
    vo: str = DEFAULT_VO,
) -> list["AccountAttributesDict"]:
    """
    Returns all the attributes for the given account.

    :param account: The account name.
    :param vo: The VO to act on

    """

    internal_account = InternalAccount(account, vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        return account_core.list_account_attributes(internal_account, session=session)


def add_account_attribute(
    key: str,
    value: Any,
    account: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> None:
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
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_attribute', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise rucio.common.exception.AccessDenied('Account %s can not add attributes. %s' % (issuer, auth_result.message))

        internal_account = InternalAccount(account, vo=vo)

        account_core.add_account_attribute(internal_account, key, value, session=session)


def del_account_attribute(
    key: str,
    account: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Delete an attribute to an account.

    :param key: attribute key.
    :param account: The account name.
    :param issuer: The issuer account.
    :param vo: The VO to act on.

    """
    kwargs = {'account': account, 'key': key}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='del_attribute', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise rucio.common.exception.AccessDenied('Account %s can not delete attribute. %s' % (issuer, auth_result.message))

        internal_account = InternalAccount(account, vo=vo)

        account_core.del_account_attribute(internal_account, key, session=session)


def get_usage(
    rse: str,
    account: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> "UsageDict":
    """
    Returns current values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse:              The RSE.
    :param account:          The account name.
    :param issuer:           The issuer account.
    :param vo:               The VO to act on.

    :returns:                A dictionary with total and bytes.
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)
        internal_account = InternalAccount(account, vo=vo)

        return account_core.get_usage(rse_id, internal_account, session=session)


def get_usage_history(
    rse: str,
    account: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> list["UsageDict"]:
    """
    Returns historical values of the specified counter, or raises CounterNotFound if the counter does not exist.

    :param rse:              The RSE.
    :param account:          The account name.
    :param issuer:           The issuer account.
    :param vo:               The VO to act on.

    :returns:                A dictionary with total and bytes.
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)
        internal_account = InternalAccount(account, vo=vo)

        return account_core.get_usage_history(rse_id, internal_account, session=session)
