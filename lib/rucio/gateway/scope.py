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

from typing import Any, Optional

import rucio.gateway.permission
from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccessDenied
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import scope as core_scope
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session


def list_scopes(filter_: Optional[dict[str, Any]] = None, vo: str = DEFAULT_VO) -> list[str]:
    """
    Lists all scopes.

    :param filter_: Dictionary of attributes by which the input data should be filtered
    :param vo: The VO to act on.

    :returns: A list containing all scopes.
    """
    # If filter is empty, create a new dict to avoid overwriting the function's default
    filter_ = filter_ or {}

    if 'scope' in filter_:
        filter_['scope'] = InternalScope(scope=filter_['scope'], vo=vo)
    else:
        filter_['scope'] = InternalScope(scope='*', vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        return [scope.external for scope in core_scope.list_scopes(filter_=filter_, session=session)]


def add_scope(
    scope: str,
    account: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Creates a scope for an account.

    :param account: The account name.
    :param scope: The scope identifier.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """

    validate_schema(name='scope', obj=scope, vo=vo)

    kwargs = {'scope': scope, 'account': account}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_scope', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s can not add scope. %s' % (issuer, auth_result.message))

        internal_scope = InternalScope(scope, vo=vo)
        internal_account = InternalAccount(account, vo=vo)

        core_scope.add_scope(internal_scope, internal_account, session=session)


def get_scopes(
    account: str,
    vo: str = DEFAULT_VO,
) -> list[str]:
    """
    Gets a list of all scopes for an account.

    :param account: The account name.
    :param vo: The VO to act on.

    :returns: A list containing the names of all scopes for this account.
    """

    internal_account = InternalAccount(account, vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        return [scope.external for scope in core_scope.get_scopes(internal_account, session=session)]
