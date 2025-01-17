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
import rucio.gateway.permission
from rucio.core.common.schema import validate_schema
from rucio.core.common.types import InternalAccount, InternalScope
from rucio.core import scope as core_scope
from rucio.core.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@read_session
def list_scopes(filter_: Optional[dict[str, Any]] = None, vo: str = 'def', *, session: "Session") -> list[str]:
    """
    Lists all scopes.

    :param filter_: Dictionary of attributes by which the input data should be filtered
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: A list containing all scopes.
    """
    # If filter is empty, create a new dict to avoid overwriting the function's default
    filter_ = filter_ or {}

    if 'scope' in filter_:
        filter_['scope'] = InternalScope(scope=filter_['scope'], vo=vo)
    else:
        filter_['scope'] = InternalScope(scope='*', vo=vo)
    return [scope.external for scope in core_scope.list_scopes(filter_=filter_, session=session)]


@transactional_session
def add_scope(
    scope: str,
    account: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> None:
    """
    Creates a scope for an account.

    :param account: The account name.
    :param scope: The scope identifier.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """

    validate_schema(name='scope', obj=scope, vo=vo)

    kwargs = {'scope': scope, 'account': account}
    auth_result = rucio.gateway.permission.has_permission(issuer=issuer, vo=vo, action='add_scope', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise rucio.common.exception.AccessDenied('Account %s can not add scope. %s' % (issuer, auth_result.message))

    internal_scope = InternalScope(scope, vo=vo)
    internal_account = InternalAccount(account, vo=vo)

    core_scope.add_scope(internal_scope, internal_account, session=session)


@read_session
def get_scopes(
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> list[str]:
    """
    Gets a list of all scopes for an account.

    :param account: The account name.
    :param vo: The VO to act on.
    :param session: The database session in use.

    :returns: A list containing the names of all scopes for this account.
    """

    internal_account = InternalAccount(account, vo=vo)

    return [scope.external for scope in core_scope.get_scopes(internal_account, session=session)]
