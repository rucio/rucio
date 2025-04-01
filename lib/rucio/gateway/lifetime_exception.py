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

from rucio.common import exception
from rucio.common.constants import DEFAULT_VO
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import gateway_update_return_dict
from rucio.core import lifetime_exception
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from rucio.db.sqla.constants import LifetimeExceptionsState


def list_exceptions(
    exception_id: Optional[str] = None,
    states: Optional["Iterable[LifetimeExceptionsState]"] = None,
    vo: str = DEFAULT_VO,
) -> 'Iterator[dict[str, Any]]':
    """
    List exceptions to Lifetime Model.

    :param id:         The id of the exception
    :param states:     The states to filter
    :param vo:         The VO to act on
    """

    with db_session(DatabaseOperationType.READ) as session:
        exceptions = lifetime_exception.list_exceptions(exception_id=exception_id, states=states, session=session)
        for e in exceptions:
            if vo == e['scope'].vo:
                yield gateway_update_return_dict(e, session=session)


def add_exception(
    dids: "Iterable[dict[str, Any]]",
    account: str,
    pattern: str,
    comments: str,
    expires_at: str,
    vo: str = DEFAULT_VO,
) -> dict[str, Any]:
    """
    Add exceptions to Lifetime Model.

    :param dids:        The list of DIDs
    :param account:     The account of the requester.
    :param pattern:     The account.
    :param comments:    The comments associated to the exception.
    :param expires_at:  The expiration date of the exception.
    :param vo:          The VO to act on.

    returns:            The id of the exception.
    """

    internal_account = InternalAccount(account, vo=vo)
    for did in dids:
        did['scope'] = InternalScope(did['scope'], vo=vo)

    with db_session(DatabaseOperationType.WRITE) as session:
        exceptions = lifetime_exception.add_exception(dids=dids, account=internal_account, pattern=pattern, comments=comments, expires_at=expires_at, session=session)

    for key in exceptions:
        if key == 'exceptions':
            for reqid in exceptions[key]:
                for did in exceptions[key][reqid]:
                    did['scope'] = did['scope'].external
                    did['did_type'] = did['did_type'].name
        else:
            for did in exceptions[key]:
                did['scope'] = did['scope'].external
                did['did_type'] = did['did_type'].name

    return exceptions


def update_exception(
    exception_id: str,
    state: 'LifetimeExceptionsState',
    issuer: str,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Update exceptions state to Lifetime Model.

    :param id:         The id of the exception.
    :param state:      The states to filter.
    :param issuer:     The issuer account.
    :param vo:         The VO to act on.
    """
    kwargs = {'exception_id': exception_id, 'vo': vo}

    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='update_lifetime_exceptions', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not update lifetime exceptions. %s' % (issuer, auth_result.message))
        return lifetime_exception.update_exception(exception_id=exception_id, state=state, session=session)
