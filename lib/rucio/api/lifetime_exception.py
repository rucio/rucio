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

from rucio.api import permission
from rucio.core import lifetime_exception
from rucio.common import exception
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import api_update_return_dict
from rucio.db.sqla.session import stream_session, transactional_session


@stream_session
def list_exceptions(exception_id=None, states=None, vo='def', session=None):
    """
    List exceptions to Lifetime Model.

    :param id:         The id of the exception
    :param states:     The states to filter
    :param vo:         The VO to act on
    :param session:    The database session in use.
    """

    exceptions = lifetime_exception.list_exceptions(exception_id=exception_id, states=states, session=session)
    for e in exceptions:
        if vo == e['scope'].vo:
            yield api_update_return_dict(e, session=session)


@transactional_session
def add_exception(dids, account, pattern, comments, expires_at, vo='def', session=None):
    """
    Add exceptions to Lifetime Model.

    :param dids:        The list of dids
    :param account:     The account of the requester.
    :param pattern:     The account.
    :param comments:    The comments associated to the exception.
    :param expires_at:  The expiration date of the exception.
    :param vo:          The VO to act on.
    :param session:     The database session in use.

    returns:            The id of the exception.
    """

    account = InternalAccount(account, vo=vo)
    for did in dids:
        did['scope'] = InternalScope(did['scope'], vo=vo)
    exceptions = lifetime_exception.add_exception(dids=dids, account=account, pattern=pattern, comments=comments, expires_at=expires_at, session=session)

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


@transactional_session
def update_exception(exception_id, state, issuer, vo='def', session=None):
    """
    Update exceptions state to Lifetime Model.

    :param id:         The id of the exception.
    :param state:      The states to filter.
    :param issuer:     The issuer account.
    :param vo:         The VO to act on.
    :param session:    The database session in use.
    """
    kwargs = {'exception_id': exception_id, 'vo': vo}
    if not permission.has_permission(issuer=issuer, vo=vo, action='update_lifetime_exceptions', kwargs=kwargs, session=session):
        raise exception.AccessDenied('Account %s can not update lifetime exceptions' % (issuer))
    return lifetime_exception.update_exception(exception_id=exception_id, state=state, session=session)
