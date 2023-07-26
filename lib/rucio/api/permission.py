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

from copy import deepcopy
from typing import TYPE_CHECKING

from rucio.common.exception import RSENotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import permission
from rucio.core.rse import get_rse_id
from rucio.db.sqla.session import read_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@read_session
def has_permission(issuer, action, kwargs, vo='def', *, session: "Session"):
    """
    Checks if an account has the specified permission to
    execute an action with parameters.

    :param issuer:  The Account issuer.
    :param vo:      The VO to check against.
    :param action:  The action (API call) called by the account.
    :param session: The db session to use
    :param kwargs:  List of arguments for the action.
    :returns: True if account is allowed to call the API call, otherwise False
    """

    kwargs = deepcopy(kwargs)
    if 'rse' in kwargs and 'rse_id' not in kwargs:
        try:
            rse_id = get_rse_id(rse=kwargs.get('rse'), vo=vo, session=session)
        except RSENotFound:
            rse_id = None
        kwargs.update({'rse_id': rse_id})

    if 'scope' in kwargs:
        kwargs['scope'] = InternalScope(kwargs['scope'], vo=vo)
    if 'attachments' in kwargs:
        for a in kwargs['attachments']:
            a['scope'] = InternalScope(a['scope'], vo=vo)

    if 'account' in kwargs:
        kwargs['account'] = InternalAccount(kwargs['account'], vo=vo)
    if 'accounts' in kwargs:
        kwargs['accounts'] = [InternalAccount(a, vo=vo) for a in kwargs['accounts']]
    if 'rules' in kwargs:
        for r in kwargs['rules']:
            r['account'] = InternalAccount(r['account'], vo=vo)
    if 'dids' in kwargs:
        for d in kwargs['dids']:
            if 'rules' in d:
                for r in d['rules']:
                    r['account'] = InternalAccount(r['account'], vo=vo)

    issuer = InternalAccount(issuer, vo=vo)

    return permission.has_permission(issuer=issuer, action=action, kwargs=kwargs, session=session)
