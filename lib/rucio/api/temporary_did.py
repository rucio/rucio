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

from rucio.common.types import InternalAccount, InternalScope
from rucio.core import temporary_did
from rucio.core.rse import get_rse_id
from rucio.db.sqla.session import transactional_session


@transactional_session
def add_temporary_dids(dids, issuer, vo='def', session=None):
    """
    Bulk add temporary data identifiers.

    :param dids: A list of dids.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    for did in dids:
        if 'rse' in did and 'rse_id' not in did:
            rse_id = None
            if did['rse'] is not None:
                rse_id = get_rse_id(rse=did['rse'], vo=vo, session=session)
            did['rse_id'] = rse_id
        if 'scope' in did:
            did['scope'] = InternalScope(did['scope'], vo=vo)
        if 'parent_scope' in did:
            did['parent_scope'] = InternalScope(did['parent_scope'], vo=vo)

    issuer = InternalAccount(issuer, vo=vo)
    return temporary_did.add_temporary_dids(dids=dids, account=issuer, session=session)
