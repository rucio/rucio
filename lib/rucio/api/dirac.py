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

from rucio.api.permission import has_permission
from rucio.api.scope import list_scopes

from rucio.core.rse import get_rse_id
from rucio.core import dirac
from rucio.common.exception import AccessDenied
from rucio.common.utils import extract_scope
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def add_files(lfns, issuer, ignore_availability, vo='def', *, session: "Session"):
    """
    Bulk add files :
    - Create the file and replica.
    - If doesn't exist create the dataset containing the file as well as a rule on the dataset on ANY sites.
    - Create all the ascendants of the dataset if they do not exist

    :param lfns: List of lfn (dictionary {'lfn': <lfn>, 'rse': <rse>, 'bytes': <bytes>, 'adler32': <adler32>, 'guid': <guid>, 'pfn': <pfn>}
    :param issuer: The issuer account.
    :param ignore_availability: A boolean to ignore blocked sites.
    :param vo: The VO to act on.
    :param session: The database session in use.

    """
    scopes = list_scopes(vo=vo, session=session)
    dids = []
    rses = {}
    for lfn in lfns:
        scope, name = extract_scope(lfn['lfn'], scopes)
        dids.append({'scope': scope, 'name': name})
        rse = lfn['rse']
        if rse not in rses:
            rse_id = get_rse_id(rse=rse, vo=vo, session=session)
            rses[rse] = rse_id
        lfn['rse_id'] = rses[rse]

    # Check if the issuer can add dids and use skip_availabitlity
    for rse in rses:
        rse_id = rses[rse]
        kwargs = {'rse': rse, 'rse_id': rse_id}
        if not has_permission(issuer=issuer, action='add_replicas', kwargs=kwargs, vo=vo, session=session):
            raise AccessDenied('Account %s can not add file replicas on %s for VO %s' % (issuer, rse, vo))
        if not has_permission(issuer=issuer, action='skip_availability_check', kwargs=kwargs, vo=vo, session=session):
            ignore_availability = False

    # Check if the issuer can add the files
    kwargs = {'issuer': issuer, 'dids': dids}
    if not has_permission(issuer=issuer, action='add_dids', kwargs=kwargs, vo=vo, session=session):
        raise AccessDenied('Account %s can not bulk add data identifier for VO %s' % (issuer, vo))

    dirac.add_files(lfns=lfns, account=issuer, ignore_availability=ignore_availability, vo=vo, session=session)
