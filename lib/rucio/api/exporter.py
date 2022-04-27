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
from rucio.common import exception
from rucio.core import exporter
from rucio.core.rse import get_rse_name
from rucio.db.sqla.session import read_session


@read_session
def export_data(issuer, distance=True, vo='def', session=None):
    """
    Export data from Rucio.

    :param issuer: the issuer.
    :param distance: To enable the reporting of distance.
    :param vo: the VO of the issuer.
    :param session: The database session in use.
    """
    kwargs = {'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='export', kwargs=kwargs, session=session):
        raise exception.AccessDenied('Account %s can not export data' % issuer)

    data = exporter.export_data(distance=distance, vo=vo, session=session)
    rses = {}
    distances = {}

    for rse_id in data['rses']:
        rse = data['rses'][rse_id]
        rses[get_rse_name(rse_id=rse_id, session=session)] = rse
    data['rses'] = rses

    if distance:
        for src_id in data['distances']:
            dests = data['distances'][src_id]
            src = get_rse_name(rse_id=src_id, session=session)
            distances[src] = {}
            for dest_id in dests:
                dest = get_rse_name(rse_id=dest_id, session=session)
                distances[src][dest] = dests[dest_id]
        data['distances'] = distances
    return data
