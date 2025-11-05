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

from typing import TYPE_CHECKING, Any

from rucio.common.constants import DEFAULT_VO
from rucio.core import distance as distance_module
from rucio.core import rse as rse_module

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def export_rses(session: "Session", vo: str = DEFAULT_VO) -> dict[str, dict[str, Any]]:
    """
    Export RSE data.

    :param session: database session in use.
    :param vo: The VO to export.

    :returns: dict with RSE id as key and a dict of the internal representation of an RSE as value.
    """
    data = {}
    for rse in rse_module.list_rses(filters={'vo': vo}, session=session):
        rse_id = rse['id']
        data[rse_id] = rse_module.export_rse(rse_id, session=session)

    return data


def export_data(session: "Session", vo: str = DEFAULT_VO, distance: bool = True) -> dict[str, Any]:
    """
    Export data.

    :param vo: The VO to export.
    :param distance: To enable the reporting of distance.
    :param session: database session in use.

    :returns: dict with rses and distances information.
    """
    if distance:
        data = {
            'rses': export_rses(vo=vo, session=session),
            'distances': distance_module.export_distances(vo, session=session)
        }
    else:
        data = {
            'rses': export_rses(vo=vo, session=session)
        }
    return data
