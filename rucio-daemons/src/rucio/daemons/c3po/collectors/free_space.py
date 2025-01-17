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

"""
Collector to get the SRM free and used information for DATADISK RSEs.
"""

from typing import TYPE_CHECKING, Optional

from sqlalchemy import and_, select

from rucio.core.db.sqla.models import RSEAttrAssociation, RSEUsage
from rucio.core.db.sqla.session import read_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


class FreeSpaceCollector:
    """
    Collector to get the SRM free and used information for DATADISK RSEs.
    """
    class _FreeSpaceCollector:
        """
        Hidden implementation
        """
        def __init__(self):
            self.rses = {}

        @read_session
        def _collect_free_space(
            self,
            *,
            session: Optional["Session"] = None
        ) -> None:
            """
            Retrieve free space from database
            """
            stmt = select(
                RSEUsage.rse_id,
                RSEUsage.free,
                RSEUsage.used
            ).join(
                RSEAttrAssociation,
                RSEAttrAssociation.rse_id == RSEUsage.rse_id
            ).where(
                and_(RSEUsage.source == 'storage',
                     RSEAttrAssociation.key == 'type',
                     RSEAttrAssociation.value == 'DATADISK'),
            )
            for rse_id, free, used in session.execute(stmt).all():  # type: ignore (session could be None)
                self.rses[rse_id] = {'total': used + free, 'used': used, 'free': free}

    instance = None

    def __init__(self):
        if not FreeSpaceCollector.instance:
            FreeSpaceCollector.instance = FreeSpaceCollector._FreeSpaceCollector()

    def collect_free_space(self) -> None:
        """
        Execute the free space collector
        """
        self.instance._collect_free_space()  # type: ignore

    def get_rse_space(self) -> dict[str, dict[str, int]]:
        """
        Return the RSE space
        """
        return self.instance.rses  # type: ignore
