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

"""
Collector to get the SRM free and used information for DATADISK RSEs.
"""

from rucio.db.sqla.models import RSEUsage, RSEAttrAssociation
from rucio.db.sqla.session import read_session


class FreeSpaceCollector(object):
    """
    Collector to get the SRM free and used information for DATADISK RSEs.
    """
    class _FreeSpaceCollector(object):
        """
        Hidden implementation
        """
        def __init__(self):
            self.rses = {}

        @read_session
        def _collect_free_space(self, session=None):
            """
            Retrieve free space from database
            """
            query = session.query(RSEUsage.rse_id, RSEUsage.free, RSEUsage.used).\
                join(RSEAttrAssociation, RSEUsage.rse_id == RSEAttrAssociation.rse_id).\
                filter(RSEUsage.source == 'storage').filter(RSEAttrAssociation.key == 'type', RSEAttrAssociation.value == 'DATADISK')
            for rse_id, free, used in query:
                self.rses[rse_id] = {'total': used + free, 'used': used, 'free': free}

    instance = None

    def __init__(self):
        if not FreeSpaceCollector.instance:
            FreeSpaceCollector.instance = FreeSpaceCollector._FreeSpaceCollector()

    def collect_free_space(self):
        """
        Execute the free space collector
        """
        self.instance._collect_free_space()

    def get_rse_space(self):
        """
        Return the RSE space
        """
        return self.instance.rses
