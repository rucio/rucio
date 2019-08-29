# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016-2017
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

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
