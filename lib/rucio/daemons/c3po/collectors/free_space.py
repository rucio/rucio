# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016

from rucio.db.sqla import models
from rucio.db.sqla.session import read_session


class FreeSpaceCollector():
    """
    Collector to get the SRM free and used information for DATADISK RSEs.
    """
    class __FreeSpaceCollector:
        def __init__(self):
            self.rses = {}

        @read_session
        def _collect_free_space(self, session=None):
            query = session.query(models.RSE.rse, models.RSEUsage.free, models.RSEUsage.used).\
                join(models.RSEUsage, models.RSE.id == models.RSEUsage.rse_id).\
                join(models.RSEAttrAssociation, models.RSE.id == models.RSEAttrAssociation.rse_id).\
                filter(models.RSEUsage.source == 'srm').filter(models.RSEAttrAssociation.key == 'type', models.RSEAttrAssociation.value == 'DATADISK')
            for rse, free, used in query:
                self.rses[rse] = {'total': used+free, 'used': used, 'free': free}

    instance = None

    def __init__(self):
        if not FreeSpaceCollector.instance:
            FreeSpaceCollector.instance = FreeSpaceCollector.__FreeSpaceCollector()

    def collect_free_space(self):
        self.instance._collect_free_space()

    def get_rse_space(self):
        return self.instance.rses
