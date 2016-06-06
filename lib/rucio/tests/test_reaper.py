'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2016
'''

from rucio.common.utils import generate_uuid
from rucio.core import rse as rse_core
from rucio.core import replica as replica_core
from rucio.daemons.reaper.reaper import reaper


class TestReaper:
    """ TestReaper Class."""

    def test_reaper(self):
        """ REAPER (DAEMON): Test the reaper daemon."""
        nb_files = 30
        file_size = 2147483648L  # 2G
        for i in xrange(nb_files):
            replica_core.add_replica(rse='MOCK', scope='data13_hip', name='lfn' + generate_uuid(), bytes=file_size, account='root', adler32=None, md5=None)

        rse_core.set_rse_usage(rse='MOCK', source='srm', used=nb_files * file_size, free=800L)
        rse_core.set_rse_limits(rse='MOCK', name='MinFreeSpace', value=10737418240L)
        rse_core.set_rse_limits(rse='MOCK', name='MaxBeingDeletedFiles', value=10)

        rses = [rse_core.get_rse('MOCK'), ]
        reaper(once=True, rses=rses)
        reaper(once=True, rses=rses)
