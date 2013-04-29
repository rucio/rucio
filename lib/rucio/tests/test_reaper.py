# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from rucio.common.utils import generate_uuid

from rucio.core import rse as rse_core
from rucio.daemons.reaper import reaper


class TestReaper():

    def test_set_rse_limits(self):
        """ RSE (CLIENTS): Test the update of RSE limits."""

        nb_files = 30
        file_size = 2147483648L  # 2G
        for file in xrange(nb_files):
            rse_core.add_file_replica(rse='MOCK', scope='data13_hip', name='lfn' + generate_uuid(), size=file_size, account='root', adler32=None, md5=None)

        rse_core.set_rse_usage(rse='MOCK', source='srm', used=nb_files*file_size, free=800L)
        rse_core.set_rse_limits(rse='MOCK', name='MinFreeSpace', value=10737418240L)
        reaper(once=True)
        reaper(once=True)
