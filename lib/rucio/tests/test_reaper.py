# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from rucio.core import rse as rse_core
from rucio.daemons.Reaper import run_once


class TestReaper():

    def test_set_rse_limits(self):
        """ RSE (CLIENTS): Test the update of RSE limits."""
        rse_core.set_rse_usage(rse='MOCK', source='srm', total=100000000000000L, free=800L)
        rse_core.set_rse_limits(rse='MOCK', name='MinFreeSpace', value=1000000000L)
        run_once()
