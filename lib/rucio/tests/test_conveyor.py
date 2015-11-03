'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Wen Guan, <wen.guan@cern.ch>, 2015
'''

import time

from rucio.daemons.mock.conveyorinjector import request_transfer
from rucio.daemons.conveyor import submitter_transfer, poller, finisher


class TestConveyorSubmitter:
    """ TestReaper Class."""

    def test_conveyor_submitter(self):
        """ CONVEYOR (DAEMON): Test the conveyor submitter daemon."""
        src = 'ATLASSCRATCHDISK://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasscratchdisk/rucio/'
        dest = 'ATLASSCRATCHDISK://dcache-se-atlas.desy.de:8443/srm/managerv2?SFN=/pnfs/desy.de/atlas/dq2/atlasscratchdisk/rucio/'
        request_transfer(loop=10, src=src, dst=dest, upload=False, same_src=True, same_dst=True)

        submitter_transfer.throttler(once=True)
        submitter_transfer.submitter(once=True)
        submitter_transfer.run(once=True)
        time.sleep(5)
        poller.run(once=True)
        finisher.run(once=True)
