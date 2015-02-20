# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015

import threading

from rucio.core.heartbeat import live, die, cardiac_arrest


class TestHeartbeat:

    @classmethod
    def setupClass(self):
        cardiac_arrest()

    def test_heartbeat(self):
        """ HEARTBEAT (CORE): Test thread assignment via heartbeat for services """

        thread_0 = threading.Thread()
        thread_1 = threading.Thread()
        thread_2 = threading.Thread()
        thread_0.start()
        thread_1.start()
        thread_2.start()

        live('rucio-test-program', 'rucio-test-host.cern.ch', 0, thread_0)       # 1
        live('rucio-test-program', 'rucio-test-host.cern.ch', 0, thread_0)       # 1
        live('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_0)   # 1,1
        live('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_1)   # 1,2
        live('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_2)   # 1,3
        live('rucio-test-program', 'rucio-test-host.cern.ch', 1, thread_0)       # 2,3

        die('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_0)  # 2,2
        die('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_1)  # 2,1
        die('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_2)  # 2
        die('rucio-test-program', 'rucio-test-host.cern.ch', 0, thread_0)      # 1

        live('rucio-test-program', 'rucio-test-host.cern.ch', 0, thread_0)       # 2
        live('rucio-test-program', 'rucio-test-host.cern.ch', 1, thread_0)       # 2
        live('rucio-test-program', 'rucio-test-host.cern.ch', 2, thread_0)       # 3
        live('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_0)   # 3,1
        live('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_0)   # 3,1,1

        die('rucio-test-program', 'rucio-test-host-dev.cern.ch', 0, thread_0)  # 3, ,1
        die('rucio-test-program', 'rucio-test-host.cern.ch', 0, thread_0)      # 3
        die('rucio-test-program', 'rucio-test-host.cern.ch', 0, thread_0)      # 2

        # TODO: Test thread-assignment - for later
