# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
# - Martin Barisits, <martin.barisits@cern.ch>, 2019

import random
import threading

from nose.tools import assert_equal

from rucio.core.heartbeat import live, die, cardiac_arrest, list_payload_counts


class TestHeartbeat:

    def __pid(self):
        return random.randint(0, 2**16)

    def __thread(self):
        thread = threading.Thread()
        thread.start()
        return thread

    def __init__(self):
        cardiac_arrest()

    def test_heartbeat_0(self):
        """ HEARTBEAT (CORE): Single instance """

        pid = self.__pid()
        thread = self.__thread()
        assert_equal(live('test0', 'host0', pid, thread), {'assign_thread': 0, 'nr_threads': 1})
        assert_equal(live('test0', 'host0', pid, thread), {'assign_thread': 0, 'nr_threads': 1})
        assert_equal(live('test0', 'host0', pid, thread), {'assign_thread': 0, 'nr_threads': 1})

    def test_heartbeat_1(self):
        """ HEARTBEAT (CORE): Multiple instance """

        pids = [self.__pid() for _ in range(4)]
        threads = [self.__thread() for _ in range(4)]
        assert_equal(live('test0', 'host0', pids[0], threads[0]), {'assign_thread': 0, 'nr_threads': 1})
        assert_equal(live('test0', 'host1', pids[1], threads[1]), {'assign_thread': 1, 'nr_threads': 2})
        assert_equal(live('test0', 'host0', pids[0], threads[0]), {'assign_thread': 0, 'nr_threads': 2})
        assert_equal(live('test0', 'host2', pids[2], threads[2]), {'assign_thread': 2, 'nr_threads': 3})
        assert_equal(live('test0', 'host0', pids[0], threads[0]), {'assign_thread': 0, 'nr_threads': 3})
        assert_equal(live('test0', 'host3', pids[3], threads[3]), {'assign_thread': 3, 'nr_threads': 4})
        assert_equal(live('test0', 'host1', pids[1], threads[1]), {'assign_thread': 1, 'nr_threads': 4})
        assert_equal(live('test0', 'host2', pids[2], threads[2]), {'assign_thread': 2, 'nr_threads': 4})
        assert_equal(live('test0', 'host3', pids[3], threads[3]), {'assign_thread': 3, 'nr_threads': 4})

    def test_heartbeat_2(self):
        """ HEARTBEAT (CORE): Multiple instance with removal"""

        pids = [self.__pid() for _ in range(4)]
        threads = [self.__thread() for _ in range(4)]
        assert_equal(live('test0', 'host0', pids[0], threads[0]), {'assign_thread': 0, 'nr_threads': 1})
        assert_equal(live('test0', 'host1', pids[1], threads[1]), {'assign_thread': 1, 'nr_threads': 2})
        assert_equal(live('test0', 'host0', pids[0], threads[0]), {'assign_thread': 0, 'nr_threads': 2})
        assert_equal(live('test0', 'host2', pids[2], threads[2]), {'assign_thread': 2, 'nr_threads': 3})
        assert_equal(live('test0', 'host0', pids[0], threads[0]), {'assign_thread': 0, 'nr_threads': 3})
        die('test0', 'host0', pids[0], threads[0])
        assert_equal(live('test0', 'host3', pids[3], threads[3]), {'assign_thread': 2, 'nr_threads': 3})
        assert_equal(live('test0', 'host1', pids[1], threads[1]), {'assign_thread': 0, 'nr_threads': 3})
        assert_equal(live('test0', 'host2', pids[2], threads[2]), {'assign_thread': 1, 'nr_threads': 3})
        die('test0', 'host2', pids[2], threads[2])
        assert_equal(live('test0', 'host3', pids[3], threads[3]), {'assign_thread': 1, 'nr_threads': 2})

    def test_heartbeat_payload(self):
        """ HEARTBEAT (CORE): Test heartbeat with payload"""

        pids = [self.__pid() for _ in range(6)]
        threads = [self.__thread() for _ in range(6)]

        live('test5', 'host0', pids[0], threads[0], payload='payload1')
        live('test5', 'host0', pids[1], threads[1], payload='payload1')
        live('test5', 'host0', pids[2], threads[2], payload='payload1')
        live('test5', 'host1', pids[3], threads[3], payload='payload2')
        live('test5', 'host2', pids[4], threads[4], payload='payload3')
        live('test5', 'host3', pids[5], threads[5], payload='payload4')

        assert_equal(list_payload_counts('test5'), {'payload4': 1, 'payload2': 1, 'payload3': 1, 'payload1': 3})

        die('test5', 'host0', pids[0], threads[0])
        die('test5', 'host0', pids[1], threads[1])
        die('test5', 'host0', pids[2], threads[2])
        die('test5', 'host1', pids[3], threads[3])
        die('test5', 'host2', pids[4], threads[4])
        die('test5', 'host3', pids[5], threads[5])

        assert_equal(list_payload_counts('test5'), {})

    def tearDown(self):
        cardiac_arrest()
