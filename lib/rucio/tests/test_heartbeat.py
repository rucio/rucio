# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015

import random
import threading

from nose.tools import assert_equal

from rucio.core.heartbeat import live, die, cardiac_arrest


class TestHeartbeat:

    def __pid(self):
        return random.randint(0, 2**16)

    def __thread(self):
        thread = threading.Thread()
        thread.start()
        return thread

    def setup(self):
        cardiac_arrest()

    def test_heartbeat_0(self):
        """ HEARTBEAT (CORE): Single instance """

        p = self.__pid()
        t = self.__thread()
        assert_equal(live('test0', 'host0', p, t), {'assign_thread': 0, 'nr_threads': 1})
        assert_equal(live('test0', 'host0', p, t), {'assign_thread': 0, 'nr_threads': 1})
        assert_equal(live('test0', 'host0', p, t), {'assign_thread': 0, 'nr_threads': 1})

    def test_heartbeat_1(self):
        """ HEARTBEAT (CORE): Multiple instance """

        p = [self.__pid() for tmp in xrange(4)]
        t = [self.__thread() for tmp in xrange(4)]
        assert_equal(live('test0', 'host0', p[0], t[0]), {'assign_thread': 0, 'nr_threads': 1})
        assert_equal(live('test0', 'host1', p[1], t[1]), {'assign_thread': 1, 'nr_threads': 2})
        assert_equal(live('test0', 'host0', p[0], t[0]), {'assign_thread': 0, 'nr_threads': 2})
        assert_equal(live('test0', 'host2', p[2], t[2]), {'assign_thread': 2, 'nr_threads': 3})
        assert_equal(live('test0', 'host0', p[0], t[0]), {'assign_thread': 0, 'nr_threads': 3})
        assert_equal(live('test0', 'host3', p[3], t[3]), {'assign_thread': 3, 'nr_threads': 4})
        assert_equal(live('test0', 'host1', p[1], t[1]), {'assign_thread': 1, 'nr_threads': 4})
        assert_equal(live('test0', 'host2', p[2], t[2]), {'assign_thread': 2, 'nr_threads': 4})
        assert_equal(live('test0', 'host3', p[3], t[3]), {'assign_thread': 3, 'nr_threads': 4})

    def test_heartbeat_2(self):
        """ HEARTBEAT (CORE): Multiple instance with removal"""

        p = [self.__pid() for tmp in xrange(4)]
        t = [self.__thread() for tmp in xrange(4)]
        assert_equal(live('test0', 'host0', p[0], t[0]), {'assign_thread': 0, 'nr_threads': 1})
        assert_equal(live('test0', 'host1', p[1], t[1]), {'assign_thread': 1, 'nr_threads': 2})
        assert_equal(live('test0', 'host0', p[0], t[0]), {'assign_thread': 0, 'nr_threads': 2})
        assert_equal(live('test0', 'host2', p[2], t[2]), {'assign_thread': 2, 'nr_threads': 3})
        assert_equal(live('test0', 'host0', p[0], t[0]), {'assign_thread': 0, 'nr_threads': 3})
        die('test0', 'host0', p[0], t[0])
        assert_equal(live('test0', 'host3', p[3], t[3]), {'assign_thread': 2, 'nr_threads': 3})
        assert_equal(live('test0', 'host1', p[1], t[1]), {'assign_thread': 0, 'nr_threads': 3})
        assert_equal(live('test0', 'host2', p[2], t[2]), {'assign_thread': 1, 'nr_threads': 3})
        die('test0', 'host2', p[2], t[2])
        assert_equal(live('test0', 'host3', p[3], t[3]), {'assign_thread': 1, 'nr_threads': 2})

    def tearDown(self):
        cardiac_arrest()
