# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Luis Rodrigues, <luis.rodrigues@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2017

from rucio.core import monitor


class TestMonitor(object):

    @classmethod
    def setupClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    @staticmethod
    def test_record_counter_message():
        """MONITOR (CORE): Send a counter message to graphite """
        monitor.record_counter('test.counter', 10)

    @staticmethod
    def test_record_gauge_message():
        """MONITOR (CORE): Send a gauge message to graphite """
        monitor.record_gauge('test.gauge', 10)

    @staticmethod
    def test_record_timer_message():
        """MONITOR (CORE): Send a timer message to graphite """
        monitor.record_timer('test.runtime', 500)

    @staticmethod
    def test_context_record_timer():
        """MONITOR (CORE): Send a timer message to graphite using context """
        with monitor.record_timer_block('test.context_timer'):
            var_a = 2 * 100
            var_a = var_a * 1

        with monitor.record_timer_block(['test.context_timer']):
            var_a = 2 * 100
            var_a = var_a * 1

        with monitor.record_timer_block(['test.context_timer', ('test.context_timer_normal10', 10)]):
            var_a = 2 * 100
            var_a = var_a * 1
