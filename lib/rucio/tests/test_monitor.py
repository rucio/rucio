# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Luis Rodrigues, <luis.rodrigues@cern.ch>, 2013

from rucio.core import monitor


class TestMonitor():

    @classmethod
    def setupClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_monitor_record_counter_message(self):
        """MONITOR (CORE): Send a counter message to graphite """
        monitor.record_counter('test.counter', 10)

    def test_monitor_record_gauge_message(self):
        """MONITOR (CORE): Send a gauge message to graphite """
        monitor.record_gauge('test.gauge', 10)

    def test_monitor_record_timer_message(self):
        """MONITOR (CORE): Send a timer message to graphite """
        monitor.record_timer('test.runtime', 500)

    def test_monitor_context_record_timer(self):
        """MONITOR (CORE): Send a timer message to graphite using context """
        with monitor.record_timer_block('test.context_timer'):
            a = 2 * 100
            a = a * 1

        with monitor.record_timer_block(['test.context_timer']):
            a = 2 * 100
            a = a * 1

        with monitor.record_timer_block(['test.context_timer', ('test.context_timer_normal10', 10)]):
            a = 2 * 100
            a = a * 1
