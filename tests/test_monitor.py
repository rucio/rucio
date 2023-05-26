# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from rucio.core import monitor


class TestMonitor:

    def test_record_counter_message(self, metrics_mock):
        """MONITOR (CORE): Send a counter message to graphite """
        monitor.MetricManager(prefix='test').counter('counter').inc(10)
        assert metrics_mock.get_sample_value('test_counter_total') == 10

    def test_record_gauge_message(self, metrics_mock):
        """MONITOR (CORE): Send a gauge message to graphite """
        monitor.MetricManager(prefix='test').gauge('gauge').set(10)
        assert metrics_mock.get_sample_value('test_gauge') == 10

    def test_record_timer_message(self, metrics_mock):
        """MONITOR (CORE): Send a timer message to graphite """
        monitor.MetricManager(prefix='test').timer('runtime').observe(500)
        assert metrics_mock.get_sample_value('test_runtime_count') == 1

    def test_context_record_timer(self, metrics_mock):
        """MONITOR (CORE): Send a timer message to graphite using context """

        metric_manager = monitor.MetricManager(prefix='test')
        with metric_manager.timer('context_timer'):
            var_a = 2 * 100
            var_a = var_a * 1
        assert metrics_mock.get_sample_value('test_context_timer_count') == 1

        with metric_manager.timer('context_timer'):
            var_a = 2 * 100
            var_a = var_a * 1
        assert metrics_mock.get_sample_value('test_context_timer_count') == 2
