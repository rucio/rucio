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


from unittest.mock import Mock, patch

import pytest

from rucio.core.common.stopwatch import Stopwatch


class TestStopwatch:
    @patch('rucio.common.stopwatch.time')
    def test_restart(self, mock_time):
        mock_now = Mock()
        mock_time.monotonic.return_value = mock_now
        watch = Stopwatch()
        assert watch._t_start == mock_now
        assert watch._t_end is None

    @patch('rucio.common.stopwatch.time')
    def test_now(self, mock_time):
        mock_now = Mock()
        mock_time.monotonic.return_value = mock_now
        watch = Stopwatch()
        assert watch._now() == mock_now

    @patch('rucio.common.stopwatch.time')
    def test_stop(self, mock_time):
        mock_now = Mock()
        mock_time.monotonic.return_value = mock_now
        watch = Stopwatch()
        watch.stop()
        assert watch._t_end == mock_now

    @pytest.mark.parametrize('now_1,now_2,now_3',
                             [
                                    (5000, 9000, 12000),
                                    (1, 3, 7),
                                    (50.03, 80.58, 99.99),
                             ])
    @patch('rucio.common.stopwatch.time')
    def test_elapsed(self, mock_time, now_1, now_2, now_3):
        mock_time.monotonic.side_effect = [now_1, now_2, now_3]
        watch = Stopwatch()
        assert watch.elapsed == now_2 - now_1
        watch.stop()
        assert watch.elapsed == now_3 - now_1

    def test_float(self):
        watch = Stopwatch()
        watch.stop()
        assert float(watch) == watch.elapsed