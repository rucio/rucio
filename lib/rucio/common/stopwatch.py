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


import time
from typing import Optional


class Stopwatch:
    """Stopwatch to measure time durations.

    Note: The stopwatch is started on initialization.
    """

    _t_start: float
    _t_end: Optional[float]

    def __init__(self) -> None:
        self.restart()

    def _now(self) -> float:
        # TODO: change to time.monotonic_ns() if python 3.6 support is dropped.
        return time.monotonic()

    def restart(self) -> None:
        """Resets and starts the stopwatch."""
        self._t_start = self._now()
        self._t_end = None

    def stop(self) -> None:
        """Stops the stopwatch."""
        self._t_end = self._now()

    @property
    def elapsed(self) -> float:
        """Returns the total number of elapsed seconds."""
        if self._t_end is None:
            return self._now() - self._t_start
        else:
            return self._t_end - self._t_start

    def __float__(self) -> float:
        """Returns the total number of elapsed seconds."""
        return self.elapsed
