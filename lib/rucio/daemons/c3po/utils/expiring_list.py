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

"""
Utility classes for C3PO
"""

from collections import deque
from threading import Lock, Timer


class ExpiringList(object):
    """
    Simple list with time based element expiration
    """

    def __init__(self, timeout=1):
        self._lock = Lock()
        self._timeout = timeout
        self._items = deque()

    def add(self, item):
        """Add event time
        """
        with self._lock:
            self._items.append(item)
            Timer(self._timeout, self._expire).start()

    def __len__(self):
        """
        Return number of active events
        """
        with self._lock:
            return len(self._items)

    def _expire(self):
        """
        Remove any expired events
        """
        with self._lock:
            self._items.popleft()

    def to_set(self):
        """
        Return items as a set
        """
        return set(self._items)

    def __str__(self):
        with self._lock:
            return str(self._items)
