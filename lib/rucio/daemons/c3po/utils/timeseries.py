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
Redis time series abstraction
"""

from time import time

from redis import StrictRedis


class RedisTimeSeries(object):
    """
    Redis time series abstraction
    """

    def __init__(self, redis_host, redis_port, window, prefix):
        self._redis = StrictRedis(host=redis_host, port=redis_port)
        self._prefix = prefix
        self._window = window * 1000000

    def add_point(self, key, value):
        """
        Add a point
        """
        r_key = self._prefix + key
        score = int(time() * 1000000)
        self._redis.zadd(r_key, score, "%d:%d" % (value, score))

    def get_series(self, key):
        """
        Return a time series tuple
        """
        r_key = self._prefix + key
        r_series = self._redis.zrange(r_key, 0, -1)
        series = []
        for val in r_series:
            values, _ = val.split(':')
            series.append(int(values))

        return tuple(series)

    def trim(self):
        """
        Trim the time series
        """
        now = time()
        max_score = int(now * 1000000 - self._window)
        for key in self.get_keys():
            self._redis.zremrangebyscore(key, 0, max_score)

    def get_keys(self):
        """
        Return matching keys
        """
        return self._redis.keys(pattern=self._prefix + "*")

    def delete_keys(self):
        """
        Delete keys
        """
        for key in self.get_keys():
            self._redis.zremrangebyrank(key, 0, -1)
