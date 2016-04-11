# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2015-2016

from redis import StrictRedis
from time import time


class RedisTimeSeries():
    def __init__(self, redis_host, redis_port, window, prefix):
        self._r = StrictRedis(host=redis_host, port=redis_port)
        self._prefix = prefix
        self._window = window * 1000000

    def add_point(self, key, value):
        r_key = self._prefix + key
        score = int(time() * 1000000)
        self._r.zadd(r_key, score, "%d:%d" % (value, score))

    def get_series(self, key):
        r_key = self._prefix + key
        r_series = self._r.zrange(r_key, 0, -1)
        series = []
        for val in r_series:
            values, _ = val.split(':')
            series.append(int(values))

        return tuple(series)

    def trim(self):
        now = time()
        max_score = int(now * 1000000 - self._window)
        for key in self.get_keys():
            self._r.zremrangebyscore(key, 0, max_score)

    def get_keys(self):
        return self._r.keys(pattern=self._prefix + "*")

    def delete_keys(self):
        for key in self.get_keys():
            self._r.zremrangebyrank(key, 0, -1)
