# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016
#
# PY3K COMPATIBLE

from uuid import uuid4

from rucio.daemons.c3po.utils.timeseries import RedisTimeSeries


class DatasetCache(object):
    """
    Utility to count the accesses of the datasets during the last day.
    """
    def __init__(self, redis_host, redis_port, timeout=1, prefix='did_cache', delete_keys=False):
        self._prefix = prefix + '_' + str(uuid4()).split('-')[0]
        self._tms = RedisTimeSeries(redis_host, redis_port, timeout, self._prefix)

        if delete_keys:
            self._tms.delete_keys()

    def add_did(self, did):
        self._tms.add_point('_'.join(did), 1)

    def get_did(self, did):
        self._tms.trim()

        series = self._tms.get_series('_'.join(did))

        return len(series)
