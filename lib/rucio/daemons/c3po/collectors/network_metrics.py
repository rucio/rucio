# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016

from json import loads

from redis import StrictRedis
from rucio.common.config import config_get, config_get_int


class NetworkMetricsCollector():
    """
    Collector to get the bandwidth metrics between two sites.
    """

    def __init__(self):
        self._r = StrictRedis(host=config_get('c3po-network_metrics', 'redis_host'), port=config_get_int('c3po-network_metrics', 'redis_port'))
        self._prefix = config_get('c3po-network_metrics', 'prefix')

    def getConnections(self, src):
        pattern = "%s#%s:*" % (self._prefix, src)
        keys = self._r.keys(pattern=pattern)
        if len(keys) == 0:
            return None
        ret = {}
        vals = self._r.mget(keys)

        for i in xrange(len(keys)):
            dst = keys[i].split(':')[1]
            ret[dst] = loads(vals[i])['mbps']

        return ret
