# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016
# - Martin Barisits, <martin.barisits@cern.ch>, 2017

from json import loads

from redis import StrictRedis
from rucio.common.config import config_get, config_get_int


class NetworkMetricsCollector(object):
    """
    Collector to get the bandwidth metrics between two sites.
    """

    def __init__(self):
        self._r = StrictRedis(host=config_get('c3po-network-metrics', 'redis_host'), port=config_get_int('c3po-network-metrics', 'redis_port'))
        self._prefix = config_get('c3po-network-metrics', 'prefix')

    def getMbps(self, src, type):
        pattern = "%s#%s:*" % (self._prefix, src)
        keys = self._r.keys(pattern=pattern)
        if len(keys) == 0:
            return None
        ret = {}

        vals = self._r.mget(keys)

        for i in xrange(len(keys)):
            dst = keys[i].split(':')[1]
            mbps_all = loads(vals[i]).get('mbps', {}).get(type, {})

            if '1h' in mbps_all:
                ret[dst] = float(mbps_all['1h'])
            else:
                if '1d' in mbps_all:
                    ret[dst] = float(mbps_all['1d'])
                else:
                    ret[dst] = float(mbps_all.get('1w', 0.0))

        return ret

    def getQueuedFiles(self, src, dst):
        key = "%s#%s:%s" % (self._prefix, src, dst)
        activities = loads(self._r.get(key)).get('files', {}).get('queued', {}).get('total', {})

        total = 0
        for _, values in activities.items():
            total += values['total']

        return total
