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

    def getMbps(self, src, type_):
        pattern = "%s#%s:*" % (self._prefix, src)
        keys = self._r.keys(pattern=pattern)
        if len(keys) == 0:
            return None
        ret = {}

        vals = self._r.mget(keys)

        for i in range(len(keys)):
            dst = keys[i].split(':')[1]
            mbps_all = loads(vals[i]).get('mbps', {}).get(type_, {})

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
