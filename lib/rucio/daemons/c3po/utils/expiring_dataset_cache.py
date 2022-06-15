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
Expiring Dataset Cache
"""
from uuid import uuid4

from redis import StrictRedis


class ExpiringDatasetCache(object):
    """
    Cache with expiring values to keep track of recently created replicas.
    """
    def __init__(self, redis_host, redis_port, timeout=1, prefix='expiring_did_cache'):
        self._redis = StrictRedis(host=redis_host, port=redis_port)
        self._prefix = prefix + '_' + str(uuid4()).split('-')[0]
        self._timeout = timeout

    def add_dataset(self, dataset):
        """ Adds a datasets to cache with lifetime """
        key = ':'.join((self._prefix, dataset))
        self._redis.set(key, 1)
        self._redis.expire(key, self._timeout)

    def check_dataset(self, dataset):
        """ Checks if dataset is still in cache """
        key = ':'.join((self._prefix, dataset))
        if self._redis.get(key) is None:
            return False

        return True
