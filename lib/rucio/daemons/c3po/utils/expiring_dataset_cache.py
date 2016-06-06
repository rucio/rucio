# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016

from redis import StrictRedis
from uuid import uuid4


class ExpiringDatasetCache:
    """
    Cache with expiring values to keep track of recently created replicas.
    """
    def __init__(self, redis_host, redis_port, timeout=1, prefix='expiring_did_cache'):
        self._r = StrictRedis(host=redis_host, port=redis_port)
        self._prefix = prefix + '_' + str(uuid4()).split('-')[0]
        self._timeout = timeout

    def add_dataset(self, dataset):
        key = ':'.join((self._prefix, dataset))
        self._r.set(key, 1)
        self._r.expire(key, self._timeout)

    def check_dataset(self, dataset):
        key = ':'.join((self._prefix, dataset))
        if self._r.get(key) is None:
            return False

        return True
