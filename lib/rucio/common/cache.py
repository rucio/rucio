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
from __future__ import absolute_import

from typing import TYPE_CHECKING

from dogpile.cache import make_region

from rucio.common.config import config_get
from rucio.common.utils import is_client

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Optional

CACHE_URL = config_get('cache', 'url', False, '127.0.0.1:11211', check_config_table=False)

ENABLE_CACHING = True
_mc_client = None
try:
    if is_client():
        ENABLE_CACHING = False
    else:
        import pymemcache
        _mc_client = pymemcache.Client(CACHE_URL, connect_timeout=1, timeout=1)
        _mc_client.version()
except IOError:
    ENABLE_CACHING = False
except ImportError:
    ENABLE_CACHING = False
finally:
    if _mc_client:
        _mc_client.close()


def make_region_memcached(
        expiration_time: int,
        function_key_generator: "Optional[Callable]" = None,
        memcached_expire_time: "Optional[int]" = None
):
    """
    Make and configure a dogpile.cache.pymemcache region
    """
    if function_key_generator:
        region = make_region(function_key_generator=function_key_generator)
    else:
        region = make_region()

    if ENABLE_CACHING:
        region.configure(
            'dogpile.cache.pymemcache',
            expiration_time=expiration_time,
            arguments={
                'url': CACHE_URL,
                'distributed_lock': True,
                'memcached_expire_time': memcached_expire_time if memcached_expire_time else expiration_time + 60,  # must be bigger than expiration_time
            }
        )
    else:
        region.configure('dogpile.cache.null')

    return region
