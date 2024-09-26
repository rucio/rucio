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

from typing import TYPE_CHECKING, Optional

from dogpile.cache.region import CacheRegion

from rucio.common.config import config_get
from rucio.common.utils import is_client

if TYPE_CHECKING:
    from collections.abc import Callable


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
except OSError:
    ENABLE_CACHING = False
except ImportError:
    ENABLE_CACHING = False
finally:
    if _mc_client:
        _mc_client.close()


class MemcacheRegion(CacheRegion):
    """
    Subclass of CacheRegion.
    It uses pymemcache as backend if ENABLE_CACHING is True,
    otherwise it it configured to null.
    """
    def __init__(
            self,
            expiration_time: int,
            function_key_generator: Optional['Callable'] = None,
            memcached_expire_time: Optional[int] = None
    ):
        if function_key_generator:
            super().__init__(function_key_generator=function_key_generator)
        else:
            super().__init__()
        self._configure_region(expiration_time, memcached_expire_time)

    def _configure_region(
            self,
            expiration_time: int,
            memcached_expire_time: Optional[int]
    ) -> None:
        if ENABLE_CACHING:
            self.configure(
                'dogpile.cache.pymemcache',
                expiration_time=expiration_time,
                arguments={
                    'url': CACHE_URL,
                    'distributed_lock': True,
                    'memcached_expire_time': memcached_expire_time if memcached_expire_time else expiration_time + 60,  # must be bigger than expiration_time
                }
            )
        else:
            self.configure('dogpile.cache.null')


class CacheKey:
    """
    Helper class to generate cache keys
    based on sections and options.
    """

    @staticmethod
    def _generate_key(*args: str) -> str:
        return '_'.join(args)

    @staticmethod
    def has_section(section: str) -> str:
        return CacheKey._generate_key('has_section', section)

    @staticmethod
    def options(section: str) -> str:
        return CacheKey._generate_key('options', section)

    @staticmethod
    def has_option(section: str, option: str) -> str:
        return CacheKey._generate_key('has_option', section, option)

    @staticmethod
    def items(section: str) -> str:
        return CacheKey._generate_key('items', section)

    @staticmethod
    def value(section: str, option: str) -> str:
        return CacheKey._generate_key('get', section, option)
