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
from unittest.mock import Mock

import pytest
from dogpile.cache.backends.memcached import PyMemcacheBackend
from dogpile.cache.backends.null import NullBackend
from dogpile.cache.util import function_key_generator

import rucio.common.cache as cache
from rucio.common.cache import CacheKey, MemcacheRegion


class TestCache:
    class TestMemcacheRegion:
        @pytest.mark.parametrize(
            'input_function_key_generator,expected_function_key_generator',
            [
                (Mock, Mock),
                (None, function_key_generator)
            ]
        )
        def test_function_key_generator(self, input_function_key_generator, expected_function_key_generator):
            region = MemcacheRegion(60, function_key_generator=input_function_key_generator)
            assert region.function_key_generator == expected_function_key_generator

        @pytest.mark.parametrize(
            'caching_enabled,expected_backend',
            [
                (True, PyMemcacheBackend),
                (False, NullBackend)
            ],
            ids=['caching_enabled', 'caching_disabled']
        )
        def test_backend(self, caching_enabled, expected_backend):
            cache.ENABLE_CACHING = caching_enabled
            region = MemcacheRegion(60)
            assert isinstance(region.backend, expected_backend)

        @pytest.mark.parametrize(
            'input_memcached_expire_time,expected_memcached_expire_time',
            [
                (120, 120),
                (None, 20)
            ]
        )
        def test_memcached_expired_time(self, input_memcached_expire_time, expected_memcached_expire_time):
            cache.ENABLE_CACHING = True
            expiration_time = 20
            expected_memcached_expire_time = input_memcached_expire_time or expiration_time + 60

            # Ensure the test is valid
            assert input_memcached_expire_time != expiration_time

            region = MemcacheRegion(expiration_time, memcached_expire_time=input_memcached_expire_time)

            assert isinstance(region.backend, PyMemcacheBackend)

            # TODO - When dogpile.cache will be upgraded to 1.3 in requirements,
            # Change region.backend.memcached_expire_time to region.backend['expire']
            assert region.backend.memcached_expire_time == expected_memcached_expire_time

    class TestCacheKey:
        section = "test"
        option = "test2"

        def test_has_section(self):
            expected = "has_section_test"
            assert CacheKey.has_section(self.section) == expected

        def test_options(self):
            expected = "options_test"
            assert CacheKey.options(self.section) == expected

        def test_has_option(self):
            expected = "has_option_test_test2"
            assert CacheKey.has_option(self.section, self.option) == expected

        def test_item(self):
            expected = "items_test"
            assert CacheKey.items(self.section) == expected

        def test_value(self):
            expected = "get_test_test2"
            assert CacheKey.value(self.section, self.option) == expected
