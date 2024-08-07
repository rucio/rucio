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
from lib.rucio.common.cache import CacheKey


class TestCache:
    class TestCacheKey:
        section = "test"
        option = "test2"

        def test_has_section_cache_key(self):
            expected = "has_section_test"
            assert CacheKey.has_section(self.section) == expected

        def test_options_cache_key(self):
            expected = "options_test"
            assert CacheKey.options(self.section) == expected

        def test_has_option_cache_key(self):
            expected = "has_option_test_test2"
            assert CacheKey.has_option(self.section, self.option) == expected

        def test_items_cache_key(self):
            expected = "items_test"
            assert CacheKey.items(self.section) == expected

        def test_value_cache_key(self):
            expected = "get_test_test2"
            assert CacheKey.value(self.section, self.option) == expected
