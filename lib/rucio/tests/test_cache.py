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

from itertools import count
import pytest
import time

from rucio.common.cache import ENABLE_CACHING, cache, disable_cache
from rucio.common.exception import InputValidationError
from rucio.db.sqla.session import read_session


class TestIgnoreKeywordArgumentsCache:
    @pytest.mark.skipif(not ENABLE_CACHING, reason="The results are different if the cache is disabled.")
    def test_ignore_session(self):
        @cache(600)
        @read_session
        def cached_func_1(x, *, y=0, session=None):
            return x + y

        # Clean-up from previous runs
        cached_func_1.invalidate(1)

        assert cached_func_1(1) == 1
        assert cached_func_1(1, session="session value") == cached_func_1(1, y=0)

        assert cached_func_1(1, session="test") == 1

    @pytest.mark.skipif(not ENABLE_CACHING, reason="The results are different if the cache is disabled.")
    def test_invalidate(self):
        @cache(600)
        def cached_func_2(x, *, y=0):
            return x + y

        # Clean-up from previous runsPlease rebas
        assert cached_func_2(1, y=1) == 2

    @pytest.mark.skipif(not ENABLE_CACHING, reason="The results are different if the cache is disabled.")
    def test_invalidate_after_timeout(self):
        number_called = count(0)

        @cache(0.1)
        def cached_func_3():
            return next(number_called)

        # Clean-up from previous runs
        cached_func_3.invalidate()

        assert cached_func_3() == 0

        time.sleep(0.05)
        assert cached_func_3() == 0

        time.sleep(0.06)
        assert cached_func_3() == 1

    @pytest.mark.skipif(not ENABLE_CACHING, reason="The results are different if the cache is disabled.")
    def test_disable_cache(self):
        number_called = count(0)

        @cache(1)
        def cached_func_4():
            return next(number_called)

        # Clean-up from previous runs
        cached_func_4.invalidate()

        assert cached_func_4() == 0
        assert cached_func_4() == 0

        with disable_cache():
            assert cached_func_4() == 1
            assert cached_func_4() == 2

        assert cached_func_4() == 0

    @pytest.mark.skipif(not ENABLE_CACHING, reason="The results are different if the cache is disabled.")
    def test_disable_cache_fixture(self, disable_cache_fixture):
        number_called = count(0)

        @cache(1)
        def cached_func_5():
            return next(number_called)

        assert cached_func_5() == 0
        assert cached_func_5() == 1
        assert cached_func_5() == 2

    @pytest.mark.skipif(not ENABLE_CACHING, reason="The results are different if the cache is disabled.")
    def test_decorator_called_without_parenthesis(self):
        with pytest.raises(InputValidationError):
            @cache
            def unused_cached_func_6():
                return 0

    @pytest.mark.skipif(not ENABLE_CACHING, reason="The results are different if the cache is disabled.")
    def test_decorator_called_with_positional_default_argument(self):
        with pytest.raises(InputValidationError):
            @cache()
            def unused_cached_func_6(unused1, unused2=1):
                return 0

    @pytest.mark.skipif(not ENABLE_CACHING, reason="The results are different if the cache is disabled.")
    def test_decorator_called_with_positional_default_argument_nested(self):
        with pytest.raises(InputValidationError):
            @cache()
            @read_session
            def unused_cached_func_6(unused1, session=None):
                return 0
