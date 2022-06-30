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
import inspect

import logging
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps
from typing import Callable, Optional, Union

from dogpile.cache import CacheRegion, make_region
from dogpile.cache import util as dogpile_util
from dogpile.cache.backends.null import NullBackend

from rucio.common.config import config_get
from rucio.common.exception import InputValidationError
from rucio.common.utils import is_client

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
    logging.warning("Cannot connect to memcached at {}. Caching will be disabled".format(CACHE_URL))
    ENABLE_CACHING = False
except ImportError:
    logging.warning("Cannot import pymemcache. Caching will be disabled")
    ENABLE_CACHING = False
finally:
    if _mc_client:
        _mc_client.close()


def make_region_memcached(expiration_time, function_key_generator=None):
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
                'memcached_expire_time': expiration_time + 60,  # must be bigger than expiration_time
            }
        )
    else:
        region.configure('dogpile.cache.null')

    return region


def ignore_arguments_key_generator(namespace, fn: Callable, to_str: Callable[..., str] = str) -> Callable[..., str]:
    """
    This function is used to construct a
    :py:func:`dogpile.cache.FunctionKeyGenerator` function. This function can be
    used to cache function results based on all positional keys.

    :param namespace: The namespace of the cache.
    :param fn: The wrapped function.
    :param to_str: The function to use to generate a string from the provided value.
    :returns: A :py:func:`dogpile.cache.FunctionKeyGenerator` implementation.
    """

    dogpile_cache_key_generator = dogpile_util.function_key_generator(namespace, fn, to_str=to_str)

    @wraps(fn)
    def generate_key(*args, **ignored_kwargs):
        """
        Construct a cache-key wihtout the keyword arguments.
        """
        return dogpile_cache_key_generator(*args)

    return generate_key


"""
The global :ref:class:dogpile.cache.region.CacheRegion: instance used to cache
items.
"""
_REGION = make_region_memcached(
    expiration_time=600,
    function_key_generator=ignore_arguments_key_generator,
)


def cache(expiration_time_in_s: Optional[Union[float, timedelta]] = 600):
    """
    A function that provides a decorator for easy cache access. It creates a
    :py:class:`dogpile.cache.region.CacheRegion` with the respective arguments.

    Example::

        @cache(600)
        @session
        def get_rse_attribute(rse_id, key, *, session=None):
            ...

    This example wraps the `get_rse_attribute` into a caching layer. The
    expiration time of the items is 600s.

    The decorator provides the same functions like the `cache_on_arguments`
    dogpile cache decorator [1]. If, for example, a function wants to invalidate
    a cache entry, it can call::

        get_rse_attribute.invalidate(rse_id, key)

    Important: Insert the `*` into the function signature before the keyword
    arguments. If this is not done, the keyword arguments get wrongly translated
    to positional ones, which creates a wrong cache key. Together with
    pymemcache, that produces the error::

        pymemcache.exceptions.MemcacheIllegalInputError: Key contains whitespace

    If used with `{read,...}_session`, the `cache` decorator should be the outer
    one. This prevent the creation of the session in case of a cache-hit.

    [1] https://dogpilecache.sqlalchemy.org/en/latest/usage.html#using-a-region

    :param expiration_time_in_s: The expiration time for the cached elements.
    :returns: A decorator function to cache function results.
    """

    if callable(expiration_time_in_s):
        raise InputValidationError("The decorator `cache` should be called with parenthesis, not without.")

    def positional_arguments_with_default_check(fn):
        def inner(*args, **kwargs):
            # The input here gets forwardef to dogpile, the first argument being
            # the function to decorate.
            if inspect.getfullargspec(args[0]).defaults is not None:
                raise InputValidationError("The `cache()` decorator only works with keyword-only arguments, it should not be called with positional arguments with defaults.")

            return fn(*args, **kwargs)
        return inner

    result = positional_arguments_with_default_check(_REGION.cache_on_arguments(expiration_time=expiration_time_in_s))
    return result


@contextmanager
def disable_cache() -> CacheRegion:
    """
    A context manager to disable the caching. After the context, the old caching
    behavior will be restored, and all previously cached elements are present
    again.

    :returns: The global dogpile CacheRegion (with the NullBackend) used by
              Rucio.
    """
    global _REGION
    old_backend = _REGION.backend
    _REGION.backend = NullBackend({})
    try:
        yield _REGION
    finally:
        _REGION.backend = old_backend
