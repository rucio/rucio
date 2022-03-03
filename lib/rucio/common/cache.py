# -*- coding: utf-8 -*-
# Copyright 2022 CERN
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
#
# Authors:
# - Radu Carpa <radu.carpa@cern.ch>, 2022

from dogpile.cache import make_region

from rucio.common.config import config_get


def make_region_memcached(expiration_time, function_key_generator=None):
    """
    Make and configure a dogpile.cache.memcached region
    """
    if function_key_generator:
        region = make_region(function_key_generator=function_key_generator)
    else:
        region = make_region()

    region.configure(
        'dogpile.cache.memcached',
        expiration_time=expiration_time,
        arguments={
            'url': config_get('cache', 'url', False, '127.0.0.1:11211', check_config_table=False),
            'distributed_lock': True,
            'memcached_expire_time': expiration_time + 60,  # must be bigger than expiration_time
        }
    )

    return region
