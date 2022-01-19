# -*- coding: utf-8 -*-
# Copyright 2017-2022 CERN
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
# - Martin Barisits, <martin.barisits@cern.ch>, 2017
# - Vincent Garonne, <vgaronne@gmail.com>, 2018
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2022

import logging
import traceback

from dogpile.cache.api import NoValue

from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.core import config as config_core
from rucio.core.rse import get_rse_id, get_rse_transfer_limits

queue_mode = config_get('conveyor', 'queue_mode', False, 'default')
if queue_mode.upper() == 'STRICT':
    queue_mode = 'strict'

config_memcache = config_get('conveyor', 'using_memcache', False, 'False')
if config_memcache.upper() == 'TRUE':
    using_memcache = True
else:
    using_memcache = False

REGION_SHORT = make_region_memcached(expiration_time=config_get_int('conveyor', 'cache_time', False, 600))


def get_transfer_limits(activity, rse_id, logger=logging.log):
    """
    Get RSE transfer limits.

    :param activity:  The activity.
    :param rse_id:    The RSE id.
    :param logger:    Optional decorated logger that can be passed from the calling daemons or servers.

    :returns: max_transfers if exists else None.
    """
    try:
        if queue_mode == 'strict':
            threshold = get_config_limit(activity, rse_id)
            if threshold:
                return {'max_transfers': threshold, 'transfers': 0, 'waitings': 0}
            else:
                return None
        else:
            return get_transfer_limits_default(activity, rse_id)
    except:
        logger(logging.WARNING, "Failed to get transfer limits: %s" % traceback.format_exc())
        return None


def get_transfer_limits_default(activity, rse_id, logger=logging.log):
    """
    Get RSE transfer limits in default mode.

    :param activity:  The activity.
    :param rse_id:    The RSE id.
    :param logger:    Optional decorated logger that can be passed from the calling daemons or servers.

    :returns: max_transfers if exists else None.
    """
    if using_memcache:
        key = 'rse_transfer_limits'
        result = REGION_SHORT.get(key)
        if type(result) is NoValue:
            try:
                logger(logging.DEBUG, "Refresh rse transfer limits")
                result = get_rse_transfer_limits()
                REGION_SHORT.set(key, result)
            except:
                logger(logging.WARNING, "Failed to retrieve rse transfer limits: %s" % (traceback.format_exc()))
                result = None
        if result and activity in result and rse_id in result[activity]:
            return result[activity][rse_id]
        return None
    else:
        result = get_rse_transfer_limits(rse_id=rse_id, activity=activity)
        if result and activity in result and rse_id in result[activity]:
            return result[activity][rse_id]
        return None


def get_config_limits(logger=logging.log):
    """
    Get config limits.
    :param logger:   Optional decorated logger that can be passed from the calling daemons or servers.

    :returns: Dictionary of limits.
    """

    config_limits = {}
    items = config_core.items('throttler', use_cache=using_memcache)
    for opt, value in items:
        try:
            if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
                activity, rse_id = opt.split(',')  # In multi VO mode, require config to be set using RSE IDs
            else:
                activity, rse_name = opt.split(',')  # In single VO mode, expect config to be set using RSE names
                if rse_name == 'all_rses':
                    rse_id = 'all_rses'
                else:
                    rse_id = get_rse_id(rse_name, vo='def')  # In single VO mode, VO should always be def
            if activity not in config_limits:
                config_limits[activity] = {}
            config_limits[activity][rse_id] = int(value)
        except:
            logger(logging.WARNING, "Failed to parse throttler config %s:%s, error: %s" % (opt, value, traceback.format_exc()))
    return config_limits


def get_config_limit(activity, rse_id, logger=logging.log):
    """
    Get RSE transfer limits in strict mode.

    :param activity:  The activity.
    :param rse_id:    The RSE id.
    :param logger:    Optional decorated logger that can be passed from the calling daemons or servers.

    :returns: max_transfers if exists else None.
    """
    result = NoValue()
    key = 'config_limits'
    if using_memcache:
        result = REGION_SHORT.get(key)
    if type(result) is NoValue:
        try:
            logger(logging.DEBUG, "Refresh rse config limits")
            result = get_config_limits()
            REGION_SHORT.set(key, result)
        except:
            logger(logging.WARNING, "Failed to retrieve rse transfer limits: %s" % (traceback.format_exc()))
            result = None

    threshold = None
    if result:
        if activity in result.keys():
            if rse_id in result[activity].keys():
                threshold = result[activity][rse_id]
            elif 'all_rses' in result[activity].keys():
                threshold = result[activity]['all_rses']
        if not threshold and 'all_activities' in result.keys():
            if rse_id in result['all_activities'].keys():
                threshold = result['all_activities'][rse_id]
            elif 'all_rses' in result['all_activities'].keys():
                threshold = result['all_activities']['all_rses']
    return threshold
