# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2017
# - Vincent Garonne, <vgaronne@gmail.com>, 2018
#
# PY3K COMPATIBLE

import logging
import traceback

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.common.config import config_get
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

cache_time = int(config_get('conveyor', 'cache_time', False, 600))

REGION_SHORT = make_region().configure('dogpile.cache.memory',
                                       expiration_time=cache_time)


def get_transfer_limits(activity, rse_id):
    """
    Get RSE transfer limits.

    :param activity:  The activity.
    :param rse_id:    The RSE id.

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
        logging.warning("Failed to get transfer limits: %s" % traceback.format_exc())
        return None


def get_transfer_limits_default(activity, rse_id):
    """
    Get RSE transfer limits in default mode.

    :param activity:  The activity.
    :param rse_id:    The RSE id.

    :returns: max_transfers if exists else None.
    """
    if using_memcache:
        key = 'rse_transfer_limits'
        result = REGION_SHORT.get(key)
        if type(result) is NoValue:
            try:
                logging.debug("Refresh rse transfer limits")
                result = get_rse_transfer_limits()
                REGION_SHORT.set(key, result)
            except:
                logging.warning("Failed to retrieve rse transfer limits: %s" % (traceback.format_exc()))
                result = None
        if result and activity in result and rse_id in result[activity]:
            return result[activity][rse_id]
        return None
    else:
        result = get_rse_transfer_limits(rse_id=rse_id, activity=activity)
        if result and activity in result and rse_id in result[activity]:
            return result[activity][rse_id]
        return None


def get_config_limits():
    """
    Get config limits.

    :returns: Dictionary of limits.
    """

    config_limits = {}
    items = config_core.items('throttler')
    for opt, value in items:
        try:
            activity, rsename = opt.split(',')
            if rsename == 'all_rses':
                rse_id = 'all_rses'
            else:
                rse_id = get_rse_id(rsename)
            if activity not in config_limits:
                config_limits[activity] = {}
            config_limits[activity][rse_id] = int(value)
        except:
            logging.warning("Failed to parse throttler config %s:%s, error: %s" % (opt, value, traceback.format_exc()))
    return config_limits


def get_config_limit(activity, rse_id):
    """
    Get RSE transfer limits in strict mode.

    :param activity:  The activity.
    :param rse_id:    The RSE id.

    :returns: max_transfers if exists else None.
    """
    key = 'config_limits'
    result = REGION_SHORT.get(key)
    if type(result) is NoValue:
        try:
            logging.debug("Refresh rse config limits")
            result = get_config_limits()
            REGION_SHORT.set(key, result)
        except:
            logging.warning("Failed to retrieve rse transfer limits: %s" % (traceback.format_exc()))
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
