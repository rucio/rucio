# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Luis Rodrigues, <luis.rodrigues@cern.ch>, 2013

from pystatsd import Client

from rucio.common.config import config_get

server = config_get('monitor', 'carbon_server')
port = config_get('monitor', 'carbon_port')
scope = config_get('monitor', 'user_scope')
pystatsd_client = Client(host=server, port=port, prefix=scope)


def record(timeseries, delta=1):
    """
    Updates one or more timeseries counters by arbitrary amounts

    :param timeseries: The timeseries or a list of timeseries to be updated.
    :param delta: The increment for the timeseries, by default increment by 1.
    """
    pystatsd_client.update_stats(timeseries, delta)


def gauge(stat, value):
    """
     Log gauge information for a single stat

    :param stat: The name of the stat to be updated.
    :param value: The value to log.
    """
    pystatsd_client.gauge(stat, value)


def timing(stat, time):
    """
     Log timing information for a single stat (in miliseconds)

    :param stat: The name of the stat to be updated.
    :param value: The time to log.
    """
    pystatsd_client.timing(stat, time)
