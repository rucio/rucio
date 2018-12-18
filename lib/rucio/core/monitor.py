# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Luis Rodrigues <lfrodrigues@gmail.com>, 2013
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017
# - Vincent Garonne vgaronne@gmail.com, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

"""
Graphite counters
"""

from __future__ import division

import time

from pystatsd import Client

from rucio.common.config import config_get

SERVER = config_get('monitor', 'carbon_server', raise_exception=False, default='localhost')
PORT = config_get('monitor', 'carbon_port', raise_exception=False, default=8125)
SCOPE = config_get('monitor', 'user_scope', raise_exception=False, default='rucio')
CLIENT = Client(host=SERVER, port=PORT, prefix=SCOPE)


def record_counter(counters, delta=1):
    """
    Log one or more counters by arbitrary amounts

    :param counters: The counter or a list of counters to be updated.
    :param delta: The increment for the counter, by default increment by 1.
    """
    CLIENT.update_stats(counters, delta)


def record_gauge(stat, value):
    """
     Log gauge information for a single stat

    :param stat: The name of the stat to be updated.
    :param value: The value to log.
    """
    CLIENT.gauge(stat, value)


def record_timer(stat, time):
    """
     Log timing information for a single stat (in miliseconds)

    :param stat: The name of the stat to be updated.
    :param value: The time to log.
    """
    CLIENT.timing(stat, time)


class record_timer_block(object):
    """
    A context manager for timing a block of code.

    :param stats: The name of the stat or list of stats that should be updated.
        Each stat can be a simple string or a tuple (string, divisor)

    Usage:
        with monitor.record_timer_block('test.context_timer'):
            stuff1()
            stuff2()

       with monitor.record_timer_block(['test.context_timer', ('test.context_timer_normalised', 10)]):
            stuff1()
            stuff2()
    """

    def __init__(self, stats):
        if not isinstance(stats, list):
            stats = [stats]
        self.stats = stats

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, typ, value, tb):
        dt = time.time() - self.start
        ms = int(round(1000 * dt))  # Convert to ms.
        for s in self.stats:
            if isinstance(s, str):
                record_timer(s, ms)
            elif isinstance(s, tuple):
                if s[1] != 0:
                    ms = ms / s[1]
                    record_timer(s[0], ms)
