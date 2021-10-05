# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Luis Rodrigues <lfrodrigues@gmail.com>, 2013
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017-2020
# - Vincent Garonne <vincent.garonne@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Radu Carpa <radu.carpa@cern.ch>, 2021

"""
Graphite counters
"""

from __future__ import division

import string
import time
from abc import abstractmethod

from prometheus_client import start_http_server, Counter, REGISTRY
from statsd import StatsClient

from rucio.common.config import config_get, config_get_bool, config_get_int

SERVER = config_get('monitor', 'carbon_server', raise_exception=False, default='localhost')
PORT = config_get('monitor', 'carbon_port', raise_exception=False, default=8125)
SCOPE = config_get('monitor', 'user_scope', raise_exception=False, default='rucio')
CLIENT = StatsClient(host=SERVER, port=PORT, prefix=SCOPE)

ENABLE_METRICS = config_get_bool('monitor', 'enable_metrics', raise_exception=False, default=False)
if ENABLE_METRICS:
    METRICS_PORT = config_get_int('monitor', 'metrics_port', raise_exception=False, default=8080)
    start_http_server(METRICS_PORT, registry=REGISTRY)

COUNTERS = {}


class MultiMetric:
    """
    Thin wrapper class allowing to record both prometheus and statsd metrics.

    Inspired by the prometheus metric behavior: uses labels to parametrize metrics.
    In case of statsd, metrics are formatted using str.format(**labels). The prometheus
    ones using metric.labels(**labels) calls.

    If the prometheus metric string is not provided, it is derived from the statsd one.
    """

    def __init__(self, statsd, prom=None, documentation=None, labelnames=(), labelvalues=None, registry=None):
        """
        :param statsd: a string, eventually with keyword placeholders for the str.format(**labels) call
        :param prom: a string or a prometheus metric object
        """
        self._registry = registry or REGISTRY
        self._documentation = documentation or ''
        self._statsd = statsd
        if not prom:
            # automatically generate a prometheus metric name
            #
            # remove '.{label}' from the string for each `label`
            stats_without_labels = ''.join(tup[0].rstrip('.') for tup in string.Formatter().parse(self._statsd))
            prom = 'rucio_{}'.format(stats_without_labels).replace('.', '_')
        if isinstance(prom, str):
            self._prom = self.init_prometheus_metric(prom, self._documentation, labelnames=labelnames, labelvalues=labelvalues)
        else:
            self._prom = prom
        self._labelnames = labelnames
        self._labelvalues = labelvalues

    @abstractmethod
    def init_prometheus_metric(self, name, documentation, labelnames=(), labelvalues=None):
        pass

    def labels(self, **labelvalues):
        return self.__class__(
            prom=self._prom.labels(**labelvalues),
            statsd=self._statsd.format(**labelvalues),
            documentation=self._documentation,
            labelnames=self._labelnames,
            labelvalues=labelvalues,
            registry=self._registry,
        )


class MultiCounter(MultiMetric):

    def inc(self, delta=1):
        self._prom.inc(delta)
        CLIENT.incr(self._statsd, delta)

    def init_prometheus_metric(self, name, documentation, labelnames=(), labelvalues=None):
        return Counter(name, documentation, labelnames=labelnames, labelvalues=labelvalues, registry=self._registry)


def record_counter(name, delta=1, labels=None):
    """
    Log one or more counters by arbitrary amounts

    :param name: The counter to be updated.
    :param delta: The increment for the counter, by default increment by 1.
    :param labels: labels used to parametrize the metric
    """

    counter = COUNTERS.get(name)
    if not counter:
        COUNTERS[name] = counter = MultiCounter(statsd=name, labelnames=labels.keys() if labels else ())

    delta = abs(delta)

    if labels:
        counter.labels(**labels).inc(delta)
    else:
        counter.inc(delta)


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
