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

"""
Graphite and prometheus metrics
"""

import __main__ as main
import atexit
import logging
import os
import string
from abc import abstractmethod
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from threading import Lock
from typing import Any, Optional, TypeVar, Union

from prometheus_client import (Counter, Gauge, Histogram, REGISTRY, CollectorRegistry, generate_latest, multiprocess,
                               push_to_gateway, start_http_server, values)
from statsd import StatsClient

from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.stopwatch import Stopwatch
from rucio.common.utils import retrying

_T = TypeVar('_T')
_M = TypeVar('_M', bound="_MultiMetric")

PROMETHEUS_MULTIPROC_DIR = os.environ.get('PROMETHEUS_MULTIPROC_DIR', os.environ.get('prometheus_multiproc_dir', None))


def cleanup_prometheus_files_at_exit():
    if PROMETHEUS_MULTIPROC_DIR:
        multiprocess.mark_process_dead(os.getpid())


class MultiprocessMutexValue(values.MultiProcessValue()):
    """
    MultiprocessValue protected by mutex

    Rucio usually is deployed using the apache MPM module, which means that it both uses multiple
    subprocesses, and multiple threads per subprocess.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = Lock()

    def inc(self, amount):
        with self._lock:
            return super().inc(amount)

    def set(self, value):
        with self._lock:
            return super().set(value)

    def get(self):
        with self._lock:
            return super().get()


if PROMETHEUS_MULTIPROC_DIR:
    os.makedirs(PROMETHEUS_MULTIPROC_DIR, exist_ok=True)
    values.ValueClass = MultiprocessMutexValue

    atexit.register(cleanup_prometheus_files_at_exit)


SERVER = config_get('monitor', 'carbon_server', raise_exception=False, default=None)
PORT = config_get_int('monitor', 'carbon_port', raise_exception=False, default=8125)
SCOPE = config_get('monitor', 'user_scope', raise_exception=False, default='rucio')
STATSD_CLIENT = None
if SERVER is not None:
    STATSD_CLIENT = StatsClient(host=SERVER, port=PORT, prefix=SCOPE)

ENABLE_METRICS = config_get_bool('monitor', 'enable_metrics', raise_exception=False, default=False)
if ENABLE_METRICS:
    METRICS_PORT = config_get_int('monitor', 'metrics_port', raise_exception=False, default=8080)
    start_http_server(METRICS_PORT, registry=REGISTRY)

COUNTERS = {}
GAUGES = {}
TIMINGS = {}
METRICS_LOCK = Lock()


_HISTOGRAM_DEFAULT_BUCKETS = Histogram.DEFAULT_BUCKETS


def _cleanup_old_prometheus_files(path, file_pattern, cleanup_delay, logger):
    """cleanup behind processes which didn't finish gracefully."""

    oldest_accepted_mtime = datetime.now() - timedelta(seconds=cleanup_delay)
    for file in Path(path).glob(file_pattern):
        if not file.is_file():
            continue

        file_mtime = datetime.fromtimestamp(file.stat().st_mtime)

        if file_mtime < oldest_accepted_mtime:
            logger(logging.INFO, 'Cleaning up prometheus db file %s', file)
            try:
                os.remove(file)
            except FileNotFoundError:
                # Probably file already removed by another concurrent process
                pass


def cleanup_old_prometheus_files(logger=logging.log):
    path = PROMETHEUS_MULTIPROC_DIR
    if path:
        _cleanup_old_prometheus_files(path, file_pattern='gauge_live*.db', cleanup_delay=timedelta(hours=1).total_seconds(), logger=logger)
        _cleanup_old_prometheus_files(path, file_pattern='*.db', cleanup_delay=timedelta(days=7).total_seconds(), logger=logger)


@retrying(retry_on_exception=lambda _: True,
          wait_fixed=500,
          stop_max_attempt_number=2)
def generate_prometheus_metrics():
    cleanup_old_prometheus_files()

    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    return generate_latest(registry)


class _MultiMetric:
    """
    Thin wrapper class allowing to record both prometheus and statsd metrics.

    Inspired by the prometheus metric behavior: uses labels to parametrize metrics.
    In case of statsd, metrics are formatted using str.format(**labels). The prometheus
    ones using metric.labels(**labels) calls.

    If the prometheus metric string is not provided, it is derived from the statsd one.

    If `labelnames` is not provided, tries to extract them from the metric name by parsing
    it as a format string.
    """

    def __init__(
            self,
            statsd: str,
            prom: Optional[Union[str, Counter, Gauge, Histogram]] = None,
            documentation: Optional[str] = None,
            labelnames: Optional[Sequence[str]] = None,
            registry: Optional[CollectorRegistry] = None
    ):
        """
        :param statsd: a string, eventually with keyword placeholders for the str.format(**labels) call
        :param prom: a string prometheus metric name; or an instantiated prometheus metric object
        """
        self._registry = registry or REGISTRY
        self._documentation = documentation or ''
        self._statsd = statsd
        if not prom:
            parsed_format = list(string.Formatter().parse(statsd))
            # automatically generate a prometheus metric name
            #
            # remove '.{label}' from the string for each `label`
            # substituted dots with underscores
            if labelnames is None:
                labelnames = tuple(field_name for _, field_name, _, _ in parsed_format if field_name)
            prom = ''.join(literal_text.rstrip('.').replace('.', '_') for literal_text, *_ in parsed_format)
        labelnames = labelnames or ()
        if isinstance(prom, str):
            self._prom = self.init_prometheus_metric(prom, self._documentation, labelnames=labelnames)
        else:
            self._prom = prom

        self._labelnames = labelnames

    @abstractmethod
    def init_prometheus_metric(self, name: str, documentation: Optional[str], labelnames: Sequence[str] = ()):
        pass

    def labels(self: _M, **labelkwargs) -> _M:
        if not labelkwargs:
            return self

        return self.__class__(
            prom=self._prom.labels(**labelkwargs),
            statsd=self._statsd.format(**labelkwargs),
            documentation=self._documentation,
            labelnames=self._labelnames,
            registry=self._registry,
        )


class _MultiCounter(_MultiMetric):

    def inc(self, delta=1):
        delta = abs(delta)
        self._prom.inc(delta)
        if STATSD_CLIENT:
            STATSD_CLIENT.incr(self._statsd, delta)

    def init_prometheus_metric(self, name: str, documentation: Optional[str], labelnames: Sequence[str] = ()):
        return Counter(name, documentation, labelnames=labelnames, registry=self._registry)


class _MultiGauge(_MultiMetric):

    def set(self, value):
        self._prom.set(value)
        if STATSD_CLIENT:
            STATSD_CLIENT.gauge(self._statsd, value)

    def init_prometheus_metric(self, name: str, documentation: Optional[str], labelnames: Sequence[str] = ()):
        return Gauge(name, documentation, labelnames=labelnames, registry=self._registry)


class _MultiTiming(_MultiMetric):

    def __init__(
            self,
            statsd: str,
            prom: Optional[str] = None,
            documentation: Optional[str] = None,
            labelnames: Optional[Sequence[str]] = None,
            registry: Optional[CollectorRegistry] = None,
            buckets: Iterable[float] = _HISTOGRAM_DEFAULT_BUCKETS,
    ) -> None:
        self._stopwatch = None
        self._histogram_buckets = tuple(buckets)
        super().__init__(statsd, prom, documentation, labelnames, registry)

    def observe(self, value: float):
        self._prom.observe(value)
        if STATSD_CLIENT:
            STATSD_CLIENT.timing(self._statsd, value * 1000)

    def init_prometheus_metric(self, name: str, documentation: Optional[str], labelnames: Sequence[str] = ()):
        return Histogram(name, documentation, labelnames=labelnames, registry=self._registry, buckets=self._histogram_buckets)

    def __enter__(self):
        self._stopwatch = Stopwatch()
        return self

    def __exit__(self, typ, value, tb):
        if self._stopwatch:
            self._stopwatch.stop()
            self.observe(self._stopwatch.elapsed)


def _fetch_or_create_metric(
        name: str,
        labelnames: Optional[Sequence[str]],
        container: dict[str, _T],
        factory: Callable[[str, Optional[Sequence[str]]], _T]
) -> "_T":
    metric = container.get(name)
    if not metric:
        with METRICS_LOCK:
            metric = container.get(name)
            if not metric:
                container[name] = metric = factory(name, labelnames)
    return metric


def _fetch_or_create_counter(
        name: str,
        labelnames: Optional[Sequence[str]] = None,
        documentation: Optional[str] = None,
        registry: Optional[CollectorRegistry] = None,
) -> _MultiCounter:
    return _fetch_or_create_metric(
        name=name,
        labelnames=labelnames,
        container=COUNTERS,
        factory=lambda _name, _labelnames: _MultiCounter(statsd=_name, labelnames=_labelnames,
                                                         documentation=documentation, registry=registry)
    )


def _fetch_or_create_gauge(
        name: str,
        labelnames: Optional[Sequence[str]] = None,
        documentation: Optional[str] = None,
        registry: Optional[CollectorRegistry] = None,
) -> _MultiGauge:
    return _fetch_or_create_metric(
        name=name,
        labelnames=labelnames,
        container=GAUGES,
        factory=lambda _name, _labelnames: _MultiGauge(statsd=_name, labelnames=_labelnames,
                                                       documentation=documentation, registry=registry)
    )


def _fetch_or_create_timer(
        name: str,
        labelnames: Optional[Sequence[str]] = None,
        documentation: Optional[str] = None,
        registry: Optional[CollectorRegistry] = None,
        buckets: Iterable[float] = _HISTOGRAM_DEFAULT_BUCKETS
) -> _MultiTiming:
    return _fetch_or_create_metric(
        name=name,
        labelnames=labelnames,
        container=TIMINGS,
        factory=lambda _name, _labels: _MultiTiming(statsd=_name, labelnames=_labels, documentation=documentation,
                                                    registry=registry, buckets=buckets)
    )


class MetricManager:

    """
    Wrapper for metrics which prefixes them automatically with the given prefix or,
    alternatively, with the path of the module.
    """

    def __init__(self, prefix: Optional[str] = None, module: Optional[str] = None,
                 registry: Optional[CollectorRegistry] = None, push_gateways: Optional[Sequence[str]] = None):
        if prefix:
            self.prefix = prefix
        elif module:
            self.prefix = module
        else:
            self.prefix = None
        self.registry = registry or REGISTRY
        self.push_gateways = push_gateways or []

    def full_name(self, name: str):
        if self.prefix:
            return f'{self.prefix}.{name}'
        return name

    def get_registry(self) -> CollectorRegistry:
        return self.registry

    def counter(
            self,
            name: str,
            *,
            labelnames: Optional[Sequence[str]] = None,
            documentation: Optional[str] = None,
    ) -> _MultiCounter:
        """
        Log a counter.

        :param name: The name (suffix) of the counter to be retrieved
        :param labelnames: optional labels used to parametrize the metric
        :param documentation: optional prometheus documentation for this metric
        """
        return _fetch_or_create_counter(name=self.full_name(name), labelnames=labelnames, documentation=documentation)

    def gauge(
            self,
            name: str,
            *,
            labelnames: Optional[Sequence[str]] = None,
            documentation: Optional[str] = None,
    ) -> _MultiGauge:
        """
        Log gauge information for a single stat

        :param name: The name (suffix) of the counter to be retrieved
        :param labelnames: optional labels used to parametrize the metric
        :param documentation: optional prometheus documentation for this metric
        """
        return _fetch_or_create_gauge(name=self.full_name(name), labelnames=labelnames, documentation=documentation)

    def timer(
            self,
            name: str,
            *,
            labelnames: Optional[Sequence[str]] = None,
            documentation: Optional[str] = None,
            buckets: Iterable[float] = _HISTOGRAM_DEFAULT_BUCKETS
    ) -> _MultiTiming:
        """
        Log a time measurement.

        :param name: The name (suffix) of the counter to be retrieved
        :param labelnames: optional labels used to parametrize the metric
        :param documentation: optional prometheus documentation for this metric
        :param buckets: Optional iterable of histogram bucket separators.
        """
        return _fetch_or_create_timer(name=self.full_name(name), labelnames=labelnames, documentation=documentation, buckets=buckets)

    def time_it(self, original_function=None, *, buckets=_HISTOGRAM_DEFAULT_BUCKETS):
        """
        Function decorator which records a timer: the amount of time spent in the function.
        """
        def _decorator(func):
            @wraps(func)
            def _wrapper(*args, **kwargs):
                with self.timer(name=func.__name__, buckets=buckets):
                    return func(*args, **kwargs)
            return _wrapper
        if original_function:
            return _decorator(original_function)
        return _decorator

    def count_it(self, original_function=None):
        """
        Function decorator which records a counter: how many times the function was executed.
        """
        def _decorator(func):
            @wraps(func)
            def _wrapper(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                finally:
                    _fetch_or_create_counter(name=self.full_name(func.__name__) + '_cnt').inc()
            return _wrapper
        if original_function:
            return _decorator(original_function)
        return _decorator

    def push_metrics_to_gw(self, job: Optional[str] = None, grouping_key: Optional[dict[str, Any]] = None) -> None:
        """
        Push the metrics out to the prometheus push gateways. This is useful for short-running programs which don't
        live long enough to be reliably scraped in the prometheus pull model.
        """

        if not job:
            job = Path(main.__file__).stem
        grouping_key = grouping_key or {}

        for server in self.push_gateways:
            try:
                push_to_gateway(server.strip(), job=job, registry=self.registry, grouping_key=grouping_key)
            except:
                continue
