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

import datetime
import functools
import logging
import os
import queue
import socket
import threading
import time
from collections.abc import Callable, Generator, Iterator, Sequence
from typing import Any, Generic, Optional, TypeVar, Union

from rucio.common.logging import formatted_logger
from rucio.common.utils import PriorityQueue
from rucio.core import heartbeat as heartbeat_core
from rucio.core.monitor import MetricManager

T = TypeVar('T')
METRICS = MetricManager(module=__name__)


class HeartbeatHandler:
    """
    Simple contextmanager which sets a heartbeat and associated logger on entry and cleans up the heartbeat on exit.
    """

    def __init__(self, executable: str, renewal_interval: int):
        """
        :param executable: the executable name which will be set in heartbeats
        :param renewal_interval: the interval at which the heartbeat will be renewed in the database.
        Calls to live() in-between intervals will re-use the locally cached heartbeat.
        """
        self.executable = executable
        self._hash_executable = None
        self.renewal_interval = renewal_interval
        self.older_than = renewal_interval * 10 if renewal_interval and renewal_interval > 0 else None  # 10 was chosen without any particular reason

        self.hostname = socket.getfqdn()
        self.pid = os.getpid()
        self.hb_thread = threading.current_thread()

        self.logger = logging.log
        self.last_heart_beat = None
        self.last_time = None
        self.last_payload = None

    def __enter__(self):
        heartbeat_core.sanity_check(executable=self.executable, hostname=self.hostname)
        self.live()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.last_heart_beat:
            heartbeat_core.die(self.executable, self.hostname, self.pid, self.hb_thread)
            if self.logger:
                self.logger(logging.INFO, 'Heartbeat cleaned up')

    @property
    def hash_executable(self):
        if not self._hash_executable:
            self._hash_executable = heartbeat_core.calc_hash(self.executable)
        return self._hash_executable

    @property
    def short_executable(self):
        return min(self.executable, self.hash_executable, key=len)

    def live(self, force_renew: bool = False, payload: Optional[str] = None):
        """
        :return: a tuple: <the number of the current worker>, <total number of workers>, <decorated logger>
        """
        if force_renew \
                or not self.last_time \
                or not self.last_heart_beat \
                or self.last_time < datetime.datetime.now() - datetime.timedelta(seconds=self.renewal_interval) \
                or self.last_payload != payload:
            if self.older_than:
                self.last_heart_beat = heartbeat_core.live(self.executable, self.hostname, self.pid, self.hb_thread, payload=payload, older_than=self.older_than)
            else:
                self.last_heart_beat = heartbeat_core.live(self.executable, self.hostname, self.pid, self.hb_thread, payload=payload)

            prefix = '[%i/%i]: ' % (self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'])
            self.logger = formatted_logger(logging.log, prefix + '%s')

            if not self.last_time:
                self.logger(logging.DEBUG, 'First heartbeat set')
            else:
                self.logger(logging.DEBUG, 'Heartbeat renewed')
            self.last_time = datetime.datetime.now()
            self.last_payload = payload

        return self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'], self.logger


def _activity_looper(
        once: bool,
        sleep_time: int,
        activities: Optional[Sequence[str]],
        heartbeat_handler: HeartbeatHandler,
) -> Generator[tuple[str, float], tuple[float, bool], None]:
    """
    Generator which loops (either once, or indefinitely) over all activities while ensuring that `sleep_time`
    passes between handling twice the same activity.

    Returns an activity and how much time the calling context must sleep before handling that activity
    and expects to get in return the time when the activity started to be executed and whether next
    execution must be immediate.
    """

    # For each activity, the priority queue will keep the next absolute time when that
    # activity must be handled.
    activity_next_exe_time = PriorityQueue()

    # On startup, we schedule to immediately handle all activities.
    now = time.time()
    for activity in activities or [None]:
        activity_next_exe_time[activity] = now

    while activity_next_exe_time:
        activity = activity_next_exe_time.top()
        desired_exe_time = activity_next_exe_time[activity]

        if once:
            time_to_sleep = 0
            activity_next_exe_time.pop()
        else:
            time_to_sleep = desired_exe_time - time.time()

        logger = heartbeat_handler.logger
        if time_to_sleep > 0:
            if activity:
                logger(logging.DEBUG, 'Switching to activity %s and sleeping %s seconds', activity, time_to_sleep)
            else:
                logger(logging.DEBUG, 'Sleeping %s seconds', time_to_sleep)
        else:
            if activity:
                logger(logging.DEBUG, 'Switching to activity %s', activity)
            else:
                logger(logging.DEBUG, 'Starting next iteration')

        # The calling context notifies us when the activity actually got handled. And if sleeping is desired.
        actual_exe_time, must_sleep = yield activity, time_to_sleep

        if not once:
            if must_sleep:
                time_diff = time.time() - actual_exe_time
                time_to_sleep = max(1, sleep_time - time_diff)
                activity_next_exe_time[activity] = time.time() + time_to_sleep
            else:
                activity_next_exe_time[activity] = time.time() + 1


def db_workqueue(
        once: bool,
        graceful_stop: threading.Event,
        executable: str,
        partition_wait_time: int,
        sleep_time: int,
        activities: Optional[Sequence[str]] = None,
):
    """
    Used to wrap a function for interacting with the database as a work queue: i.e. to select
    a set of rows and perform some work on those rows while ensuring that two instances running in parallel don't
    work on the same set of rows. The last condition is ensured by using heartbeats to keep track of currently
    active workers.

    :param once: Whether to stop after one iteration
    :param graceful_stop: the threading.Event() object used for graceful stop of the daemon
    :param executable: the name of the executable used for hearbeats
    :param partition_wait_time: time to wait for database partition rebalancing before starting the actual daemon loop
    :param sleep_time: time to sleep between the iterations of the daemon
    :param activities: optional list of activities on which to work. The run_once_fnc will be called on activities one by one.
    """

    def _decorate(run_once_fnc: Callable[..., Optional[Union[bool, tuple[bool, T]]]]) -> Callable[[], Iterator[Optional[T]]]:

        @functools.wraps(run_once_fnc)
        def _generator():

            with HeartbeatHandler(executable=executable, renewal_interval=sleep_time - 1) as heartbeat_handler:
                logger = heartbeat_handler.logger
                logger(logging.INFO, 'started')

                if partition_wait_time:
                    graceful_stop.wait(partition_wait_time)
                    _, _, logger = heartbeat_handler.live(force_renew=True)

                activity_loop = _activity_looper(once=once, sleep_time=sleep_time, activities=activities, heartbeat_handler=heartbeat_handler)
                activity, time_to_sleep = next(activity_loop, (None, None))
                while time_to_sleep is not None:
                    if graceful_stop.is_set():
                        break

                    if time_to_sleep > 0:
                        graceful_stop.wait(time_to_sleep)

                    _, _, logger = heartbeat_handler.live()

                    must_sleep = True
                    start_time = time.time()
                    try:
                        result = run_once_fnc(heartbeat_handler=heartbeat_handler, activity=activity)

                        # Handle return values already existing in the code
                        # TODO: update all existing daemons to always explicitly return (must_sleep, ret_value)
                        if result is None:
                            must_sleep = True
                            ret_value = None
                        elif isinstance(result, bool):
                            must_sleep = result
                            ret_value = None
                        else:
                            must_sleep, ret_value = result

                        if ret_value is not None:
                            yield ret_value
                    except Exception as e:
                        METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
                        logger(logging.CRITICAL, "Exception", exc_info=True)
                        if once:
                            raise

                    try:
                        activity, time_to_sleep = activity_loop.send((start_time, must_sleep))
                    except StopIteration:
                        break

                if not once:
                    logger(logging.INFO, 'Graceful stop requested')

        return _generator

    return _decorate


def run_daemon(
        once: bool,
        graceful_stop: threading.Event,
        executable: str,
        partition_wait_time: int,
        sleep_time: int,
        run_once_fnc: Callable[..., Optional[Union[bool, tuple[bool, Any]]]],
        activities: Optional[list[str]] = None):
    """
    Run the daemon loop and call the function run_once_fnc at each iteration
    """

    daemon = db_workqueue(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        activities=activities,
    )(run_once_fnc)

    for _ in daemon():
        pass


class ProducerConsumerDaemon(Generic[T]):
    """
    Daemon which connects N producers with M consumers via a queue.
    """

    def __init__(self, producers, consumers, graceful_stop, logger=logging.log):
        self.producers = producers
        self.consumers = consumers

        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.graceful_stop = graceful_stop
        self.active_producers = 0
        self.producers_done_event = threading.Event()
        self.logger = logger

    def _produce(
            self,
            it: Callable[[], Iterator[T]],
            wait_for_consumers: bool = False
    ):
        """
        Iterate over the generator function and put the extracted elements into the queue.

        Perform a graceful shutdown when graceful_stop is set.
        """

        i = it()
        with self.lock:
            self.active_producers += 1
        try:
            while not self.graceful_stop.is_set():
                if self.queue.qsize() > len(self.consumers):
                    self.graceful_stop.wait(1)
                    continue

                try:
                    product = next(i)
                    self.queue.put(product)
                except StopIteration:
                    break
                except Exception as e:
                    METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
                    self.logger(logging.CRITICAL, "Exception", exc_info=True)
        finally:
            with self.lock:
                self.active_producers -= 1
                if not self.active_producers > 0:
                    self.producers_done_event.set()

            if wait_for_consumers:
                self.queue.join()

    def _consume(
            self,
            fnc: Callable[[T], Any]
    ):
        """
        Wait for elements to arrive via the queue and call the given function on each element.

        If producers_done_event is set, handle all remaining elements from the queue and exit gracefully.
        """
        while not self.producers_done_event.is_set() or self.queue.unfinished_tasks:
            try:
                product = self.queue.get_nowait()
            except queue.Empty:
                self.producers_done_event.wait(1)
                continue

            try:
                fnc(product)
            except Exception as e:
                METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
                self.logger(logging.CRITICAL, "Exception", exc_info=True)
            finally:
                self.queue.task_done()

    def run(self):

        producer_threads = []
        for i, producer in enumerate(self.producers):
            thread = threading.Thread(
                target=self._produce,
                name=f'producer-{i}-{producer.__name__}',
                kwargs={
                    'it': producer,
                    'wait_for_consumers': True
                }
            )
            thread.start()
            producer_threads.append(thread)

        consumer_threads = []
        for i, consumer in enumerate(self.consumers):
            thread = threading.Thread(
                target=self._consume,
                name=f'consumer-{i}-{consumer.__name__}',
                kwargs={
                    'fnc': consumer,
                }
            )
            thread.start()
            consumer_threads.append(thread)

        logging.info('waiting for interrupts')

        while producer_threads:
            for thread in producer_threads:
                thread.join(timeout=3.14)
            producer_threads = [thread for thread in producer_threads if thread.is_alive()]

        self.producers_done_event.set()

        while consumer_threads:
            for thread in consumer_threads:
                thread.join(timeout=3.14)
            consumer_threads = [thread for thread in consumer_threads if thread.is_alive()]
