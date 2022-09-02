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
import hashlib
import logging
import os
import socket
import threading
import time

from rucio.common.logging import formatted_logger
from rucio.common.utils import PriorityQueue
from rucio.core import heartbeat


class HeartbeatHandler:
    """
    Simple contextmanager which sets a heartbeat and associated logger on entry and cleans up the heartbeat on exit.
    """

    def __init__(self, executable, renewal_interval, logger_prefix=None):
        """
        :param executable: the executable name which will be set in heartbeats
        :param renewal_interval: the interval at which the heartbeat will be renewed in the database.
        Calls to live() in-between intervals will re-use the locally cached heartbeat.
        :param logger_prefix: the prefix to be prepended to all log messages
        """
        self.executable = executable
        self.renewal_interval = renewal_interval
        self.older_than = renewal_interval * 10 if renewal_interval and renewal_interval > 0 else None  # 10 was chosen without any particular reason
        self.logger_prefix = logger_prefix or executable

        self.hostname = socket.getfqdn()
        self.pid = os.getpid()
        self.hb_thread = threading.current_thread()
        self.logger_id = hashlib.sha1(f'{self.hostname}:{self.pid}:{self.hb_thread}'.encode('utf-8')).hexdigest()[:7]

        self.logger = logging.log
        self.last_heart_beat = None
        self.last_time = None
        self.last_payload = None

    def __enter__(self):
        heartbeat.sanity_check(executable=self.executable, hostname=self.hostname)
        self.live()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.last_heart_beat:
            heartbeat.die(self.executable, self.hostname, self.pid, self.hb_thread)
            if self.logger:
                self.logger(logging.INFO, 'Heartbeat cleaned up')

    def live(self, force_renew=False, payload=None):
        """
        :return: a tuple: <the number of the current worker>, <total number of workers>, <decorated logger>
        """
        if force_renew \
                or not self.last_time \
                or not self.last_heart_beat \
                or self.last_time < datetime.datetime.now() - datetime.timedelta(seconds=self.renewal_interval) \
                or self.last_payload != payload:
            if self.older_than:
                self.last_heart_beat = heartbeat.live(self.executable, self.hostname, self.pid, self.hb_thread, payload=payload, older_than=self.older_than)
            else:
                self.last_heart_beat = heartbeat.live(self.executable, self.hostname, self.pid, self.hb_thread, payload=payload)

            prefix = '%s[%s:%i/%i]: ' % (self.logger_prefix, self.logger_id, self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'])
            self.logger = formatted_logger(logging.log, prefix + '%s')

            if not self.last_time:
                self.logger(logging.DEBUG, 'First heartbeat set')
            else:
                self.logger(logging.DEBUG, 'Heartbeat renewed')
            self.last_time = datetime.datetime.now()
            self.last_payload = payload

        return self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'], self.logger


def run_daemon(once, graceful_stop, executable, logger_prefix, partition_wait_time, sleep_time, run_once_fnc, activities=None):
    """
    Run the daemon loop and call the function run_once_fnc at each iteration
    :param once: Whether to stop after one iteration
    :param graceful_stop: the threading.Event() object used for graceful stop of the daemon
    :param executable: the name of the executable used for hearbeats
    :param logger_prefix: the prefix to be prepended to all log messages
    :param partition_wait_time: time to wait for database partition rebalancing before starting the actual daemon loop
    :param sleep_time: time to sleep between the iterations of the daemon
    :param run_once_fnc: the function which will do the actual work
    :param activities: optional list of activities on which to work. The run_once_fnc will be called on activities one by one.
    """

    with HeartbeatHandler(executable=executable, renewal_interval=sleep_time - 1, logger_prefix=logger_prefix) as heartbeat_handler:
        logger = heartbeat_handler.logger
        logger(logging.INFO, 'started')

        if partition_wait_time:
            graceful_stop.wait(partition_wait_time)
            _, _, logger = heartbeat_handler.live(force_renew=True)

        activity_next_exe_time = PriorityQueue()
        for activity in activities or [None]:
            activity_next_exe_time[activity] = time.time()

        while not graceful_stop.is_set() and activity_next_exe_time:
            if once:
                activity = activity_next_exe_time.pop()
                time_to_sleep = 0
            else:
                activity = activity_next_exe_time.top()
                time_to_sleep = activity_next_exe_time[activity] - time.time()

            if time_to_sleep > 0:
                if activity:
                    logger(logging.DEBUG, 'Switching to activity %s and sleeping %s seconds', activity, time_to_sleep)
                else:
                    logger(logging.DEBUG, 'Sleeping %s seconds', time_to_sleep)
                graceful_stop.wait(time_to_sleep)
            else:
                if activity:
                    logger(logging.DEBUG, 'Switching to activity %s', activity)
                else:
                    logger(logging.DEBUG, 'Starting next iteration')

            _, _, logger = heartbeat_handler.live()

            must_sleep = True
            start_time = time.time()
            try:
                must_sleep = run_once_fnc(activity=activity, heartbeat_handler=heartbeat_handler)
                if must_sleep is None:
                    # The run_once_fnc doesn't explicitly return whether we must sleep,
                    # so sleep by default
                    must_sleep = True
            except Exception:
                logger(logging.CRITICAL, "Exception", exc_info=True)
                if once:
                    raise

            if not once:
                if must_sleep:
                    time_diff = time.time() - start_time
                    time_to_sleep = max(1, sleep_time - time_diff)
                    activity_next_exe_time[activity] = time.time() + time_to_sleep
                else:
                    activity_next_exe_time[activity] = time.time() + 1

        if not once:
            logger(logging.INFO, 'Graceful stop requested')
