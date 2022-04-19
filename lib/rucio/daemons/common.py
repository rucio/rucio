# -*- coding: utf-8 -*-
# Copyright CERN since 2022
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

from __future__ import division

import datetime
import logging
import os
import socket
import threading

from rucio.common.logging import formatted_logger
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

        self.logger = None
        self.last_heart_beat = None
        self.last_time = None

    def __enter__(self):
        heartbeat.sanity_check(executable=self.executable, hostname=self.hostname)
        self.live()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.last_heart_beat:
            heartbeat.die(self.executable, self.hostname, self.pid, self.hb_thread)
            if self.logger:
                self.logger(logging.INFO, 'Heartbeat cleaned up')

    def live(self):
        """
        :return: a tuple: <the number of the current worker>, <total number of workers>, <decorated logger>
        """
        if not self.last_time or self.last_time < datetime.datetime.now() - datetime.timedelta(seconds=self.renewal_interval):
            if self.older_than:
                self.last_heart_beat = heartbeat.live(self.executable, self.hostname, self.pid, self.hb_thread, older_than=self.older_than)
            else:
                self.last_heart_beat = heartbeat.live(self.executable, self.hostname, self.pid, self.hb_thread)

            prefix = '%s[%i/%i]: ' % (self.logger_prefix, self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'])
            self.logger = formatted_logger(logging.log, prefix + '%s')

            if not self.last_time:
                self.logger(logging.DEBUG, 'First heartbeat set')
            else:
                self.logger(logging.DEBUG, 'Heartbeat renewed')
            self.last_time = datetime.datetime.now()

        return self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'], self.logger
