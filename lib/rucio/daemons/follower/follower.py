# Copyright 2014-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Ruturaj Gujar, <ruturaj.gujar23@gmail.com>, 2019
#
# PY3K COMPATIBLE

import logging
import os
import socket
import sys
import threading
import traceback

from rucio.common.config import config_get
from rucio.common.utils import get_thread_with_periodic_running_function
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.did import create_reports


graceful_stop = threading.Event()


@read_session
def aggregate_events():
    """
    Collect all the events affecting the dids followed by the corresponding account.
    """

    logging.info('event_aggregation: started')

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()
    live(executable='rucio-follower', hostname=hostname, pid=pid, thread=current_thread)

    while not graceful_stop.is_set():
        # Create reports of events for all the accounts.
        create_reports()
        break

    logging.info('follower: graceful stop requested')
    die(executable='rucio-follower', hostname=hostname, pid=pid, thread=current_thread)
    logging.info('follower: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the follower threads
    """
    hostname = socket.gethostname()
    sanity_check(executable='rucio-follower', hostname=hostname)

    if once:
        logging.info("executing one follower iteration only")
        aggregate_events()
    else:
        logging.info("starting follower threads")
        # Run the follower daemon thrice a day
        threads = [get_thread_with_periodic_running_function(28800, aggregate_events, graceful_stop) for i in range(threads)]
        [t.start() for t in threads]

        logging.info("waiting for interrupts")
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
