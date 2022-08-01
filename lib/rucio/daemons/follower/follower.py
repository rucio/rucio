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

import logging
import os
import socket
import threading
import time

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging
from rucio.common.utils import get_thread_with_periodic_running_function
from rucio.core.did import create_reports
from rucio.core.heartbeat import live, die, sanity_check

graceful_stop = threading.Event()


def aggregate_events(once=False):
    """
    Collect all the events affecting the dids followed by the corresponding account.
    """

    logging.info('event_aggregation: started')

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()
    live(executable='rucio-follower', hostname=hostname, pid=pid, thread=current_thread)

    while not graceful_stop.is_set():
        heartbeat = live(executable='rucio-follower', hostname=hostname, pid=pid, thread=current_thread)
        # Create a report of events and send a mail to the corresponding account.
        start_time = time.time()
        create_reports(total_workers=heartbeat['nr_threads'] - 1,
                       worker_number=heartbeat['assign_thread'])
        logging.info('worker[%s/%s] took %s for creating reports' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, time.time() - start_time))

        if once:
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
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    hostname = socket.gethostname()
    sanity_check(executable='rucio-follower', hostname=hostname)

    if once:
        logging.info("executing one follower iteration only")
        aggregate_events(once)
    else:
        logging.info("starting follower threads")
        # Run the follower daemon thrice a day
        threads = [get_thread_with_periodic_running_function(28800, aggregate_events, graceful_stop) for i in range(threads)]
        [t.start() for t in threads]

        logging.info("waiting for interrupts")
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
