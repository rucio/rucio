# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015
# - Wen Guan, <wen.guan@cern.ch>, 2014-2016

"""
Conveyor throttler is a daemon to manage rucio internal queue.
"""

import logging
import os
import socket
import sys
import threading
import time
import traceback


from rucio.common.config import config_get
from rucio.core import heartbeat

from rucio.daemons.conveyor.utils import schedule_requests

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def throttler(once=False, sleep_time=600):
    """
    Main loop to check rse transfer limits.
    """

    logging.info('Throttler starting')

    executable = 'throttler'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb = heartbeat.live(executable, hostname, pid, hb_thread)

    logging.info('Throttler started - thread (%i/%i) timeout (%s)' % (hb['assign_thread'], hb['nr_threads'], sleep_time))

    current_time = time.time()
    while not graceful_stop.is_set():

        try:
            hb = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            logging.info('Throttler - thread (%i/%i)' % (hb['assign_thread'], hb['nr_threads']))
            if hb['assign_thread'] != 0:
                logging.info('Throttler thread id is not 0, will sleep. Only thread 0 will work')
                while time.time() < current_time + sleep_time:
                    time.sleep(1)
                    if graceful_stop.is_set() or once:
                        break
                current_time = time.time()
                continue

            logging.info("Throttler thread %s - schedule requests" % hb['assign_thread'])
            schedule_requests()

            while time.time() < current_time + sleep_time:
                time.sleep(1)
                if graceful_stop.is_set() or once:
                    break
            current_time = time.time()
        except:
            logging.critical('Throtter thread %s - %s' % (hb['assign_thread'], traceback.format_exc()))

        if once:
            break

    logging.info('Throtter thread %s - graceful stop requested' % (hb['assign_thread']))

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('Throtter thread %s - graceful stop done' % (hb['assign_thread']))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, sleep_time=600):
    """
    Starts up the conveyer threads.
    """
    threads = []
    logging.info('starting throttler thread')
    throttler_thread = threading.Thread(target=throttler, kwargs={'once': once, 'sleep_time': sleep_time})

    threads.append(throttler_thread)
    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while len(threads) > 0:
        threads = [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
