# -*- coding: utf-8 -*-
# Copyright 2014-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

"""
Abacus-RSE is a daemon to update RSE counters.
"""

import logging
import os
import socket
import sys
import threading
import time
import traceback

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.utils import get_thread_with_periodic_running_function
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.rse_counter import get_updated_rse_counters, update_rse_counter, fill_rse_counter_history_table

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rse_update(once=False):
    """
    Main loop to check and update the RSE Counters.
    """

    logging.info('rse_update: starting')

    logging.info('rse_update: started')

    # Make an initial heartbeat so that all abacus-rse daemons have the correct worker number on the next try
    executable = 'abacus-rse'
    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()
    live(executable=executable, hostname=hostname, pid=pid, thread=current_thread)

    while not graceful_stop.is_set():
        try:
            # Heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread)

            # Select a bunch of rses for to update for this worker
            start = time.time()  # NOQA
            rse_ids = get_updated_rse_counters(total_workers=heartbeat['nr_threads'],
                                               worker_number=heartbeat['assign_thread'])
            logging.debug('Index query time %f size=%d' % (time.time() - start, len(rse_ids)))

            # If the list is empty, sent the worker to sleep
            if not rse_ids and not once:
                logging.info('rse_update[%s/%s] did not get any work' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1))
                time.sleep(10)
            else:
                for rse_id in rse_ids:
                    if graceful_stop.is_set():
                        break
                    start_time = time.time()
                    update_rse_counter(rse_id=rse_id)
                    logging.debug('rse_update[%s/%s]: update of rse "%s" took %f' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rse_id, time.time() - start_time))
        except Exception:
            logging.error(traceback.format_exc())
        if once:
            break

    logging.info('rse_update: graceful stop requested')
    die(executable=executable, hostname=hostname, pid=pid, thread=current_thread)
    logging.info('rse_update: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, threads=1, fill_history_table=False):
    """
    Starts up the Abacus-RSE threads.
    """
    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    executable = 'abacus-rse'
    hostname = socket.gethostname()
    sanity_check(executable=executable, hostname=hostname)

    if once:
        logging.info('main: executing one iteration only')
        rse_update(once)
    else:
        logging.info('main: starting threads')
        threads = [threading.Thread(target=rse_update, kwargs={'once': once}) for i in range(0, threads)]
        if fill_history_table:
            threads.append(get_thread_with_periodic_running_function(3600, fill_rse_counter_history_table, graceful_stop))
        [t.start() for t in threads]
        logging.info('main: waiting for interrupts')
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
