# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Martin Barisits <martin.barisits@cern.ch>, 2020
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Cedric Serfon <cedric.serfon@cern.ch>, 2021
# - Joel Dierkes <joel.dierkes@cern.ch>, 2021

"""
Abacus-Collection-Replica is a daemon to update collection replica.
"""

import logging
import os
import socket
import threading
import time
import traceback

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging, formatted_logger
from rucio.common.utils import daemon_sleep
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.replica import get_cleaned_updated_collection_replicas, update_collection_replica

graceful_stop = threading.Event()


def collection_replica_update(once=False, limit=1000, sleep_time=10):
    """
    Main loop to check and update the collection replicas.
    """

    # Make an initial heartbeat so that all abacus-collection-replica daemons have the correct worker number on the next try
    executable = 'abacus-collection-replica'
    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()
    live(executable=executable, hostname=hostname, pid=pid, thread=current_thread)

    while not graceful_stop.is_set():
        try:
            # Heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread)

            prepend_str = 'collection_replica_update[%i/%i] : ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
            logger = formatted_logger(logging.log, prepend_str + '%s')

            # Select a bunch of collection replicas for to update for this worker
            start = time.time()  # NOQA
            replicas = get_cleaned_updated_collection_replicas(total_workers=heartbeat['nr_threads'] - 1,
                                                               worker_number=heartbeat['assign_thread'],
                                                               limit=limit)

            logger(logging.DEBUG, 'Index query time %f size=%d' % (time.time() - start, len(replicas)))
            # If the list is empty, sent the worker to sleep
            if not replicas and not once:
                logger(logging.INFO, 'did not get any work')
                daemon_sleep(start_time=start, sleep_time=sleep_time, graceful_stop=graceful_stop)
            else:
                for replica in replicas:
                    if graceful_stop.is_set():
                        break
                    start_time = time.time()
                    update_collection_replica(replica)
                    logger(logging.DEBUG, 'update of collection replica "%s" took %f' % (replica['id'], time.time() - start_time))
                if limit and len(replicas) < limit and not once:
                    daemon_sleep(start_time=start, sleep_time=sleep_time, graceful_stop=graceful_stop)

        except Exception:
            logger(logging.ERROR, traceback.format_exc())
        if once:
            break

    logging.info('collection_replica_update: graceful stop requested')
    die(executable=executable, hostname=hostname, pid=pid, thread=current_thread)
    logging.info('collection_replica_update: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, threads=1, sleep_time=10, limit=1000):
    """
    Starts up the Abacus-Collection-Replica threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    executable = 'abacus-collection-replica'
    hostname = socket.gethostname()
    sanity_check(executable=executable, hostname=hostname)

    if once:
        logging.info('main: executing one iteration only')
        collection_replica_update(once)
    else:
        logging.info('main: starting threads')
        threads = [threading.Thread(target=collection_replica_update, kwargs={'once': once, 'sleep_time': sleep_time, 'limit': limit})
                   for _ in range(0, threads)]
        [t.start() for t in threads]
        logging.info('main: waiting for interrupts')
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
