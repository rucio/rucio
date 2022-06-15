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
Abacus-Collection-Replica is a daemon to update collection replica.
"""
import functools
import logging
import threading
import time

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging
from rucio.core.replica import get_cleaned_updated_collection_replicas, update_collection_replica
from rucio.daemons.common import run_daemon

graceful_stop = threading.Event()


def collection_replica_update(once=False, limit=1000, sleep_time=10):
    """
    Main loop to check and update the collection replicas.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable='abacus-collection-replica',
        logger_prefix='collection_replica_update',
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            limit=limit,
        ),
    )


def run_once(heartbeat_handler, limit, **_kwargs):
    worker_number, total_workers, logger = heartbeat_handler.live()
    # Select a bunch of collection replicas for to update for this worker
    start = time.time()  # NOQA
    replicas = get_cleaned_updated_collection_replicas(total_workers=total_workers - 1,
                                                       worker_number=worker_number,
                                                       limit=limit)

    logger(logging.DEBUG, 'Index query time %f size=%d' % (time.time() - start, len(replicas)))
    # If the list is empty, sent the worker to sleep
    if not replicas:
        logger(logging.INFO, 'did not get any work')
        must_sleep = True
        return must_sleep

    for replica in replicas:
        worker_number, total_workers, logger = heartbeat_handler.live()
        if graceful_stop.is_set():
            break
        start_time = time.time()
        update_collection_replica(replica)
        logger(logging.DEBUG, 'update of collection replica "%s" took %f' % (replica['id'], time.time() - start_time))

    must_sleep = False
    if limit and len(replicas) < limit:
        must_sleep = True
    return must_sleep


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
