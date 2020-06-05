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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020

"""
Abacus-Collection-Replica is a daemon to update collection replica.
"""

import logging
import os
import socket
import sys
import threading
import time
import traceback

from rucio.common.config import config_get
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.replica import get_cleaned_updated_collection_replicas, update_collection_replica

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def collection_replica_update(once=False):
    """
    Main loop to check and update the collection replicas.
    """

    logging.info('collection_replica_update: starting')

    logging.info('collection_replica_update: started')

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

            # Select a bunch of collection replicas for to update for this worker
            start = time.time()  # NOQA
            replicas = get_cleaned_updated_collection_replicas(total_workers=heartbeat['nr_threads'] - 1,
                                                               worker_number=heartbeat['assign_thread'])

            logging.debug('Index query time %f size=%d' % (time.time() - start, len(replicas)))
            # If the list is empty, sent the worker to sleep
            if not replicas and not once:
                logging.info('collection_replica_update[%s/%s] did not get any work' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1))
                time.sleep(10)
            else:
                for replica in replicas:
                    if graceful_stop.is_set():
                        break
                    start_time = time.time()
                    update_collection_replica(replica)
                    logging.debug('collection_replica_update[%s/%s]: update of collection replica "%s" took %f' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, replica['id'], time.time() - start_time))
        except Exception:
            logging.error(traceback.format_exc())
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


def run(once=False, threads=1):
    """
    Starts up the Abacus-Collection-Replica threads.
    """
    executable = 'abacus-collection-replica'
    hostname = socket.gethostname()
    sanity_check(executable=executable, hostname=hostname)

    if once:
        logging.info('main: executing one iteration only')
        collection_replica_update(once)
    else:
        logging.info('main: starting threads')
        threads = [threading.Thread(target=collection_replica_update, kwargs={'once': once}) for i in range(0, threads)]
        [t.start() for t in threads]
        logging.info('main: waiting for interrupts')
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
