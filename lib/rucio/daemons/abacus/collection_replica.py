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

"""
Abacus-Collection-Replica is a daemon to update collection replica.
"""

import logging
import sys
import threading
import time
import traceback

from rucio.common.config import config_get
from rucio.core.replica import get_cleaned_updated_collection_replicas, update_collection_replica

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def collection_replica_update(once=False, process=0, total_processes=1, thread=0, threads_per_process=1):
    """
    Main loop to check and update the collection replicas.
    """

    logging.info('collection_replica_update: starting')

    logging.info('collection_replica_update: started')

    while not graceful_stop.is_set():
        try:
            # Select a bunch of collection replicas for to update for this worker
            start = time.time()  # NOQA
            replicas = get_cleaned_updated_collection_replicas(total_workers=total_processes * threads_per_process - 1, worker_number=process * threads_per_process + thread)

            logging.debug('Index query time %f size=%d' % (time.time() - start, len(replicas)))
            # If the list is empty, sent the worker to sleep
            if not replicas and not once:
                logging.info('collection_replica_update[%s/%s] did not get any work' % (process * threads_per_process + thread, total_processes * threads_per_process - 1))
                time.sleep(10)
            else:
                for replica_id in replicas:
                    if graceful_stop.is_set():
                        break
                    start_time = time.time()
                    update_collection_replica(replica_id)
                    logging.debug('collection_replica_update[%s/%s]: update of collection replica "%s" took %f' % (process * threads_per_process + thread, total_processes * threads_per_process - 1, replica_id, time.time() - start_time))
        except Exception:
            logging.error(traceback.format_exc())
        if once:
            break

    logging.info('collection_replica_update: graceful stop requested')

    logging.info('collection_replica_update: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, threads_per_process=11):
    """
    Starts up the Abacus-Collection-Replica threads.
    """
    if once:
        logging.info('main: executing one iteration only')
        collection_replica_update(once)
    else:
        logging.info('main: starting threads')
        threads = [threading.Thread(target=collection_replica_update, kwargs={'process': process, 'total_processes': total_processes, 'once': once, 'thread': i, 'threads_per_process': threads_per_process}) for i in xrange(0, threads_per_process)]
        [t.start() for t in threads]
        logging.info('main: waiting for interrupts')
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
