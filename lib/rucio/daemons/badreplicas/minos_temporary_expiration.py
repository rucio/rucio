# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2018
#
# PY3K COMPATIBLE

import logging
import os
import socket
import threading
import time

from sys import stdout, argv

from rucio.db.sqla.constants import BadFilesStatus, ReplicaState

from rucio.db.sqla.session import get_session
from rucio.common.config import config_get
from rucio.common.utils import chunks
from rucio.core.replica import (update_replicas_states,
                                bulk_delete_bad_replicas, list_expired_temporary_unavailable_replicas)

from rucio.core import heartbeat


logging.basicConfig(stream=stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


graceful_stop = threading.Event()


def minos_tu_expiration(bulk=1000, once=False, sleep_time=60):
    """
    Creates a Minos Temporary Unavailable Replicas Expiration Worker that
    gets the list of expired TU replicas and sets them back to AVAILABLE.

    :param bulk: The number of requests to process.
    :param once: Run only once.
    :param sleep_time: Time between two cycles.
    """

    executable = ' '.join(argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
    logging.info(prepend_str + 'Minos Temporary Expiration starting')

    time.sleep(10)  # To prevent running on the same partition if all the daemons restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])

    logging.info(prepend_str + 'Minos Temporary Expiration started')

    chunk_size = 10  # The chunk size used for the commits

    while not graceful_stop.is_set():
        start_time = time.time()
        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
        prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
        try:
            # Get list of expired TU replicas
            logging.info(prepend_str + 'Getting list of expired replicas')
            expired_replicas = list_expired_temporary_unavailable_replicas(total_workers=heart_beat['nr_threads'] - 1,
                                                                           worker_number=heart_beat['assign_thread'],
                                                                           limit=1000)
            logging.info(prepend_str + '%s expired replicas returned' % len(expired_replicas))
            logging.debug(prepend_str + 'List of expired replicas returned %s' % str(expired_replicas))
            replicas = []
            bad_replicas = []
            for replica in expired_replicas:
                replicas.append({'scope': replica[0], 'name': replica[1], 'rse_id': replica[2], 'state': ReplicaState.AVAILABLE})
                bad_replicas.append({'scope': replica[0], 'name': replica[1], 'rse_id': replica[2], 'state': BadFilesStatus.TEMPORARY_UNAVAILABLE})
            session = get_session()

            for chunk in chunks(replicas, chunk_size):
                # Process and update the replicas in chunks
                update_replicas_states(chunk, nowait=False, session=session)
            for chunk in chunks(bad_replicas, chunk_size):
                # Remove the replicas from bad_replicas table in chunks
                bulk_delete_bad_replicas(chunk, session=session)

            session.commit()  # pylint: disable=no-member

        except Exception as error:
            logging.error(prepend_str + '%s' % (str(error)))

        tottime = time.time() - start_time
        if once:
            break
        if tottime < sleep_time:
            logging.info(prepend_str + 'Will sleep for %s seconds' % (sleep_time - tottime))
            time.sleep(sleep_time - tottime)

    heartbeat.die(executable, hostname, pid, hb_thread)
    logging.info(prepend_str + 'Graceful stop requested')
    logging.info(prepend_str + 'Graceful stop done')


def run(threads=1, bulk=100, once=False, sleep_time=60):
    """
    Starts up the minos threads.
    """

    if once:
        logging.info('Will run only one iteration in a single threaded mode')
        minos_tu_expiration(bulk=bulk, once=once)
    else:
        logging.info('Starting Minos Temporary Expiration threads')
        thread_list = [threading.Thread(target=minos_tu_expiration, kwargs={'once': once,
                                                                            'sleep_time': sleep_time,
                                                                            'bulk': bulk}) for _ in range(0, threads)]
        [thread.start() for thread in thread_list]
        logging.info('Waiting for interrupts')
        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.isAlive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
