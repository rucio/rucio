# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2018-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2019-2020
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
from __future__ import division

import logging
import math
import os
import socket
import threading
import time
import traceback
from sys import stdout

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.exception import DataIdentifierNotFound, ReplicaNotFound
from rucio.common.utils import chunks
from rucio.core import heartbeat
from rucio.core.did import get_metadata
from rucio.core.replica import (update_replicas_states, get_replicas_state,
                                bulk_delete_bad_replicas, list_expired_temporary_unavailable_replicas)
from rucio.db.sqla.constants import BadFilesStatus, ReplicaState
from rucio.db.sqla.session import get_session

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

    executable = 'minos-temporary-expiration'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logging.info('%s Minos Temporary Expiration starting', prepend_str)

    time.sleep(10)  # To prevent running on the same partition if all the daemons restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])

    logging.info('%s Minos Temporary Expiration started', prepend_str)

    chunk_size = 10  # The chunk size used for the commits

    while not graceful_stop.is_set():
        start_time = time.time()
        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
        prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
        try:
            # Get list of expired TU replicas
            logging.info('%s Getting list of expired replicas', prepend_str)
            expired_replicas = list_expired_temporary_unavailable_replicas(total_workers=heart_beat['nr_threads'],
                                                                           worker_number=heart_beat['assign_thread'],
                                                                           limit=1000)
            logging.info('%s %s expired replicas returned', prepend_str, len(expired_replicas))
            logging.debug('%s List of expired replicas returned %s', prepend_str, str(expired_replicas))
            replicas = []
            bad_replicas = []
            nchunk = 0
            tot_chunk = int(math.ceil(len(expired_replicas) / float(chunk_size)))
            session = get_session()
            for chunk in chunks(expired_replicas, chunk_size):
                skip_replica_update = []
                # Process and update the replicas in chunks
                for replica in chunk:
                    scope, name, rse_id = replica[0], replica[1], replica[2]
                    states_dictionary = get_replicas_state(scope=scope, name=name, session=session)
                    # Check if the replica is not declared bad
                    # If already declared bad don't update the replica state, but remove from bad_pfns
                    if not (ReplicaState.BAD in states_dictionary and rse_id in states_dictionary[ReplicaState.BAD]):
                        replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.AVAILABLE})
                    else:
                        skip_replica_update.append((scope, name))
                    # Remove the replicas from bad_replicas table in chunks
                    bad_replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': BadFilesStatus.TEMPORARY_UNAVAILABLE})
                try:
                    nchunk += 1
                    logging.debug('%s Running on %s chunk out of %s', prepend_str, nchunk, tot_chunk)
                    update_replicas_states(replicas, nowait=True, session=session)
                    bulk_delete_bad_replicas(bad_replicas, session=session)
                    session.commit()  # pylint: disable=no-member
                except (ReplicaNotFound, DataIdentifierNotFound) as error:
                    session.rollback()  # pylint: disable=no-member
                    logging.warning('%s One of the replicas does not exist anymore. Updating and deleting one by one. Error : %s', prepend_str, str(error))
                    for replica in chunk:
                        scope, name, rse_id = replica[0], replica[1], replica[2]
                        logging.debug('%s Working on %s:%s on %s', prepend_str, scope, name, rse_id)
                        try:
                            # First check if the DID exists
                            get_metadata(scope, name)
                            if (scope, name) not in skip_replica_update:
                                update_replicas_states([{'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.AVAILABLE}, ], nowait=True, session=session)
                            bulk_delete_bad_replicas([{'scope': scope, 'name': name, 'rse_id': rse_id, 'state': BadFilesStatus.TEMPORARY_UNAVAILABLE}, ], session=session)
                            session.commit()  # pylint: disable=no-member
                        except DataIdentifierNotFound:
                            session.rollback()  # pylint: disable=no-member
                            logging.warning('%s DID %s:%s does not exist anymore.', prepend_str, scope, name)
                            bulk_delete_bad_replicas([{'scope': scope, 'name': name, 'rse_id': rse_id, 'state': BadFilesStatus.TEMPORARY_UNAVAILABLE}, ], session=session)
                            session.commit()  # pylint: disable=no-member
                        except ReplicaNotFound:
                            session.rollback()  # pylint: disable=no-member
                            logging.warning('%s Replica %s:%s on RSEID %s does not exist anymore.', prepend_str, scope, name, rse_id)
                            bulk_delete_bad_replicas([{'scope': scope, 'name': name, 'rse_id': rse_id, 'state': BadFilesStatus.TEMPORARY_UNAVAILABLE}, ], session=session)
                            session.commit()  # pylint: disable=no-member
                    session = get_session()
                except Exception:
                    session.rollback()  # pylint: disable=no-member
                    logging.critical('%s %s', prepend_str, str(traceback.format_exc()))
                    session = get_session()

        except Exception:
            logging.critical('%s %s', prepend_str, str(traceback.format_exc()))

        tottime = time.time() - start_time
        if once:
            break
        if tottime < sleep_time:
            logging.info(prepend_str + 'Will sleep for %s seconds' % (sleep_time - tottime))
            time.sleep(sleep_time - tottime)

    heartbeat.die(executable, hostname, pid, hb_thread)
    logging.info('%s Graceful stop requested', prepend_str)
    logging.info('%s Graceful stop done', prepend_str)


def run(threads=1, bulk=100, once=False, sleep_time=60):
    """
    Starts up the minos threads.
    """
    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

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
