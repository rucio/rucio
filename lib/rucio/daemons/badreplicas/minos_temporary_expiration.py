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
# - Martin Barisits <martin.barisits@cern.ch>, 2018-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2019-2021
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021

from __future__ import division

import logging
import math
import os
import re
import socket
import threading
import time
import traceback

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.exception import DataIdentifierNotFound, ReplicaNotFound, DatabaseException
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.utils import chunks, daemon_sleep
from rucio.core import heartbeat
from rucio.core.did import get_metadata
from rucio.core.replica import (update_replicas_states, get_replicas_state,
                                bulk_delete_bad_replicas, list_expired_temporary_unavailable_replicas)
from rucio.db.sqla.constants import BadFilesStatus, ReplicaState
from rucio.db.sqla.session import get_session


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
    prefix = 'minos_temporary_expiration[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'Minos Temporary Expiration starting')

    time.sleep(10)  # To prevent running on the same partition if all the daemons restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    logger(logging.INFO, 'Minos Temporary Expiration started')

    chunk_size = 10  # The chunk size used for the commits

    while not graceful_stop.is_set():
        start_time = time.time()
        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
        try:
            # Get list of expired TU replicas
            logger(logging.INFO, 'Getting list of expired replicas')
            expired_replicas = list_expired_temporary_unavailable_replicas(total_workers=heart_beat['nr_threads'],
                                                                           worker_number=heart_beat['assign_thread'],
                                                                           limit=1000)
            logger(logging.INFO, '%s expired replicas returned', len(expired_replicas))
            logger(logging.DEBUG, 'List of expired replicas returned %s', str(expired_replicas))
            replicas = []
            bad_replicas = []
            nchunk = 0
            tot_chunk = int(math.ceil(len(expired_replicas) / float(chunk_size)))
            session = get_session()
            for chunk in chunks(expired_replicas, chunk_size):
                heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
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
                    logger(logging.DEBUG, 'Running on %s chunk out of %s', nchunk, tot_chunk)
                    update_replicas_states(replicas, nowait=True, session=session)
                    bulk_delete_bad_replicas(bad_replicas, session=session)
                    session.commit()  # pylint: disable=no-member
                except (ReplicaNotFound, DataIdentifierNotFound) as error:
                    session.rollback()  # pylint: disable=no-member
                    logger(logging.WARNING, 'One of the replicas does not exist anymore. Updating and deleting one by one. Error : %s', str(error))
                    for replica in chunk:
                        scope, name, rse_id = replica[0], replica[1], replica[2]
                        logger(logging.DEBUG, 'Working on %s:%s on %s', scope, name, rse_id)
                        try:
                            # First check if the DID exists
                            get_metadata(scope, name)
                            if (scope, name) not in skip_replica_update:
                                update_replicas_states([{'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.AVAILABLE}, ], nowait=True, session=session)
                            bulk_delete_bad_replicas([{'scope': scope, 'name': name, 'rse_id': rse_id, 'state': BadFilesStatus.TEMPORARY_UNAVAILABLE}, ], session=session)
                            session.commit()  # pylint: disable=no-member
                        except DataIdentifierNotFound:
                            session.rollback()  # pylint: disable=no-member
                            logger(logging.WARNING, 'DID %s:%s does not exist anymore.', scope, name)
                            bulk_delete_bad_replicas([{'scope': scope, 'name': name, 'rse_id': rse_id, 'state': BadFilesStatus.TEMPORARY_UNAVAILABLE}, ], session=session)
                            session.commit()  # pylint: disable=no-member
                        except ReplicaNotFound:
                            session.rollback()  # pylint: disable=no-member
                            logger(logging.WARNING, 'Replica %s:%s on RSEID %s does not exist anymore.', scope, name, rse_id)
                            bulk_delete_bad_replicas([{'scope': scope, 'name': name, 'rse_id': rse_id, 'state': BadFilesStatus.TEMPORARY_UNAVAILABLE}, ], session=session)
                            session.commit()  # pylint: disable=no-member
                    session = get_session()
                except (DatabaseException, DatabaseError) as error:
                    if re.match('.*ORA-00054.*', error.args[0]) or re.match('.*ORA-00060.*', error.args[0]) or 'ERROR 1205 (HY000)' in error.args[0]:
                        logger(logging.WARNING, 'Lock detected when handling request - skipping: %s', str(error))
                    else:
                        logger(logging.ERROR, 'Exception', exc_info=True)
                    session.rollback()
                    session = get_session()
                except Exception:
                    session.rollback()  # pylint: disable=no-member
                    logger(logging.CRITICAL, str(traceback.format_exc()))
                    session = get_session()

        except Exception:
            logger(logging.CRITICAL, str(traceback.format_exc()))

        if once:
            break
        daemon_sleep(start_time=start_time, sleep_time=sleep_time, graceful_stop=graceful_stop)

    heartbeat.die(executable, hostname, pid, hb_thread)
    logger(logging.INFO, 'Graceful stop requested')
    logger(logging.INFO, 'Graceful stop done')


def run(threads=1, bulk=100, once=False, sleep_time=60):
    """
    Starts up the minos threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.log(logging.INFO, 'Will run only one iteration in a single threaded mode')
        minos_tu_expiration(bulk=bulk, once=once)
    else:
        logging.log(logging.INFO, 'Starting Minos Temporary Expiration threads')
        thread_list = [threading.Thread(target=minos_tu_expiration, kwargs={'once': once,
                                                                            'sleep_time': sleep_time,
                                                                            'bulk': bulk}) for _ in range(0, threads)]
        [thread.start() for thread in thread_list]
        logging.log(logging.INFO, 'Waiting for interrupts')
        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.is_alive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
