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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from __future__ import division

import logging
import os
import socket
import threading
import time
from datetime import datetime, timedelta
from math import ceil
from sys import exc_info
from traceback import format_exception

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.exception import DatabaseException, ConfigNotFound
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.utils import chunks, daemon_sleep
from rucio.core import monitor, heartbeat
from rucio.core.config import get
from rucio.core.replica import list_bad_replicas, get_replicas_state, list_bad_replicas_history, update_bad_replicas_history
from rucio.core.rule import update_rules_for_lost_replica, update_rules_for_bad_replica, get_evaluation_backlog
from rucio.db.sqla.constants import ReplicaState

GRACEFUL_STOP = threading.Event()


def necromancer(thread=0, bulk=5, once=False, sleep_time=60):
    """
    Creates a Necromancer Worker that gets a list of bad replicas for a given hash,
    identify lost DIDs and for non-lost ones, set the locks and rules for reevaluation.

    :param thread: Thread number at startup.
    :param bulk: The number of requests to process.
    :param once: Run only once.
    :param sleep_time: Thread sleep time after each chunk of work.
    """

    update_history_threshold = 3600
    update_history_time = time.time()

    executable = 'necromancer'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)

    while not GRACEFUL_STOP.is_set():

        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
        prefix = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
        logger = formatted_logger(logging.log, prefix + '%s')

        # Check if there is a Judge Evaluator backlog
        try:
            max_evaluator_backlog_count = get('necromancer', 'max_evaluator_backlog_count')
        except ConfigNotFound:
            max_evaluator_backlog_count = None
        try:
            max_evaluator_backlog_duration = get('necromancer', 'max_evaluator_backlog_duration')
        except ConfigNotFound:
            max_evaluator_backlog_duration = None
        if max_evaluator_backlog_count or max_evaluator_backlog_duration:
            backlog = get_evaluation_backlog(expiration_time=sleep_time)
            if max_evaluator_backlog_count and \
               backlog[0] and \
               max_evaluator_backlog_duration and \
               backlog[1] and \
               backlog[0] > max_evaluator_backlog_count and \
               backlog[1] < datetime.utcnow() - timedelta(minutes=max_evaluator_backlog_duration):
                logger(logging.ERROR, 'Necromancer: Judge evaluator backlog count and duration hit, stopping operation')
                GRACEFUL_STOP.wait(30)
                continue
            elif max_evaluator_backlog_count and backlog[0] and backlog[0] > max_evaluator_backlog_count:
                logger(logging.ERROR, 'Necromancer: Judge evaluator backlog count hit, stopping operation')
                GRACEFUL_STOP.wait(30)
                continue
            elif max_evaluator_backlog_duration and backlog[1] and backlog[1] < datetime.utcnow() - timedelta(minutes=max_evaluator_backlog_duration):
                logger(logging.ERROR, 'Necromancer: Judge evaluator backlog duration hit, stopping operation')
                GRACEFUL_STOP.wait(30)
                continue

        stime = time.time()
        replicas = []
        try:
            replicas = list_bad_replicas(limit=bulk, thread=heart_beat['assign_thread'], total_threads=heart_beat['nr_threads'])

            for replica in replicas:
                scope, name, rse_id, rse = replica['scope'], replica['name'], replica['rse_id'], replica['rse']
                logger(logging.INFO, 'Working on %s:%s on %s' % (scope, name, rse))

                list_replicas = get_replicas_state(scope=scope, name=name)
                if ReplicaState.AVAILABLE not in list_replicas and ReplicaState.TEMPORARY_UNAVAILABLE not in list_replicas:
                    logger(logging.INFO, 'File %s:%s has no other available or temporary available replicas, it will be marked as lost' % (scope, name))
                    try:
                        update_rules_for_lost_replica(scope=scope, name=name, rse_id=rse_id, nowait=True)
                        monitor.record_counter(name='necromancer.badfiles.lostfile')
                    except DatabaseException as error:
                        logger(logging.WARNING, str(error))

                else:
                    rep = list_replicas.get(ReplicaState.AVAILABLE, [])
                    unavailable_rep = list_replicas.get(ReplicaState.TEMPORARY_UNAVAILABLE, [])
                    logger(logging.INFO, 'File %s:%s can be recovered. Available sources : %s + Unavailable sources : %s' % (scope, name, str(rep), str(unavailable_rep)))
                    try:
                        update_rules_for_bad_replica(scope=scope, name=name, rse_id=rse_id, nowait=True)
                        monitor.record_counter(name='necromancer.badfiles.recovering')
                    except DatabaseException as error:
                        logger(logging.WARNING, str(error))

            logger(logging.INFO, 'It took %s seconds to process %s replicas' % (str(time.time() - stime), str(len(replicas))))
        except Exception:
            exc_type, exc_value, exc_traceback = exc_info()
            logger(logging.CRITICAL, ''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

        if once:
            break
        else:
            now = time.time()
            if (now - update_history_time) > update_history_threshold:
                logger(logging.INFO, 'Last update of history table %s seconds ago. Running update.' % (now - update_history_time))
                bad_replicas = list_bad_replicas_history(limit=1000000,
                                                         thread=heart_beat['assign_thread'],
                                                         total_threads=heart_beat['nr_threads'])
                for rse_id in bad_replicas:
                    chunk_size = 1000
                    nchunk = int(ceil(len(bad_replicas[rse_id]) / chunk_size))
                    logger(logging.DEBUG, 'Update history for rse_id %s' % (rse_id))
                    cnt = 0
                    for chunk in chunks(bad_replicas[rse_id], chunk_size):
                        logger(logging.DEBUG, ' History for rse_id %s : chunk %i/%i' % (rse_id, cnt, nchunk))
                        cnt += 1
                        update_bad_replicas_history(chunk, rse_id)
                logger(logging.INFO, 'History table updated in %s seconds' % (time.time() - now))
                update_history_time = time.time()

            if len(replicas) == bulk:
                logger(logging.INFO, 'Processed maximum number of replicas according to the bulk size. Restart immediately next cycle')
            else:
                daemon_sleep(start_time=stime, sleep_time=sleep_time, graceful_stop=GRACEFUL_STOP)

    logger(logging.INFO, 'Graceful stop requested')
    heartbeat.die(executable, hostname, pid, hb_thread)
    logger(logging.INFO, 'Graceful stop done')


def run(threads=1, bulk=100, once=False, sleep_time=60):
    """
    Starts up the necromancer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.info('Will run only one iteration in a single threaded mode')
        necromancer(bulk=bulk, once=once)
    else:
        logging.info('starting necromancer threads')
        thread_list = [threading.Thread(target=necromancer, kwargs={'once': once,
                                                                    'thread': i,
                                                                    'bulk': bulk,
                                                                    'sleep_time': sleep_time}) for i in range(0, threads)]
        [t.start() for t in thread_list]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.is_alive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
