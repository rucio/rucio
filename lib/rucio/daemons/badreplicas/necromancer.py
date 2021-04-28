# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015
# - Wen Guan <wguan.icedew@gmail.com>, 2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from __future__ import division

import logging
import os
import socket
import threading
import time
from math import ceil
from sys import exc_info
from traceback import format_exception

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.exception import DatabaseException
from rucio.common.logging import setup_logging
from rucio.common.utils import chunks
from rucio.core import monitor, heartbeat
from rucio.core.replica import list_bad_replicas, get_replicas_state, list_bad_replicas_history, update_bad_replicas_history
from rucio.core.rule import update_rules_for_lost_replica, update_rules_for_bad_replica
from rucio.db.sqla.constants import ReplicaState

graceful_stop = threading.Event()


def necromancer(thread=0, bulk=5, once=False):
    """
    Creates a Necromancer Worker that gets a list of bad replicas for a given hash,
    identify lost DIDs and for non-lost ones, set the locks and rules for reevaluation.

    :param thread: Thread number at startup.
    :param bulk: The number of requests to process.
    :param once: Run only once.
    """

    sleep_time = 60
    update_history_threshold = 3600
    update_history_time = time.time()

    executable = 'necromancer'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)

    while not graceful_stop.is_set():

        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
        prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])

        stime = time.time()
        replicas = []
        try:
            replicas = list_bad_replicas(limit=bulk, thread=heart_beat['assign_thread'], total_threads=heart_beat['nr_threads'])

            for replica in replicas:
                scope, name, rse_id, rse = replica['scope'], replica['name'], replica['rse_id'], replica['rse']
                logging.info(prepend_str + 'Working on %s:%s on %s' % (scope, name, rse))

                list_replicas = get_replicas_state(scope=scope, name=name)
                if ReplicaState.AVAILABLE not in list_replicas and ReplicaState.TEMPORARY_UNAVAILABLE not in list_replicas:
                    logging.info(prepend_str + 'File %s:%s has no other available or temporary available replicas, it will be marked as lost' % (scope, name))
                    try:
                        update_rules_for_lost_replica(scope=scope, name=name, rse_id=rse_id, nowait=True)
                        monitor.record_counter(counters='necromancer.badfiles.lostfile', delta=1)
                    except DatabaseException as error:
                        logging.info(prepend_str + '%s' % (str(error)))

                else:
                    rep = list_replicas.get(ReplicaState.AVAILABLE, [])
                    unavailable_rep = list_replicas.get(ReplicaState.TEMPORARY_UNAVAILABLE, [])
                    logging.info(prepend_str + 'File %s:%s can be recovered. Available sources : %s + Unavailable sources : %s' % (scope, name, str(rep), str(unavailable_rep)))
                    try:
                        update_rules_for_bad_replica(scope=scope, name=name, rse_id=rse_id, nowait=True)
                        monitor.record_counter(counters='necromancer.badfiles.recovering', delta=1)
                    except DatabaseException as error:
                        logging.info(prepend_str + '%s' % (str(error)))

            logging.info(prepend_str + 'It took %s seconds to process %s replicas' % (str(time.time() - stime), str(len(replicas))))
        except Exception:
            exc_type, exc_value, exc_traceback = exc_info()
            logging.critical(prepend_str + ''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

        if once:
            break
        else:
            now = time.time()
            if (now - update_history_time) > update_history_threshold:
                logging.info(prepend_str + 'Last update of history table %s seconds ago. Running update.' % (now - update_history_time))
                bad_replicas = list_bad_replicas_history(limit=1000000,
                                                         thread=heart_beat['assign_thread'],
                                                         total_threads=heart_beat['nr_threads'])
                for rse_id in bad_replicas:
                    chunk_size = 1000
                    nchunk = int(ceil(len(bad_replicas[rse_id]) / chunk_size))
                    logging.debug(prepend_str + 'Update history for rse_id %s' % (rse_id))
                    cnt = 0
                    for chunk in chunks(bad_replicas[rse_id], chunk_size):
                        logging.debug(prepend_str + ' History for rse_id %s : chunk %i/%i' % (rse_id, cnt, nchunk))
                        cnt += 1
                        update_bad_replicas_history(chunk, rse_id)
                logging.info(prepend_str + 'History table updated in %s seconds' % (time.time() - now))
                update_history_time = time.time()

            tottime = time.time() - stime
            if len(replicas) == bulk:
                logging.info(prepend_str + 'Processed maximum number of replicas according to the bulk size. Restart immediately next cycle')
            elif tottime < sleep_time:
                logging.info(prepend_str + 'Will sleep for %s seconds' % (str(sleep_time - tottime)))
                time.sleep(sleep_time - tottime)
                continue

    logging.info(prepend_str + 'Graceful stop requested')
    heartbeat.die(executable, hostname, pid, hb_thread)
    logging.info(prepend_str + 'Graceful stop done')


def run(threads=1, bulk=100, once=False):
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
                                                                    'bulk': bulk}) for i in range(0, threads)]
        [t.start() for t in thread_list]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.is_alive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
