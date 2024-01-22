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

import functools
import logging
import re
import threading
import time
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from dogpile.cache.api import NO_VALUE
from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get_int
from rucio.common.exception import DatabaseException
from rucio.common.logging import setup_logging
from rucio.core.monitor import MetricManager
from rucio.core.replica import list_bad_replicas, get_replicas_state, get_bad_replicas_backlog
from rucio.core.rule import (update_rules_for_lost_replica, update_rules_for_bad_replica,
                             get_evaluation_backlog)
from rucio.daemons.common import run_daemon
from rucio.db.sqla.constants import MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED, ORACLE_DEADLOCK_DETECTED_REGEX, ORACLE_RESOURCE_BUSY_REGEX, ReplicaState

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

    from rucio.daemons.common import HeartbeatHandler

graceful_stop = threading.Event()
METRICS = MetricManager(module=__name__)
REGION = make_region_memcached(expiration_time=config_get_int('necromancer', 'cache_time', False, 600))
DAEMON_NAME = 'necromancer'


def necromancer(bulk: int, once: bool = False, sleep_time: int = 60) -> None:
    """
    Creates a Necromancer Worker that gets a list of bad replicas for a given hash,
    identify lost DIDs and for non-lost ones, set the locks and rules for reevaluation.

    :param bulk: The number of requests to process.
    :param once: Run only once.
    :param sleep_time: Thread sleep time after each chunk of work.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=10,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            bulk=bulk,
        ),
    )


def run_once(heartbeat_handler: "HeartbeatHandler", bulk: int, **_kwargs) -> bool:
    worker_number, total_workers, logger = heartbeat_handler.live()
    must_sleep = True

    # Check if there is a Judge Evaluator backlog
    max_evaluator_backlog_count = config_get_int('necromancer', 'max_evaluator_backlog_count', default=0, raise_exception=False)
    max_evaluator_backlog_duration = config_get_int('necromancer', 'max_evaluator_backlog_duration', default=0, raise_exception=False)
    backlog_refresh_time = config_get_int('necromancer', 'backlog_refresh_time', default=60, raise_exception=False)
    if max_evaluator_backlog_count or max_evaluator_backlog_duration:
        evaluator_backlog_count, evaluator_backlog_duration = get_evaluation_backlog(expiration_time=backlog_refresh_time)
        if max_evaluator_backlog_count and \
           evaluator_backlog_count and \
           max_evaluator_backlog_duration and \
           evaluator_backlog_duration and \
           evaluator_backlog_count > max_evaluator_backlog_count and \
           evaluator_backlog_duration < datetime.utcnow() - timedelta(minutes=max_evaluator_backlog_duration):
            logger(logging.ERROR, 'Necromancer: Judge evaluator backlog count and duration hit, stopping operation')
            return must_sleep
        elif max_evaluator_backlog_count and evaluator_backlog_count and evaluator_backlog_count > max_evaluator_backlog_count:
            logger(logging.ERROR, 'Necromancer: Judge evaluator backlog count hit, stopping operation')
            return must_sleep
        elif max_evaluator_backlog_duration and evaluator_backlog_duration and evaluator_backlog_duration < datetime.utcnow() - timedelta(minutes=max_evaluator_backlog_duration):
            logger(logging.ERROR, 'Necromancer: Judge evaluator backlog duration hit, stopping operation')
            return must_sleep

    # Check how many bad replicas are queued
    max_bad_replicas_backlog_count = config_get_int('necromancer', 'max_bad_replicas_backlog_count', default=0, raise_exception=False)
    bad_replicas_backlog = REGION.get('bad_replicas_backlog')
    if bad_replicas_backlog is NO_VALUE:
        bad_replicas_backlog = get_bad_replicas_backlog()
        REGION.set('bad_replicas_backlog', bad_replicas_backlog)
    tot_bad_files = sum([bad_replicas_backlog[key] for key in bad_replicas_backlog])
    list_of_rses = list()
    # If too many replica, call list_bad_replicas with a list of RSEs
    if max_bad_replicas_backlog_count and tot_bad_files > max_bad_replicas_backlog_count and len(bad_replicas_backlog) > 1:
        logger(logging.INFO, 'Backlog of bads replica too big. Apply some sharing between different RSEs')
        rses = list()
        cnt = 0
        for key in sorted(bad_replicas_backlog, key=bad_replicas_backlog.get, reverse=True):
            rses.append({'id': key})
            cnt += bad_replicas_backlog[key]
            if cnt >= bulk:
                list_of_rses.append(rses)
                rses = list()
                cnt = 0
    else:
        list_of_rses.append(None)

    tot_processed = 0
    if tot_bad_files == 0:
        logger(logging.INFO, 'No bad replicas to process.')
    else:
        ttime = time.time()
        replicas = []
        for rses in list_of_rses:

            worker_number, total_workers, logger = heartbeat_handler.live()
            replicas = list_bad_replicas(limit=bulk, thread=worker_number, total_threads=total_workers, rses=rses)
            for replica in replicas:
                scope, name, rse_id, rse = replica['scope'], replica['name'], replica['rse_id'], replica['rse']
                logger(logging.INFO, 'Working on %s:%s on %s' % (scope, name, rse))

                list_replicas = get_replicas_state(scope=scope, name=name)
                if ReplicaState.AVAILABLE not in list_replicas and ReplicaState.TEMPORARY_UNAVAILABLE not in list_replicas:
                    logger(logging.INFO, 'File %s:%s has no other available or temporary available replicas, it will be marked as lost' % (scope, name))
                    try:
                        update_rules_for_lost_replica(scope=scope, name=name, rse_id=rse_id, nowait=True)
                        METRICS.counter(name='badfiles.lostfile').inc()
                    except (DatabaseException, DatabaseError) as error:
                        if re.match(ORACLE_RESOURCE_BUSY_REGEX, error.args[0]) or re.match(ORACLE_DEADLOCK_DETECTED_REGEX, error.args[0]) or MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED in error.args[0]:
                            logger(logging.WARNING, 'Lock detected when handling request - skipping: %s', str(error))
                        else:
                            logger(logging.ERROR, str(error))

                else:
                    rep = list_replicas.get(ReplicaState.AVAILABLE, [])
                    unavailable_rep = list_replicas.get(ReplicaState.TEMPORARY_UNAVAILABLE, [])
                    logger(logging.INFO, 'File %s:%s can be recovered. Available sources : %s + Unavailable sources : %s' % (scope, name, str(rep), str(unavailable_rep)))
                    try:
                        update_rules_for_bad_replica(scope=scope, name=name, rse_id=rse_id, nowait=True)
                        METRICS.counter(name='badfiles.recovering').inc()
                    except (DatabaseException, DatabaseError) as error:
                        if re.match(ORACLE_RESOURCE_BUSY_REGEX, error.args[0]) or re.match(ORACLE_DEADLOCK_DETECTED_REGEX, error.args[0]) or MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED in error.args[0]:
                            logger(logging.WARNING, 'Lock detected when handling request - skipping: %s', str(error))
                        else:
                            logger(logging.ERROR, str(error))

            tot_processed += len(replicas)
            logger(logging.INFO, 'It took %s seconds to process %s replicas' % (str(time.time() - ttime), str(len(replicas))))

    if tot_processed == 0 or tot_bad_files == 0:
        return must_sleep
    must_sleep = False
    return must_sleep


def run(threads: int = 1, bulk: int = 100, once: bool = False, sleep_time: int = 60) -> None:
    """
    Starts up the necromancer threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.info('Will run only one iteration in a single threaded mode')
        necromancer(bulk=bulk, once=once)
    else:
        logging.info('starting necromancer threads')
        thread_list = [threading.Thread(target=necromancer, kwargs={'once': once,
                                                                    'bulk': bulk,
                                                                    'sleep_time': sleep_time}) for _ in range(0, threads)]
        [t.start() for t in thread_list]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.is_alive()]


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """
    graceful_stop.set()
