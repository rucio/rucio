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

'''
Undertaker is a daemon to manage expired did.
'''

import functools
import logging
import threading
import traceback
from copy import deepcopy
from datetime import datetime, timedelta
from random import randint
from re import match
from typing import Tuple, Dict

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.exception import DatabaseException, UnsupportedOperation, RuleNotFound
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.common.utils import chunks
from rucio.core.did import list_expired_dids, delete_dids
from rucio.core.monitor import record_counter
from rucio.daemons.common import run_daemon, HeartbeatHandler

logging.getLogger("requests").setLevel(logging.CRITICAL)

graceful_stop = threading.Event()


def undertaker(once: bool = False, sleep_time: int = 60, chunk_size: int = 10):
    """
    Main loop to select and delete dids.
    """
    executable = 'undertaker'
    paused_dids = {}  # {(scope, name): datetime}
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        logger_prefix=executable,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            paused_dids=paused_dids,
            chunk_size=chunk_size,
        )
    )


def run_once(paused_dids: Dict[Tuple, datetime], chunk_size: int, heartbeat_handler: HeartbeatHandler, **_kwargs):
    worker_number, total_workers, logger = heartbeat_handler.live()

    try:
        # Refresh paused dids
        iter_paused_dids = deepcopy(paused_dids)
        for key in iter_paused_dids:
            if datetime.utcnow() > paused_dids[key]:
                del paused_dids[key]

        dids = list_expired_dids(worker_number=worker_number, total_workers=total_workers, limit=10000)

        dids = [did for did in dids if (did['scope'], did['name']) not in paused_dids]

        if not dids:
            logger(logging.INFO, 'did not get any work')
            return

        for chunk in chunks(dids, chunk_size):
            _, _, logger = heartbeat_handler.live()
            try:
                logger(logging.INFO, 'Receive %s dids to delete', len(chunk))
                delete_dids(dids=chunk, account=InternalAccount('root', vo='def'), expire_rules=True)
                logger(logging.INFO, 'Delete %s dids', len(chunk))
                record_counter(name='undertaker.delete_dids', delta=len(chunk))
            except RuleNotFound as error:
                logger(logging.ERROR, error)
            except (DatabaseException, DatabaseError, UnsupportedOperation) as e:
                if match('.*ORA-00054.*', str(e.args[0])) or match('.*55P03.*', str(e.args[0])) or match('.*3572.*', str(e.args[0])):
                    for did in chunk:
                        paused_dids[(did['scope'], did['name'])] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))
                    record_counter('undertaker.delete_dids.exceptions.{exception}', labels={'exception': 'LocksDetected'})
                    logger(logging.WARNING, 'Locks detected for chunk')
                else:
                    logger(logging.ERROR, 'Got database error %s.', str(e))
    except:
        logging.critical(traceback.format_exc())


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once: bool = False, total_workers: int = 1, chunk_size: int = 10, sleep_time: int = 60):
    """
    Starts up the undertaker threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        undertaker(once)
    else:
        logging.info('main: starting threads')
        threads = [threading.Thread(target=undertaker, kwargs={'once': once, 'chunk_size': chunk_size,
                                                               'sleep_time': sleep_time}) for i in range(0, total_workers)]
        [t.start() for t in threads]
        logging.info('main: waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
