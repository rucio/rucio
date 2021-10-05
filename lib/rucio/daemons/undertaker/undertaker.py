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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021

'''
Undertaker is a daemon to manage expired did.
'''

import logging
import os
import socket
import threading
import time
import traceback
from copy import deepcopy
from datetime import datetime, timedelta
from random import randint
from re import match

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.exception import DatabaseException, UnsupportedOperation, RuleNotFound
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.common.utils import chunks, daemon_sleep
from rucio.core.did import list_expired_dids, delete_dids
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter

logging.getLogger("requests").setLevel(logging.CRITICAL)

GRACEFUL_STOP = threading.Event()


def undertaker(worker_number=1, total_workers=1, chunk_size=5, once=False, sleep_time=60):
    """
    Main loop to select and delete dids.
    """
    logging.info('Undertaker(%s): starting', worker_number)
    logging.info('Undertaker(%s): started', worker_number)
    executable = 'undertaker'
    hostname = socket.gethostname()
    pid = os.getpid()
    thread = threading.current_thread()
    sanity_check(executable=executable, hostname=hostname)

    paused_dids = {}  # {(scope, name): datetime}

    while not GRACEFUL_STOP.is_set():
        try:
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=thread, older_than=6000)
            logging.info('Undertaker({0[worker_number]}/{0[total_workers]}): Live gives {0[heartbeat]}'.format(locals()))

            start = time.time()

            # Refresh paused dids
            iter_paused_dids = deepcopy(paused_dids)
            for key in iter_paused_dids:
                if datetime.utcnow() > paused_dids[key]:
                    del paused_dids[key]

            dids = list_expired_dids(worker_number=heartbeat['assign_thread'], total_workers=heartbeat['nr_threads'], limit=10000)

            dids = [did for did in dids if (did['scope'], did['name']) not in paused_dids]

            if not dids and not once:
                logging.info('Undertaker(%s): Nothing to do. sleep 60.', worker_number)
                daemon_sleep(start_time=start, sleep_time=sleep_time, graceful_stop=GRACEFUL_STOP)
                continue

            for chunk in chunks(dids, chunk_size):
                try:
                    logging.info('Undertaker(%s): Receive %s dids to delete', worker_number, len(chunk))
                    delete_dids(dids=chunk, account=InternalAccount('root', vo='def'), expire_rules=True)
                    logging.info('Undertaker(%s): Delete %s dids', worker_number, len(chunk))
                    record_counter(name='undertaker.delete_dids', delta=len(chunk))
                except RuleNotFound as error:
                    logging.error(error)
                except (DatabaseException, DatabaseError, UnsupportedOperation) as e:
                    if match('.*ORA-00054.*', str(e.args[0])) or match('.*55P03.*', str(e.args[0])) or match('.*3572.*', str(e.args[0])):
                        for did in chunk:
                            paused_dids[(did['scope'], did['name'])] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))
                        record_counter('undertaker.delete_dids.exceptions.{exception}', labels={'exception': 'LocksDetected'})
                        logging.warning('undertaker[%s/%s]: Locks detected for chunk', heartbeat['assign_thread'], heartbeat['nr_threads'])
                    else:
                        logging.error('Undertaker(%s): Got database error %s.', worker_number, str(e))
        except:
            logging.critical(traceback.format_exc())
            time.sleep(1)

        if once:
            break

    die(executable=executable, hostname=hostname, pid=pid, thread=thread)
    logging.info('Undertaker(%s): graceful stop requested', worker_number)
    logging.info('Undertaker(%s): graceful stop done', worker_number)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(once=False, total_workers=1, chunk_size=10, sleep_time=60):
    """
    Starts up the undertaker threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('main: starting threads')
    threads = [threading.Thread(target=undertaker, kwargs={'worker_number': i, 'total_workers': total_workers,
                                                           'once': once, 'chunk_size': chunk_size,
                                                           'sleep_time': sleep_time}) for i in range(0, total_workers)]
    [t.start() for t in threads]
    logging.info('main: waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
