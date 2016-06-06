# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

'''
Undertaker is a daemon to manage expired did.
'''

import logging
import os
import sys
import socket
import threading
import time
import traceback


from rucio.common.config import config_get
from rucio.common.exception import DatabaseException, RuleNotFound
from rucio.common.utils import chunks
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.did import list_expired_dids, delete_dids

logging.getLogger("requests").setLevel(getattr(logging, config_get('common', 'loglevel').upper()))

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()


def undertaker(worker_number=1, total_workers=1, chunk_size=5, once=False):
    """
    Main loop to select and delete dids.
    """
    logging.info('Undertaker(%s): starting', worker_number)
    logging.info('Undertaker(%s): started', worker_number)
    hostname = socket.gethostname()
    pid = os.getpid()
    thread = threading.current_thread()
    sanity_check(executable='rucio-undertaker', hostname=hostname)
    while not GRACEFUL_STOP.is_set():
        try:
            heartbeat = live(executable='rucio-undertaker', hostname=hostname, pid=pid, thread=thread, older_than=6000)
            logging.info('Undertaker({0[worker_number]}/{0[total_workers]}): Live gives {0[heartbeat]}'.format(locals()))

            dids = list_expired_dids(worker_number=heartbeat['assign_thread'] + 1, total_workers=heartbeat['nr_threads'], limit=10000)
            if not dids and not once:
                logging.info('Undertaker(%s): Nothing to do. sleep 60.', worker_number)
                time.sleep(60)
                continue

            for chunk in chunks(dids, chunk_size):
                try:
                    logging.info('Undertaker(%s): Receive %s dids to delete', worker_number, len(chunk))
                    delete_dids(dids=chunk, account='root')
                    logging.info('Undertaker(%s): Delete %s dids', worker_number, len(chunk))
                    record_counter(counters='undertaker.delete_dids', delta=len(chunk))
                except RuleNotFound, error:
                    logging.error(error)
                except DatabaseException, error:
                    logging.error('Undertaker(%s): Got database error %s.', worker_number, str(error))
        except:
            logging.critical(traceback.format_exc())
            time.sleep(1)

        if once:
            break

    die(executable='rucio-undertaker', hostname=hostname, pid=pid, thread=thread)
    logging.info('Undertaker(%s): graceful stop requested', worker_number)
    logging.info('Undertaker(%s): graceful stop done', worker_number)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(once=False, total_workers=1, chunk_size=10):
    """
    Starts up the undertaker threads.
    """
    logging.info('main: starting threads')
    threads = [threading.Thread(target=undertaker, kwargs={'worker_number': i, 'total_workers': total_workers, 'once': once, 'chunk_size': chunk_size}) for i in xrange(1, total_workers + 1)]
    [t.start() for t in threads]
    logging.info('main: waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
