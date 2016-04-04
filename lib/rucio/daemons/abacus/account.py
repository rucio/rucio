# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

"""
Abacus-Account is a daemon to update Account counters.
"""

import logging
import sys
import threading
import time
import traceback

from rucio.common.config import config_get
from rucio.core.account_counter import get_updated_account_counters, update_account_counter

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def account_update(once=False, process=0, total_processes=1, thread=0, threads_per_process=1):
    """
    Main loop to check and update the Account Counters.
    """

    logging.info('account_update: starting')

    logging.info('account_update: started')

    while not graceful_stop.is_set():
        try:
            # Select a bunch of rses for to update for this worker
            start = time.time()  # NOQA
            account_rse_ids = get_updated_account_counters(total_workers=total_processes * threads_per_process - 1,
                                                           worker_number=process * threads_per_process + thread)
            logging.debug('Index query time %f size=%d' % (time.time() - start, len(account_rse_ids)))

            # If the list is empty, sent the worker to sleep
            if not account_rse_ids and not once:
                logging.info('account_update[%s/%s] did not get any work' % (process * threads_per_process + thread, total_processes * threads_per_process - 1))
                time.sleep(10)
            else:
                for account_rse_id in account_rse_ids:
                    if graceful_stop.is_set():
                        break
                    start_time = time.time()
                    update_account_counter(account=account_rse_id[0], rse_id=account_rse_id[1])
                    logging.debug('account_update[%s/%s]: update of account-rse counter "%s-%s" took %f' % (process * threads_per_process + thread, total_processes * threads_per_process - 1, account_rse_id[0], account_rse_id[1], time.time() - start_time))
        except Exception:
            logging.error(traceback.format_exc())

        if once:
            break

    logging.info('account_update: graceful stop requested')

    logging.info('account_update: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, threads_per_process=11):
    """
    Starts up the Abacus-Account threads.
    """
    if once:
        logging.info('main: executing one iteration only')
        account_update(once)
    else:
        logging.info('main: starting threads')
        threads = [threading.Thread(target=account_update, kwargs={'process': process, 'total_processes': total_processes, 'once': once, 'thread': i, 'threads_per_process': threads_per_process}) for i in xrange(0, threads_per_process)]
        [t.start() for t in threads]
        logging.info('main: waiting for interrupts')
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
