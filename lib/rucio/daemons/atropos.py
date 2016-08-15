'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2016
'''

import datetime
import logging
import os
import socket
import threading
import time

from sys import exc_info, stdout, argv
from traceback import format_exception

from rucio.common.config import config_get
from rucio.core import heartbeat
from rucio.core.lock import get_dataset_locks
from rucio.core.rule import get_rules_behond_eol

from rucio.db.sqla.session import get_session

logging.getLogger("atropos").setLevel(logging.CRITICAL)

logging.basicConfig(stream=stdout, level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def atropos(thread, bulk, date_check, dry_run, once):
    """
    Creates an Atropos Worker that gets a list of rules which have an eol_at expired and delete them.

    :param thread: Thread number at startup.
    :param bulk: The number of requests to process.
    :param once: Run only once.
    """

    sleep_time = 60

    executable = ' '.join(argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    now = datetime.datetime.now()
    hb = heartbeat.live(executable, hostname, pid, hb_thread)
    summary = {}
    if not dry_run and date_check > now:
        logging.error('Thread [%i/%i] : Atropos cannot run in non-dry-run mode for date in the future' % (hb['assign_thread'], hb['nr_threads']))
    else:
        session = get_session()
        while not graceful_stop.is_set():

            hb = heartbeat.live(executable, hostname, pid, hb_thread)

            stime = time.time()
            try:
                rules = get_rules_behond_eol(date_check, thread, hb['nr_threads'] - 1, session=session)
                for rule in rules:
                    no_locks = True
                    for lock in get_dataset_locks(rule.scope, rule.name, session=session):
                        if lock['rule_id'] == rule[4]:
                            no_locks = False
                            if lock['rse'] not in summary:
                                summary[lock['rse']] = {'length': 0, 'bytes': 0}
                            summary[lock['rse']]['length'], summary[lock['rse']]['bytes'] = lock['length'], lock['bytes']
                    if no_locks:
                        logging.warning('Thread [%i/%i] : Cannot find a lock for rule %s on DID %s:%s' % (hb['assign_thread'],
                                                                                                          hb['nr_threads'],
                                                                                                          rule.id,
                                                                                                          rule.scope,
                                                                                                          rule.name))
                if not dry_run:
                    raise NotImplementedError
            except NotImplementedError:
                logging.error('Thread [%i/%i] : Non dry run is not implemented yet' % (hb['assign_thread'],
                                                                                       hb['nr_threads']))
            except Exception:
                exc_type, exc_value, exc_traceback = exc_info()
                logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

            logging.info('Thread [%i/%i] : Summary %s' % (hb['assign_thread'], hb['nr_threads'], str(summary)))
            if once:
                break
            else:
                tottime = time.time() - stime
                if tottime < sleep_time:
                    logging.info('Thread [%i/%i] : Will sleep for %s seconds' % (hb['assign_thread'],
                                                                                 hb['nr_threads'],
                                                                                 str(sleep_time - tottime)))
                    time.sleep(sleep_time - tottime)
                    continue

        logging.info('Thread [%i/%i] : Graceful stop requested' % (hb['assign_thread'], hb['nr_threads']))
        heartbeat.die(executable, hostname, pid, hb_thread)
        logging.info('Thread [%i/%i] : Graceful stop done' % (hb['assign_thread'], hb['nr_threads']))


def run(threads=1, bulk=100, date_check=None, dry_run=None, once=False):
    """
    Starts up the atropos threads.
    """
    if not date_check:
        date_check = datetime.datetime.now()
    else:
        date_check = datetime.datetime.strptime(date_check, '%Y-%m-%d')
    if once:
        logging.info('Will run only one iteration in a single threaded mode')
    logging.info('starting atropos threads')
    thread_list = [threading.Thread(target=atropos, kwargs={'once': once,
                                                            'thread': i,
                                                            'date_check': date_check,
                                                            'dry_run': dry_run,
                                                            'bulk': bulk}) for i in xrange(0, threads)]
    [t.start() for t in thread_list]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while len(thread_list) > 0:
        thread_list = [t.join(timeout=3.14) for t in thread_list if t and t.isAlive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
