# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2015


import logging
import threading
import time

from sys import exc_info, stdout
from traceback import format_exception

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.core import monitor
from rucio.core.replica import list_bad_replicas, list_replicas
from rucio.core.rule import update_rules_for_lost_replica, update_rules_for_bad_replica


logging.getLogger("necromancer").setLevel(logging.CRITICAL)

logging.basicConfig(stream=stdout, level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def necromancer(worker_number=1, total_workers=1, chunk_size=5, once=False):
    """
    Creates a Necromancer Worker that gets a list of bad replicas for a given hash, identify lost DIDs and for non-lost ones, set the locks and rules for reevaluation.

    param worker_number: The number of the worker (thread).
    param total_number: The total number of workers (threads).
    chunk_size: The chunk of the size to process.
    once: To run only once
    """
    sleep_time = 60
    while not graceful_stop.is_set():
        stime = time.time()
        try:
            replicas = list_bad_replicas(limit=chunk_size, worker_number=worker_number, total_workers=total_workers)
            for replica in replicas:
                scope, name, rse_id, rse = replica['scope'], replica['name'], replica['rse_id'], replica['rse']
                logging.info('Thread [%i/%i] : Working on %s:%s on %s' % (worker_number, total_workers, scope, name, rse))
                rep = [r for r in list_replicas([{'scope': scope, 'name': name}, ])]
                if (not rep[0]['rses']) or (rep[0]['rses'].keys() == [rse]):
                    logging.info('Thread [%i/%i] : File %s:%s has no other replicas, it will be marked as lost' % (worker_number, total_workers, scope, name))
                    try:
                        update_rules_for_lost_replica(scope=scope, name=name, rse_id=rse_id)
                        monitor.record_counter(counters='necromancer.badfiles.lostfile',  delta=1)
                    except DatabaseException, e:
                        logging.info('Thread [%i/%i] : %s' % (worker_number, total_workers, str(e)))
                else:
                    logging.info('Thread [%i/%i] : File %s:%s can be recovered. Available sources : %s' % (worker_number, total_workers, scope, name, str(rep[0]['rses'])))
                    try:
                        update_rules_for_bad_replica(scope=scope, name=name, rse_id=rse_id)
                        monitor.record_counter(counters='necromancer.badfiles.recovering',  delta=1)
                    except DatabaseException, e:
                        logging.info('Thread [%i/%i] : %s' % (worker_number, total_workers, str(e)))
            logging.info('Thread [%i/%i] : It took %s seconds to process %s replicas' % (worker_number, total_workers, str(time.time() - stime), str(len(replicas))))
        except:
            exc_type, exc_value, exc_traceback = exc_info()
            logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())
        if once:
            break
        else:
            tottime = time.time() - stime
            if tottime < sleep_time:
                logging.info('Thread [%i/%i] : Will sleep for %s seconds' % (worker_number, total_workers, str(sleep_time - tottime)))
                time.sleep(sleep_time - tottime)
                continue


def run(total_workers=1, chunk_size=100, once=False):
    """
    Starts up the necromancer threads.
    """

    threads = list()
    for worker_number in xrange(0, total_workers):
        kwargs = {'worker_number': worker_number + 1,
                  'total_workers': total_workers,
                  'once': once,
                  'chunk_size': chunk_size}
        threads.append(threading.Thread(target=necromancer, kwargs=kwargs))
    [t.start() for t in threads]
    while threads[0].is_alive():
        logging.info('Still %i active threads' % len(threads))
        [t.join(timeout=3.14) for t in threads]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
