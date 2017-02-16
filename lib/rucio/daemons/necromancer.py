'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2017
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
'''

import logging
import os
import socket
import threading
import time

from sys import exc_info, stdout, argv
from traceback import format_exception

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.core import monitor, heartbeat
from rucio.core.replica import list_bad_replicas, list_replicas, list_bad_replicas_history, update_bad_replicas_history
from rucio.core.rule import update_rules_for_lost_replica, update_rules_for_bad_replica


logging.basicConfig(stream=stdout, level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

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

    executable = ' '.join(argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)

    while not graceful_stop.is_set():

        hb = heartbeat.live(executable, hostname, pid, hb_thread)
        prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'] + 1, hb['nr_threads'])

        stime = time.time()
        try:
            replicas = list_bad_replicas(limit=bulk, thread=hb['assign_thread'], total_threads=hb['nr_threads'])

            for replica in replicas:
                scope, name, rse_id, rse = replica['scope'], replica['name'], replica['rse_id'], replica['rse']
                logging.info(prepend_str + 'Working on %s:%s on %s' % (scope, name, rse))

                rep = [r for r in list_replicas([{'scope': scope, 'name': name}, ])]
                if (not rep[0]['rses']) or (rep[0]['rses'].keys() == [rse]):
                    logging.info(prepend_str + 'File %s:%s has no other replicas, it will be marked as lost' % (scope, name))
                    try:
                        update_rules_for_lost_replica(scope=scope, name=name, rse_id=rse_id, nowait=True)
                        monitor.record_counter(counters='necromancer.badfiles.lostfile', delta=1)
                    except DatabaseException, error:
                        logging.info(prepend_str + '%s' % (str(error)))

                else:
                    logging.info(prepend_str + 'File %s:%s can be recovered. Available sources : %s' % (scope, name, str(rep[0]['rses'])))
                    try:
                        update_rules_for_bad_replica(scope=scope, name=name, rse_id=rse_id, nowait=True)
                        monitor.record_counter(counters='necromancer.badfiles.recovering', delta=1)
                    except DatabaseException, error:
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
                bad_replicas = list_bad_replicas_history(limit=10000000,
                                                         thread=hb['assign_thread'],
                                                         total_threads=hb['nr_threads'])
                for rse_id in bad_replicas:
                    update_bad_replicas_history(bad_replicas[rse_id], rse_id)
                logging.info(prepend_str + 'History table updated in %s seconds' % (time.time() - now))
                update_history_time = time.time()

            tottime = time.time() - stime
            if tottime < sleep_time:
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

    if once:
        logging.info('Will run only one iteration in a single threaded mode')
        necromancer(bulk=bulk, once=once)
    else:
        logging.info('starting necromancer threads')
        thread_list = [threading.Thread(target=necromancer, kwargs={'once': once,
                                                                    'thread': i,
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
