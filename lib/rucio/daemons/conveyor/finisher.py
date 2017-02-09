# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015-2016
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017


"""
Conveyor finisher is a daemon to update replicas and rules based on requests.
"""

import datetime
import logging
import os
import re
import socket
import sys
import threading
import time
import traceback

from sqlalchemy.exc import DatabaseError

from rucio.common.config import config_get
from rucio.common.utils import chunks
from rucio.common.exception import DatabaseException, ConfigNotFound
from rucio.core import request, heartbeat
from rucio.core.config import get
from rucio.core.monitor import record_timer, record_counter
from rucio.daemons.conveyor import common
from rucio.db.sqla.constants import RequestState, RequestType


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def finisher(once=False, process=0, total_processes=1, thread=0, total_threads=1, sleep_time=60, activities=None, bulk=100, db_bulk=1000):
    """
    Main loop to update the replicas and rules based on finished requests.
    """

    logging.info('finisher starting - process (%i/%i) thread (%i/%i) db_bulk(%i) bulk (%i)' % (process, total_processes,
                                                                                               thread, total_threads,
                                                                                               db_bulk, bulk))
    try:
        suspicious_patterns = []
        pattern = get(section='conveyor', option='suspicious_pattern', session=None)
        pattern = str(pattern)
        patterns = pattern.split(",")
        for pat in patterns:
            suspicious_patterns.append(re.compile(pat.strip()))
    except ConfigNotFound:
        suspicious_patterns = []
    logging.debug("Suspicious patterns: %s" % [pat.pattern for pat in suspicious_patterns])

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    # Make an initial heartbeat so that all finishers have the correct worker number on the next try
    hb = heartbeat.live(executable, hostname, pid, hb_thread)
    graceful_stop.wait(1)
    sleeping = False
    while not graceful_stop.is_set():

        try:
            hb = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'] + 1, hb['nr_threads'])

            if activities is None:
                activities = [None]

            if sleeping:
                logging.info(prepend_str + 'Nothing to do. will sleep %s seconds' % (sleep_time))
                time.sleep(sleep_time)

            sleeping = True
            for activity in activities:
                ts = time.time()
                reqs = request.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                        state=[RequestState.DONE, RequestState.FAILED, RequestState.LOST, RequestState.SUBMITTING,
                                               RequestState.SUBMISSION_FAILED, RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES],
                                        limit=db_bulk,
                                        older_than=datetime.datetime.utcnow(),
                                        activity=activity,
                                        process=process, total_processes=total_processes,
                                        thread=hb['assign_thread'], total_threads=hb['nr_threads'])
                record_timer('daemons.conveyor.finisher.000-get_next', (time.time() - ts) * 1000)
                if reqs:
                    logging.debug(prepend_str + 'Updating %i requests for activity %s' % (len(reqs), activity))
                    sleeping = False

                for chunk in chunks(reqs, bulk):
                    try:
                        ts = time.time()
                        common.handle_requests(chunk, suspicious_patterns)
                        record_timer('daemons.conveyor.finisher.handle_requests', (time.time() - ts) * 1000 / (len(chunk) if len(chunk) else 1))
                        record_counter('daemons.conveyor.finisher.handle_requests', len(chunk))
                    except:
                        logging.warn(str(traceback.format_exc()))
                if reqs:
                    logging.debug(prepend_str + 'Finish to update %s finished requests for activity %s' % (len(reqs), activity))

        except (DatabaseException, DatabaseError) as error:
            if isinstance(error.args[0], tuple) and (re.match('.*ORA-00054.*', error.args[0][0]) or ('ERROR 1205 (HY000)' in error.args[0][0])):
                logging.warn(prepend_str + 'Lock detected when handling request - skipping: %s' % (str(error)))
            else:
                logging.error(prepend_str + '%s' % (traceback.format_exc()))
            sleeping = False
        except:
            sleeping = False
            logging.critical(prepend_str + '%s' % (traceback.format_exc()))

        if once:
            return

    logging.info(prepend_str + 'Graceful stop requests')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info(prepend_str + 'Graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1, sleep_time=60, activities=None, bulk=100, db_bulk=1000):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one finisher iteration only')
        finisher(once=once, activities=activities, bulk=bulk, db_bulk=db_bulk)

    else:

        logging.info('starting finisher threads')
        threads = [threading.Thread(target=finisher, kwargs={'process': process,
                                                             'total_processes': total_processes,
                                                             'thread': i,
                                                             'total_threads': total_threads,
                                                             'sleep_time': sleep_time,
                                                             'activities': activities,
                                                             'db_bulk': db_bulk,
                                                             'bulk': bulk}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            threads = [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
