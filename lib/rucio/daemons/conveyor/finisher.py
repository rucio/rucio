# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015

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

from collections import defaultdict
from sqlalchemy.exc import DatabaseError

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.core import request, heartbeat
from rucio.core.monitor import record_timer, record_counter
from rucio.daemons.conveyor import common
from rucio.db.constants import RequestState, RequestType


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def finisher(once=False, process=0, total_processes=1, thread=0, total_threads=1, sleep_time=60, activities=None, bulk=1000):
    """
    Main loop to update the replicas and rules based on finished requests.
    """

    logging.info('finisher starting - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                   thread, total_threads,
                                                                                   bulk))
    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb = heartbeat.live(executable, hostname, pid, hb_thread)

    logging.info('finisher started - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                  hb['assign_thread'], hb['nr_threads'],
                                                                                  bulk))

    activity_next_exe_time = defaultdict(time.time)
    sleeping = False
    while not graceful_stop.is_set():

        try:
            if not sleeping:
                sleeping = True
                hb = heartbeat.live(executable, hostname, pid, hb_thread)
                logging.info('finisher - thread (%i/%i)' % (hb['assign_thread'], hb['nr_threads']))

            if activities is None:
                activities = [None]
            for activity in activities:
                if activity_next_exe_time[activity] > time.time():
                    time.sleep(1)
                    continue
                sleeping = False

                ts = time.time()
                logging.debug('%i:%i - start to update %s finished requests for activity %s' % (process, hb['assign_thread'], bulk, activity))
                reqs = request.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                        state=[RequestState.DONE, RequestState.FAILED, RequestState.LOST, RequestState.SUBMITTING],
                                        limit=bulk,
                                        older_than=datetime.datetime.utcnow(),
                                        activity=activity,
                                        process=process, total_processes=total_processes,
                                        thread=hb['assign_thread'], total_threads=hb['nr_threads'])
                record_timer('daemons.conveyor.finisher.000-get_next', (time.time()-ts)*1000)

                if reqs:
                    logging.debug('%i:%i - updating %i requests for activity %s' % (process, hb['assign_thread'], len(reqs), activity))

                ts = time.time()
                common.handle_requests(reqs)
                record_timer('daemons.conveyor.finisher.handle_requests', (time.time()-ts)*1000/(len(reqs) if len(reqs) else 1))
                record_counter('daemons.conveyor.finisher.handle_requests', len(reqs))

                if len(reqs) < bulk / 2:
                    logging.info("%i:%i - only %s transfers for activity %s, which is less than half of the bulk %s, will sleep %s seconds" % (process, hb['assign_thread'], len(reqs), activity, bulk, sleep_time))
                    if activity_next_exe_time[activity] < time.time():
                        activity_next_exe_time[activity] = time.time() + sleep_time

        except (DatabaseException, DatabaseError), e:
            if isinstance(e.args[0], tuple) and (re.match('.*ORA-00054.*', e.args[0][0]) or ('ERROR 1205 (HY000)' in e.args[0][0])):
                logging.warn("%i:%i - Lock detected when handling request - skipping: %s" % (process, hb['assign_thread'], str(e)))
            else:
                logging.error("%i:%i - %s" % (process, hb['assign_thread'], traceback.format_exc()))
        except:
            logging.critical("%i:%i - %s" % (process, hb['assign_thread'], traceback.format_exc()))

        if once:
            return

    logging.debug('%i:%i - graceful stop requests' % (process, hb['assign_thread']))

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.debug('%i:%i - graceful stop done' % (process, hb['assign_thread']))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1, sleep_time=60, activities=None, bulk=1000):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one finisher iteration only')
        finisher(once=once, activities=activities, bulk=bulk)

    else:

        logging.info('starting finisher threads')
        threads = [threading.Thread(target=finisher, kwargs={'process': process,
                                                             'total_processes': total_processes,
                                                             'thread': i,
                                                             'total_threads': total_threads,
                                                             'sleep_time': sleep_time,
                                                             'activities': activities,
                                                             'bulk': bulk}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
