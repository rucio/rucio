# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014-2016

"""
Conveyor is a daemon to manage file transfers.
"""

import datetime
import json
import logging
import os
import socket
import sys
import threading
import time
import traceback

from collections import defaultdict
from ConfigParser import NoOptionError
from threadpool import ThreadPool, makeRequests

from rucio.common.config import config_get
from rucio.common.utils import chunks
from rucio.core import request, heartbeat
from rucio.core.monitor import record_timer
from rucio.daemons.conveyor import common
from rucio.db.sqla.constants import RequestState, RequestType


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()

# http://bugs.python.org/issue7980
datetime.datetime.strptime('', '')


def poller(once=False,
           process=0, total_processes=1, thread=0, total_threads=1, activities=None, sleep_time=60,
           fts_bulk=100, db_bulk=1000, older_than=60, activity_shares=None):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    try:
        timeout = config_get('conveyor', 'poll_timeout')
        timeout = float(timeout)
    except NoOptionError:
        timeout = None

    logging.info('poller starting - process (%i/%i) thread (%i/%i) bulk (%i) timeout (%s)' % (process, total_processes,
                                                                                              thread, total_threads,
                                                                                              db_bulk, timeout))

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb = heartbeat.live(executable, hostname, pid, hb_thread)

    logging.info('poller started - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                hb['assign_thread'], hb['nr_threads'],
                                                                                db_bulk))

    activity_next_exe_time = defaultdict(time.time)
    threadPool = ThreadPool(total_threads)
    sleeping = False

    while not graceful_stop.is_set():

        try:
            hb = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            logging.debug('poller - thread (%i/%i)' % (hb['assign_thread'], hb['nr_threads']))

            if not sleeping:
                sleeping = True

            if activities is None:
                activities = [None]
            for activity in activities:
                if activity_next_exe_time[activity] > time.time():
                    time.sleep(1)
                    continue
                sleeping = False

                ts = time.time()
                logging.debug('%i:%i - start to poll transfers older than %i seconds for activity %s' % (process, hb['assign_thread'], older_than, activity))
                transfs = request.get_next_transfers(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                                     state=[RequestState.SUBMITTED],
                                                     limit=db_bulk,
                                                     older_than=datetime.datetime.utcnow() - datetime.timedelta(seconds=older_than),
                                                     process=process, total_processes=total_processes,
                                                     thread=hb['assign_thread'], total_threads=hb['nr_threads'],
                                                     activity=activity,
                                                     activity_shares=activity_shares)
                record_timer('daemons.conveyor.poller.000-get_next_transfers', (time.time() - ts) * 1000)

                if transfs:
                    logging.debug('%i:%i - polling %i transfers for activity %s' % (process, hb['assign_thread'], len(transfs), activity))

                xfers_ids = {}
                for transf in transfs:
                    if not transf['external_host'] in xfers_ids:
                        xfers_ids[transf['external_host']] = []
                    xfers_ids[transf['external_host']].append(transf['external_id'])

                for external_host in xfers_ids:
                    for xfers in chunks(xfers_ids[external_host], fts_bulk):
                        # poll transfers
                        # xfer_requests = makeRequests(common.poll_transfers, args_list=[((external_host, xfers, process, thread), {})])
                        xfer_requests = makeRequests(common.poll_transfers, args_list=[((), {'external_host': external_host, 'xfers': xfers, 'process': process, 'thread': hb['assign_thread'], 'timeout': timeout})])
                        [threadPool.putRequest(xfer_req) for xfer_req in xfer_requests]
                threadPool.wait()

                if len(transfs) < db_bulk / 2:
                    logging.info("%i:%i - only %s transfers for activity %s, which is less than half of the bulk %s, will sleep %s seconds" % (process, hb['assign_thread'], len(transfs), activity, db_bulk, sleep_time))
                    if activity_next_exe_time[activity] < time.time():
                        activity_next_exe_time[activity] = time.time() + sleep_time
        except:
            logging.critical("%i:%i - %s" % (process, hb['assign_thread'], traceback.format_exc()))

        if once:
            break

    logging.info('%i:%i - graceful stop requests' % (process, hb['assign_thread']))

    threadPool.dismissWorkers(total_threads, do_join=True)
    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('%i:%i - graceful stop done' % (process, hb['assign_thread']))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False,
        process=0, total_processes=1, total_threads=1, sleep_time=60, activities=None,
        fts_bulk=100, db_bulk=1000, older_than=60, activity_shares=None):
    """
    Starts up the conveyer threads.
    """

    if activity_shares:

        try:
            activity_shares = json.loads(activity_shares)
        except:
            logging.critical('activity share is not a valid JSON dictionary')
            return

        try:
            if round(sum(activity_shares.values()), 2) != 1:
                logging.critical('activity shares do not sum up to 1, got %s - aborting' % round(sum(activity_shares.values()), 2))
                return
        except:
            logging.critical('activity shares are not numbers? - aborting')
            return

        activity_shares.update((share, int(percentage * db_bulk)) for share, percentage in activity_shares.items())
        logging.info('activity shares enabled: %s' % activity_shares)

    if once:
        logging.info('executing one poller iteration only')
        poller(once=once, fts_bulk=fts_bulk, db_bulk=db_bulk, older_than=older_than, activities=activities, activity_shares=activity_shares)

    else:

        logging.info('starting poller threads')

        threads = [threading.Thread(target=poller, kwargs={'process': process,
                                                           'total_processes': total_processes,
                                                           'thread': 0,
                                                           'total_threads': total_threads,
                                                           'older_than': older_than,
                                                           'fts_bulk': fts_bulk,
                                                           'db_bulk': db_bulk,
                                                           'sleep_time': sleep_time,
                                                           'activities': activities,
                                                           'activity_shares': activity_shares})]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            threads = [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
