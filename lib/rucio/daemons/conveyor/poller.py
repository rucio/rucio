# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2014
# - Vincent Garonne <vgaronne@gmail.com>, 2014-2018
# - Wen Guan <wguan.icedew@gmail.com>, 2014-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2017

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

from re import match

from collections import defaultdict
from ConfigParser import NoOptionError
from requests.exceptions import RequestException
from sqlalchemy.exc import DatabaseError
from threadpool import ThreadPool, makeRequests

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.common.utils import chunks
from rucio.core import heartbeat, transfer as transfer_core, request as request_core
from rucio.core.monitor import record_timer, record_counter
from rucio.db.sqla.constants import RequestState, RequestType


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()

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

    while not graceful_stop.is_set():

        try:
            hb = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            logging.debug('poller - thread (%i/%i)' % (hb['assign_thread'], hb['nr_threads']))

            if activities is None:
                activities = [None]
            for activity in activities:
                if activity_next_exe_time[activity] > time.time():
                    graceful_stop.wait(1)
                    continue

                ts = time.time()
                logging.debug('%i:%i - start to poll transfers older than %i seconds for activity %s' % (process, hb['assign_thread'], older_than, activity))
                transfs = transfer_core.get_next_transfers(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
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
                        xfer_requests = makeRequests(poll_transfers, args_list=[((), {'external_host': external_host, 'xfers': xfers, 'process': process, 'thread': hb['assign_thread'], 'timeout': timeout})])
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


def poll_transfers(external_host, xfers, process=0, thread=0, timeout=None):
    """
    Poll a list of transfers from an FTS server

    :param external_host:    The FTS server to query from.
    :param xfrs:             List of transfers to poll.
    :param process:          Process number.
    :param thread:           Thread number.
    :param timeout:          Timeout.
    """
    try:
        try:
            tss = time.time()
            logging.info('%i:%i - polling %i transfers against %s with timeout %s' % (process, thread, len(xfers), external_host, timeout))
            resps = transfer_core.bulk_query_transfers(external_host, xfers, 'fts3', timeout)
            record_timer('daemons.conveyor.poller.bulk_query_transfers', (time.time() - tss) * 1000 / len(xfers))
        except RequestException as error:
            logging.error("Failed to contact FTS server: %s" % (str(error)))
            return
        except:
            logging.error("Failed to query FTS info: %s" % (traceback.format_exc()))
            return

        logging.debug('%i:%i - updating %s requests status' % (process, thread, len(xfers)))
        for transfer_id in resps:
            try:
                transf_resp = resps[transfer_id]
                # transf_resp is None: Lost.
                #             is Exception: Failed to get fts job status.
                #             is {}: No terminated jobs.
                #             is {request_id: {file_status}}: terminated jobs.
                if transf_resp is None:
                    transfer_core.update_transfer_state(external_host, transfer_id, RequestState.LOST)
                    record_counter('daemons.conveyor.poller.transfer_lost')
                elif isinstance(transf_resp, Exception):
                    logging.warning("Failed to poll FTS(%s) job (%s): %s" % (external_host, transfer_id, transf_resp))
                    record_counter('daemons.conveyor.poller.query_transfer_exception')
                else:
                    for request_id in transf_resp:
                        ret = request_core.update_request_state(transf_resp[request_id])
                        # if True, really update request content; if False, only touch request
                        record_counter('daemons.conveyor.poller.update_request_state.%s' % ret)

                # should touch transfers.
                # Otherwise if one bulk transfer includes many requests and one is not terminated, the transfer will be poll again.
                transfer_core.touch_transfer(external_host, transfer_id)
            except (DatabaseException, DatabaseError) as error:
                if isinstance(error.args[0], tuple) and (match('.*ORA-00054.*', error.args[0][0]) or match('.*ORA-00060.*', error.args[0][0]) or ('ERROR 1205 (HY000)' in error.args[0][0])):
                    logging.warn("Lock detected when handling request %s - skipping" % request_id)
                else:
                    logging.error(traceback.format_exc())
        logging.debug('%i:%i - finished updating %s requests status' % (process, thread, len(xfers)))
    except:
        logging.error(traceback.format_exc())
