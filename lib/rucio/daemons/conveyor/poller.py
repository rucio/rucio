# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2018
# - Wen Guan <wen.guan@cern.ch>, 2014-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2021
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Matt Snyder <msnyder@bnl.gov>, 2019-2021
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Nick Smith <nick.smith@cern.ch>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021

"""
Conveyor is a daemon to manage file transfers.
"""

from __future__ import division

import datetime
import json
import logging
import os
import re
import socket
import threading
import time
from collections import defaultdict

from requests.exceptions import RequestException
from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get
from rucio.common.exception import DatabaseException, TransferToolTimeout, TransferToolWrongAnswer
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.utils import chunks
from rucio.core import heartbeat, transfer as transfer_core, request as request_core
from rucio.core.monitor import record_timer, record_counter
from rucio.db.sqla.constants import RequestState, RequestType

try:
    from ConfigParser import NoOptionError  # py2
except Exception:
    from configparser import NoOptionError  # py3

graceful_stop = threading.Event()

datetime.datetime.strptime('', '')

TRANSFER_TOOL = config_get('conveyor', 'transfertool', False, None)  # NOTE: This should eventually be completely removed, as it can be fetched from the request
FILTER_TRANSFERTOOL = config_get('conveyor', 'filter_transfertool', False, None)  # NOTE: TRANSFERTOOL to filter requests on


def poller(once=False, activities=None, sleep_time=60,
           fts_bulk=100, db_bulk=1000, older_than=60, activity_shares=None, partition_wait_time=10):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    try:
        timeout = config_get('conveyor', 'poll_timeout')
        timeout = float(timeout)
    except NoOptionError:
        timeout = None

    executable = 'conveyor-poller'
    if activities:
        activities.sort()
        executable += '--activities ' + str(activities)
    if activity_shares:
        activities.sort()
        executable += '--activity_shares' + str(activity_shares)
    if FILTER_TRANSFERTOOL:
        executable += ' --filter-transfertool ' + FILTER_TRANSFERTOOL

    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prefix = 'conveyor-poller[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'Poller starting - db_bulk (%i) fts_bulk (%i) timeout (%s)' % (db_bulk, fts_bulk, timeout))

    if partition_wait_time:
        time.sleep(partition_wait_time)  # To prevent running on the same partition if all the poller restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prefix = 'conveyor-poller[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')

    logger(logging.INFO, 'Poller started')

    activity_next_exe_time = defaultdict(time.time)

    while not graceful_stop.is_set():

        try:
            heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            prefix = 'conveyor-poller[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
            logger = formatted_logger(logging.log, prefix + '%s')

            if activities is None:
                activities = [None]
            for activity in activities:
                if activity_next_exe_time[activity] > time.time():
                    graceful_stop.wait(1)
                    continue

                start_time = time.time()
                logger(logging.DEBUG, 'Start to poll transfers older than %i seconds for activity %s using transfer tool: %s' % (older_than, activity, FILTER_TRANSFERTOOL))
                transfs = request_core.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                                state=[RequestState.SUBMITTED],
                                                limit=db_bulk,
                                                older_than=datetime.datetime.utcnow() - datetime.timedelta(seconds=older_than),
                                                total_workers=heart_beat['nr_threads'], worker_number=heart_beat['assign_thread'],
                                                mode_all=False, hash_variable='id',
                                                activity=activity,
                                                activity_shares=activity_shares,
                                                transfertool=FILTER_TRANSFERTOOL)

                record_timer('daemons.conveyor.poller.000-get_next', (time.time() - start_time) * 1000)

                if transfs:
                    logger(logging.DEBUG, 'Polling %i transfers for activity %s' % (len(transfs), activity))

                xfers_ids = {}
                for transf in transfs:
                    if not transf['external_host'] in xfers_ids:
                        xfers_ids[transf['external_host']] = []
                    xfers_ids[transf['external_host']].append((transf['external_id'], transf['request_id']))

                for external_host in xfers_ids:
                    external_ids = list({trf[0] for trf in xfers_ids[external_host]})
                    request_ids = [trf[1] for trf in xfers_ids[external_host]]
                    for xfers in chunks(external_ids, fts_bulk):
                        # poll transfers
                        poll_transfers(external_host=external_host, xfers=xfers, request_ids=request_ids, timeout=timeout, logger=logger)

                if len(transfs) < fts_bulk / 2:
                    logger(logging.INFO, "Only %s transfers for activity %s, which is less than half of the bulk %s, will sleep %s seconds" % (len(transfs), activity, fts_bulk, sleep_time))
                    if activity_next_exe_time[activity] < time.time():
                        activity_next_exe_time[activity] = time.time() + sleep_time
        except Exception:
            logger(logging.CRITICAL, "Exception", exc_info=True)

        if once:
            break

    logger(logging.INFO, 'Graceful stop requested')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logger(logging.INFO, 'Graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, sleep_time=60, activities=None,
        fts_bulk=100, db_bulk=1000, older_than=60, activity_shares=None, total_threads=1):
    """
    Starts up the conveyer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    if activity_shares:

        try:
            activity_shares = json.loads(activity_shares)
        except Exception:
            logging.critical('activity share is not a valid JSON dictionary')
            return

        try:
            if round(sum(activity_shares.values()), 2) != 1:
                logging.critical('activity shares do not sum up to 1, got %s - aborting' % round(sum(activity_shares.values()), 2))
                return
        except Exception:
            logging.critical('activity shares are not numbers? - aborting')
            return

        activity_shares.update((share, int(percentage * db_bulk)) for share, percentage in activity_shares.items())
        logging.info('activity shares enabled: %s' % activity_shares)

    if once:
        logging.info('executing one poller iteration only')
        poller(once=once, fts_bulk=fts_bulk, db_bulk=db_bulk, older_than=older_than, activities=activities, activity_shares=activity_shares)

    else:

        logging.info('starting poller threads')

        threads = [threading.Thread(target=poller, kwargs={'older_than': older_than,
                                                           'fts_bulk': fts_bulk,
                                                           'db_bulk': db_bulk,
                                                           'sleep_time': sleep_time,
                                                           'activities': activities,
                                                           'activity_shares': activity_shares}) for _ in range(0, total_threads)]

        [thread.start() for thread in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads:
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]


def poll_transfers(external_host, xfers, request_ids=None, timeout=None, logger=logging.log):
    """
    Poll a list of transfers from an FTS server

    :param external_host:    The FTS server to query from.
    :param xfrs:             List of transfers to poll.
    :param process:          Process number.
    :param thread:           Thread number.
    :param timeout:          Timeout.
    :param logger:           Optional decorated logger that can be passed from the calling daemons or servers.
    """
    try:
        if TRANSFER_TOOL == 'mock':
            logger(logging.DEBUG, 'Setting %s transfer requests status to DONE per mock tool' % (len(xfers)))
            for task_id in xfers:
                ret = transfer_core.update_transfer_state(external_host=None, transfer_id=task_id, state=RequestState.DONE)
                record_counter('daemons.conveyor.poller.update_request_state.%s' % ret)
            return
        try:
            tss = time.time()
            logger(logging.INFO, 'Polling %i transfers against %s with timeout %s' % (len(xfers), external_host, timeout))
            resps = transfer_core.bulk_query_transfers(external_host, xfers, TRANSFER_TOOL, timeout)
            record_timer('daemons.conveyor.poller.bulk_query_transfers', (time.time() - tss) * 1000 / len(xfers))
        except TransferToolTimeout as error:
            logger(logging.ERROR, str(error))
            return
        except TransferToolWrongAnswer as error:
            logger(logging.ERROR, str(error))
            logger(logging.ERROR, 'Problem querying %s on %s. All jobs are being checked individually' % (str(xfers), external_host))
            for xfer in xfers:
                try:
                    logger(logging.DEBUG, 'Checking %s on %s' % (xfer, external_host))
                    status = transfer_core.bulk_query_transfers(external_host, [xfer, ], TRANSFER_TOOL, timeout)
                    if xfer in status and isinstance(status[xfer], Exception):
                        logger(logging.ERROR, 'Problem querying %s on %s . Error returned : %s' % (xfer, external_host, str(status[xfer])))
                except Exception as err:
                    logger(logging.ERROR, 'Problem querying %s on %s . Error returned : %s' % (xfer, external_host, str(err)))
                    break
            return
        except RequestException as error:
            logger(logging.ERROR, "Failed to contact FTS server: %s" % (str(error)))
            return
        except Exception:
            logger(logging.ERROR, "Failed to query FTS info", exc_info=True)
            return

        logger(logging.DEBUG, 'Polled %s transfer requests status in %s seconds' % (len(xfers), (time.time() - tss)))
        tss = time.time()
        logger(logging.DEBUG, 'Updating %s transfer requests status' % (len(xfers)))
        cnt = 0

        if TRANSFER_TOOL == 'globus':
            for task_id in resps:
                ret = transfer_core.update_transfer_state(external_host=None, transfer_id=task_id, state=resps[task_id])
                record_counter('daemons.conveyor.poller.update_request_state.%s' % ret)
        else:
            for transfer_id in resps:
                try:
                    transf_resp = resps[transfer_id]
                    # transf_resp is None: Lost.
                    #             is Exception: Failed to get fts job status.
                    #             is {}: No terminated jobs.
                    #             is {request_id: {file_status}}: terminated jobs.
                    if transf_resp is None:
                        transfer_core.update_transfer_state(external_host, transfer_id, RequestState.LOST, logger=logger)
                        record_counter('daemons.conveyor.poller.transfer_lost')
                    elif isinstance(transf_resp, Exception):
                        logger(logging.WARNING, "Failed to poll FTS(%s) job (%s): %s" % (external_host, transfer_id, transf_resp))
                        record_counter('daemons.conveyor.poller.query_transfer_exception')
                    else:
                        for request_id in transf_resp:
                            if request_id in request_ids:
                                ret = request_core.update_request_state(transf_resp[request_id], logger=logger)
                                # if True, really update request content; if False, only touch request
                                if ret:
                                    cnt += 1
                                record_counter('daemons.conveyor.poller.update_request_state.%s' % ret)

                    # should touch transfers.
                    # Otherwise if one bulk transfer includes many requests and one is not terminated, the transfer will be poll again.
                    transfer_core.touch_transfer(external_host, transfer_id)
                except (DatabaseException, DatabaseError) as error:
                    if re.match('.*ORA-00054.*', error.args[0]) or re.match('.*ORA-00060.*', error.args[0]) or 'ERROR 1205 (HY000)' in error.args[0]:
                        logger(logging.WARNING, "Lock detected when handling request %s - skipping" % request_id)
                    else:
                        logger(logging.ERROR, 'Exception', exc_info=True)
            logger(logging.DEBUG, 'Finished updating %s transfer requests status (%i requests state changed) in %s seconds' % (len(xfers), cnt, (time.time() - tss)))
    except Exception:
        logger(logging.ERROR, 'Exception', exc_info=True)
