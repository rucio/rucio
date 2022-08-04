# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

"""
Conveyor is a daemon to manage file transfers.
"""

import datetime
import functools
import itertools
import json
import logging
import re
import threading
import time
from itertools import groupby

from requests.exceptions import RequestException
from configparser import NoOptionError
from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import DatabaseException, TransferToolTimeout, TransferToolWrongAnswer
from rucio.common.types import InternalAccount
from rucio.common.logging import setup_logging
from rucio.common.utils import dict_chunks
from rucio.core import transfer as transfer_core, request as request_core
from rucio.core.monitor import Timer, record_counter
from rucio.db.sqla.constants import RequestState, RequestType
from rucio.daemons.common import run_daemon
from rucio.transfertool.fts3 import FTS3Transfertool
from rucio.transfertool.globus import GlobusTransferTool

graceful_stop = threading.Event()

datetime.datetime.strptime('', '')

TRANSFER_TOOL = config_get('conveyor', 'transfertool', False, None)  # NOTE: This should eventually be completely removed, as it can be fetched from the request
FILTER_TRANSFERTOOL = config_get('conveyor', 'filter_transfertool', False, None)  # NOTE: TRANSFERTOOL to filter requests on


def run_once(fts_bulk, db_bulk, older_than, activity_shares, multi_vo, timeout, activity, heartbeat_handler, oidc_account: str):
    worker_number, total_workers, logger = heartbeat_handler.live()

    with Timer('daemons.conveyor.poller.get_next'):
        logger(logging.DEBUG, 'Start to poll transfers older than %i seconds for activity %s using transfer tool: %s' % (older_than, activity, FILTER_TRANSFERTOOL))
        transfs = request_core.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                        state=[RequestState.SUBMITTED],
                                        limit=db_bulk,
                                        older_than=datetime.datetime.utcnow() - datetime.timedelta(seconds=older_than) if older_than else None,
                                        total_workers=total_workers,
                                        worker_number=worker_number,
                                        mode_all=True,
                                        hash_variable='id',
                                        activity=activity,
                                        activity_shares=activity_shares,
                                        transfertool=FILTER_TRANSFERTOOL)

    if TRANSFER_TOOL and not FILTER_TRANSFERTOOL:
        # only keep transfers which don't have any transfertool set, or have one equal to TRANSFER_TOOL
        transfs_tmp = [t for t in transfs if not t['transfertool'] or t['transfertool'] == TRANSFER_TOOL]
        if len(transfs_tmp) != len(transfs):
            logger(logging.INFO, 'Skipping %i transfers because of missmatched transfertool', len(transfs) - len(transfs_tmp))
        transfs = transfs_tmp

    if transfs:
        logger(logging.DEBUG, 'Polling %i transfers for activity %s' % (len(transfs), activity))

    transfs.sort(key=lambda t: (t['external_host'] or '',
                                t['scope'].vo if multi_vo else '',
                                t['external_id'] or '',
                                t['request_id'] or ''))
    for (external_host, vo), transfers_for_host in groupby(transfs, key=lambda t: (t['external_host'],
                                                                                   t['scope'].vo if multi_vo else None)):
        transfers_by_eid = {}
        for external_id, xfers in groupby(transfers_for_host, key=lambda t: t['external_id']):
            transfers_by_eid[external_id] = {t['request_id']: t for t in xfers}

        for chunk in dict_chunks(transfers_by_eid, fts_bulk):
            try:
                if TRANSFER_TOOL == 'globus':
                    transfertool_obj = GlobusTransferTool(external_host=None)
                else:
                    account = None
                    if oidc_account:
                        if vo:
                            account = InternalAccount(oidc_account, vo=vo)
                        else:
                            account = InternalAccount(oidc_account)
                    transfertool_obj = FTS3Transfertool(external_host=external_host, vo=vo, oidc_account=account)
                worker_number, total_workers, logger = heartbeat_handler.live()
                poll_transfers(transfertool_obj=transfertool_obj, transfers_by_eid=chunk, timeout=timeout, logger=logger)
            except Exception:
                logger(logging.ERROR, 'Exception', exc_info=True)

    queue_empty = False
    if len(transfs) < fts_bulk / 2:
        logger(logging.INFO, "Only %s transfers for activity %s, which is less than half of the bulk %s" % (len(transfs), activity, fts_bulk))
        queue_empty = True

    return queue_empty


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

    multi_vo = config_get_bool('common', 'multi_vo', False, None)
    oidc_account = config_get('conveyor', 'poller_oidc_account', False, None)

    logger_prefix = executable = 'conveyor-poller'

    if activities:
        activities.sort()
        executable += '--activities ' + str(activities)
    if activity_shares:
        activities.sort()
        executable += '--activity_shares' + str(activity_shares)
    if FILTER_TRANSFERTOOL:
        executable += ' --filter-transfertool ' + FILTER_TRANSFERTOOL

    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        logger_prefix=logger_prefix,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            fts_bulk=fts_bulk,
            db_bulk=db_bulk,
            older_than=older_than,
            activity_shares=activity_shares,
            multi_vo=multi_vo,
            timeout=timeout,
            oidc_account=oidc_account,
        ),
        activities=activities,
    )


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


def poll_transfers(transfertool_obj, transfers_by_eid, timeout=None, logger=logging.log):
    """
    Poll a list of transfers from an FTS server

    :param transfertool_obj: The Transfertool to use for query
    :param transfers_by_eid: Dict of the form {external_id: list_of_transfers}
    :param timeout:          Timeout.
    :param logger:           Optional decorated logger that can be passed from the calling daemons or servers.
    """

    poll_individual_transfers = False
    try:
        _poll_transfers(transfertool_obj, transfers_by_eid, timeout, logger)
    except TransferToolWrongAnswer:
        poll_individual_transfers = True

    if poll_individual_transfers:
        logger(logging.ERROR, 'Problem querying %s on %s. All jobs are being checked individually' % (list(transfers_by_eid), transfertool_obj))
        for external_id, transfers in transfers_by_eid.items():
            logger(logging.DEBUG, 'Checking %s on %s' % (external_id, transfertool_obj))
            try:
                _poll_transfers(transfertool_obj, {external_id: transfers}, timeout, logger)
            except Exception as err:
                logger(logging.ERROR, 'Problem querying %s on %s . Error returned : %s' % (external_id, transfertool_obj, str(err)))


def _poll_transfers(transfertool_obj, transfers_by_eid, timeout, logger):
    """
    Helper function for poll_transfers which performs the actual polling and database update.
    """
    is_bulk = len(transfers_by_eid) > 1
    try:
        timer = Timer()
        logger(logging.INFO, 'Polling %i transfers against %s with timeout %s' % (len(transfers_by_eid), transfertool_obj, timeout))
        resps = transfertool_obj.bulk_query(requests_by_eid=transfers_by_eid, timeout=timeout)
        timer.stop()
        timer.record('daemons.conveyor.poller.bulk_query_transfers', divisor=len(transfers_by_eid))
        logger(logging.DEBUG, 'Polled %s transfer requests status in %s seconds' % (len(transfers_by_eid), timer.elapsed))
    except TransferToolTimeout as error:
        logger(logging.ERROR, str(error))
        return
    except TransferToolWrongAnswer as error:
        logger(logging.ERROR, str(error))
        if is_bulk:
            raise  # The calling context will retry transfers one-by-one
        else:
            return
    except RequestException as error:
        logger(logging.ERROR, "Failed to contact FTS server: %s" % (str(error)))
        return
    except Exception:
        logger(logging.ERROR, "Failed to query FTS info", exc_info=True)
        return

    tss = time.time()
    logger(logging.DEBUG, 'Updating %s transfer requests status' % (len(transfers_by_eid)))
    cnt = 0

    request_ids = set(itertools.chain.from_iterable(transfers_by_eid.values()))
    for transfer_id in resps:
        try:
            transf_resp = resps[transfer_id]
            # transf_resp is None: Lost.
            #             is Exception: Failed to get fts job status.
            #             is {}: No terminated jobs.
            #             is {request_id: {file_status}}: terminated jobs.
            if transf_resp is None:
                for request_id, request in transfers_by_eid[transfer_id].items():
                    transfer_core.mark_transfer_lost(request, logger=logger)
                record_counter('daemons.conveyor.poller.transfer_lost')
            elif isinstance(transf_resp, Exception):
                logger(logging.WARNING, "Failed to poll FTS(%s) job (%s): %s" % (transfertool_obj, transfer_id, transf_resp))
                record_counter('daemons.conveyor.poller.query_transfer_exception')
            else:
                for request_id in request_ids.intersection(transf_resp):
                    ret = request_core.update_request_state(transf_resp[request_id], logger=logger)
                    # if True, really update request content; if False, only touch request
                    if ret:
                        cnt += 1
                    record_counter('daemons.conveyor.poller.update_request_state.{updated}', labels={'updated': ret})

            # should touch transfers.
            # Otherwise if one bulk transfer includes many requests and one is not terminated, the transfer will be poll again.
            transfer_core.touch_transfer(transfertool_obj.external_host, transfer_id)
        except (DatabaseException, DatabaseError) as error:
            if re.match('.*ORA-00054.*', error.args[0]) or re.match('.*ORA-00060.*', error.args[0]) or 'ERROR 1205 (HY000)' in error.args[0]:
                logger(logging.WARNING, "Lock detected when handling request %s - skipping" % transfer_id)
            else:
                logger(logging.ERROR, 'Exception', exc_info=True)
    logger(logging.DEBUG, 'Finished updating %s transfer requests status (%i requests state changed) in %s seconds' % (len(transfers_by_eid), cnt, (time.time() - tss)))
