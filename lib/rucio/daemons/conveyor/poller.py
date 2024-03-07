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
import itertools
import json
import logging
import re
import threading
import time
from collections.abc import Sequence
from itertools import groupby
from types import FrameType
from typing import TYPE_CHECKING, Any, Mapping, Optional

from requests.exceptions import RequestException
from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import DatabaseException, TransferToolTimeout, TransferToolWrongAnswer
from rucio.common.logging import setup_logging
from rucio.common.stopwatch import Stopwatch
from rucio.common.types import InternalAccount
from rucio.common.utils import dict_chunks
from rucio.core import transfer as transfer_core, request as request_core
from rucio.core.monitor import MetricManager
from rucio.core.topology import Topology, ExpiringObjectCache
from rucio.daemons.common import db_workqueue, ProducerConsumerDaemon
from rucio.db.sqla.constants import MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED, ORACLE_DEADLOCK_DETECTED_REGEX, ORACLE_RESOURCE_BUSY_REGEX, RequestState, RequestType
from rucio.transfertool.transfertool import Transfertool
from rucio.transfertool.fts3 import FTS3Transfertool

if TYPE_CHECKING:
    from rucio.daemons.common import HeartbeatHandler

GRACEFUL_STOP = threading.Event()
METRICS = MetricManager(module=__name__)
DAEMON_NAME = 'conveyor-poller'

TRANSFER_TOOL = config_get('conveyor', 'transfertool', False, None)  # NOTE: This should eventually be completely removed, as it can be fetched from the request
FILTER_TRANSFERTOOL = config_get('conveyor', 'filter_transfertool', False, None)  # NOTE: TRANSFERTOOL to filter requests on


def _fetch_requests(
        db_bulk,
        older_than,
        activity_shares,
        transfertool,
        filter_transfertool,
        cached_topology,
        activity,
        set_last_processed_by: bool,
        heartbeat_handler
):
    worker_number, total_workers, logger = heartbeat_handler.live()

    logger(logging.DEBUG, 'Start to poll transfers older than %i seconds for activity %s using transfer tool: %s' % (older_than, activity, filter_transfertool))

    topology = cached_topology.get() if cached_topology else Topology()
    transfs = request_core.get_and_mark_next(
        rse_collection=topology,
        request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
        state=[RequestState.SUBMITTED],
        processed_by=heartbeat_handler.short_executable if set_last_processed_by else None,
        limit=db_bulk,
        older_than=datetime.datetime.utcnow() - datetime.timedelta(seconds=older_than) if older_than else None,
        total_workers=total_workers,
        worker_number=worker_number,
        mode_all=True,
        hash_variable='id',
        activity=activity,
        activity_shares=activity_shares,
        transfertool=filter_transfertool,
    )

    if transfertool and not filter_transfertool:
        # only keep transfers which don't have any transfertool set, or have one equal to TRANSFER_TOOL
        transfs_tmp = [t for t in transfs if not t['transfertool'] or t['transfertool'] == transfertool]
        if len(transfs_tmp) != len(transfs):
            logger(logging.INFO, 'Skipping %i transfers because of missmatched transfertool', len(transfs) - len(transfs_tmp))
        transfs = transfs_tmp

    if transfs:
        logger(logging.DEBUG, 'Polling %i transfers for activity %s' % (len(transfs), activity))

    must_sleep = False
    if len(transfs) < db_bulk / 2:
        logger(logging.INFO, "Only %s transfers for activity %s, which is less than half of the bulk %s" % (len(transfs), activity, db_bulk))
        must_sleep = True

    return must_sleep, transfs


def _handle_requests(
        transfs,
        fts_bulk,
        multi_vo,
        timeout,
        transfertool,
        transfer_stats_manager: request_core.TransferStatsManager,
        oidc_account: Optional[str],
        *,
        logger=logging.log,
):
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
                transfertool_cls = transfer_core.TRANSFERTOOL_CLASSES_BY_NAME.get(transfertool, FTS3Transfertool)

                transfertool_kwargs = {}
                if transfertool_cls.external_name == FTS3Transfertool.external_name:
                    account = None
                    if oidc_account:
                        if vo:
                            account = InternalAccount(oidc_account, vo=vo)
                        else:
                            account = InternalAccount(oidc_account)
                    transfertool_kwargs.update({
                        'vo': vo,
                        'oidc_account': account,
                    })

                transfertool_obj = transfertool_cls(external_host=external_host, **transfertool_kwargs)
                poll_transfers(
                    transfertool_obj=transfertool_obj,
                    transfers_by_eid=chunk,
                    transfer_stats_manager=transfer_stats_manager,
                    timeout=timeout,
                    logger=logger,
                )
            except Exception:
                logger(logging.ERROR, 'Exception', exc_info=True)


def poller(
        once: bool = False,
        activities: Optional[Sequence[str]] = None,
        sleep_time: int = 60,
        fts_bulk: int = 100,
        db_bulk: int = 1000,
        older_than: int = 60,
        activity_shares: Optional[Mapping[str, float]] = None,
        partition_wait_time: int = 10,
        transfertool: Optional[str] = TRANSFER_TOOL,
        filter_transfertool: Optional[str] = FILTER_TRANSFERTOOL,
        cached_topology=None,
        total_threads: int = 1,
):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    timeout = config_get('conveyor', 'poll_timeout', default=None, raise_exception=False)
    if timeout:
        timeout = float(timeout)

    multi_vo = config_get_bool('common', 'multi_vo', False, None)
    oidc_account = config_get('conveyor', 'poller_oidc_account', False, None)

    executable = DAEMON_NAME

    if activities:
        activities = sorted(activities)
        executable += '--activities ' + str(activities)
    if activity_shares:
        executable += '--activity_shares' + str(sorted(activity_shares))
    if filter_transfertool:
        executable += ' --filter-transfertool ' + filter_transfertool

    transfer_stats_manager = request_core.TransferStatsManager()

    @db_workqueue(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=executable,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        activities=activities,
    )
    def _db_producer(*, activity: str, heartbeat_handler: "HeartbeatHandler"):
        return _fetch_requests(
            db_bulk=db_bulk,
            older_than=older_than,
            activity_shares=activity_shares,
            transfertool=transfertool,
            filter_transfertool=filter_transfertool,
            cached_topology=cached_topology,
            activity=activity,
            set_last_processed_by=not once,
            heartbeat_handler=heartbeat_handler,
        )

    def _consumer(transfs):
        return _handle_requests(
            transfs=transfs,
            fts_bulk=fts_bulk,
            multi_vo=multi_vo,
            timeout=timeout,
            oidc_account=oidc_account,
            transfertool=transfertool,
            transfer_stats_manager=transfer_stats_manager,
        )

    with transfer_stats_manager:
        ProducerConsumerDaemon(
            producers=[_db_producer],
            consumers=[_consumer for _ in range(total_threads)],
            graceful_stop=GRACEFUL_STOP,
        ).run()


def stop(signum: Optional[int] = None, frame: Optional[FrameType] = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(
        once=False,
        sleep_time=60,
        activities=None,
        fts_bulk=100,
        db_bulk=1000,
        older_than=60,
        activity_shares: Optional[str] = None,
        total_threads=1
):
    """
    Starts up the conveyer threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    parsed_activity_shares = None
    if activity_shares:

        try:
            parsed_activity_shares = {str(activity): float(share) for activity, share in json.loads(activity_shares).items()}
        except Exception:
            logging.critical('activity share is not a valid JSON dictionary')
            return

        try:
            if round(sum(parsed_activity_shares.values()), 2) != 1:
                logging.critical('activity shares do not sum up to 1, got %s - aborting' % round(sum(parsed_activity_shares.values()), 2))
                return
        except Exception:
            logging.critical('activity shares are not numbers? - aborting')
            return

        parsed_activity_shares.update((share, int(percentage * db_bulk)) for share, percentage in parsed_activity_shares.items())
        logging.info('activity shares enabled: %s' % parsed_activity_shares)

    cached_topology = ExpiringObjectCache(ttl=300, new_obj_fnc=lambda: Topology())
    poller(
        once=once,
        fts_bulk=fts_bulk,
        db_bulk=db_bulk,
        older_than=older_than,
        sleep_time=sleep_time,
        activities=activities,
        activity_shares=parsed_activity_shares,
        cached_topology=cached_topology,
        total_threads=total_threads,
    )


def poll_transfers(
        transfertool_obj: Transfertool,
        transfers_by_eid: Mapping[str, Mapping[str, Any]],
        transfer_stats_manager: request_core.TransferStatsManager,
        timeout: "Optional[int]" = None,
        logger=logging.log
):
    """
    Poll a list of transfers from an FTS server
    """

    poll_individual_transfers = False
    try:
        _poll_transfers(transfertool_obj, transfers_by_eid, transfer_stats_manager, timeout, logger)
    except TransferToolWrongAnswer:
        poll_individual_transfers = True

    if poll_individual_transfers:
        logger(logging.ERROR, 'Problem querying %s on %s. All jobs are being checked individually' % (list(transfers_by_eid), transfertool_obj))
        for external_id, transfers in transfers_by_eid.items():
            logger(logging.DEBUG, 'Checking %s on %s' % (external_id, transfertool_obj))
            try:
                _poll_transfers(transfertool_obj, {external_id: transfers}, transfer_stats_manager, timeout, logger)
            except Exception as err:
                logger(logging.ERROR, 'Problem querying %s on %s . Error returned : %s' % (external_id, transfertool_obj, str(err)))


def _poll_transfers(
        transfertool_obj: Transfertool,
        transfers_by_eid: Mapping[str, Mapping[str, Any]],
        transfer_stats_manager: request_core.TransferStatsManager,
        timeout: "Optional[int]" = None,
        logger=logging.log
):
    """
    Helper function for poll_transfers which performs the actual polling and database update.
    """
    is_bulk = len(transfers_by_eid) > 1
    try:
        stopwatch = Stopwatch()
        logger(logging.INFO, 'Polling %i transfers against %s with timeout %s' % (len(transfers_by_eid), transfertool_obj, timeout))
        resps = transfertool_obj.bulk_query(requests_by_eid=transfers_by_eid, timeout=timeout)
        stopwatch.stop()
        METRICS.timer('bulk_query_transfers').observe(stopwatch.elapsed / (len(transfers_by_eid) or 1))
        logger(logging.DEBUG, 'Polled %s transfer requests status in %s seconds' % (len(transfers_by_eid), stopwatch.elapsed))
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
                METRICS.counter('transfer_lost').inc()
            elif isinstance(transf_resp, Exception):
                logger(logging.WARNING, "Failed to poll FTS(%s) job (%s): %s" % (transfertool_obj, transfer_id, transf_resp))
                METRICS.counter('query_transfer_exception').inc()
            else:
                for request_id in request_ids.intersection(transf_resp):
                    ret = transfer_core.update_transfer_state(
                        tt_status_report=transf_resp[request_id],
                        stats_manager=transfer_stats_manager,
                        logger=logger,
                    )
                    cnt += ret
                    if ret:
                        METRICS.counter('update_request_state.{updated}').labels(updated=True).inc(delta=ret)
                    else:
                        METRICS.counter('update_request_state.{updated}').labels(updated=False).inc()

            # should touch transfers.
            # Otherwise if one bulk transfer includes many requests and one is not terminated, the transfer will be poll again.
            transfer_core.touch_transfer(transfertool_obj.external_host, transfer_id)
        except (DatabaseException, DatabaseError) as error:
            if re.match(ORACLE_RESOURCE_BUSY_REGEX, error.args[0]) or re.match(ORACLE_DEADLOCK_DETECTED_REGEX, error.args[0]) or MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED in error.args[0]:
                logger(logging.WARNING, "Lock detected when handling request %s - skipping" % transfer_id)
            else:
                logger(logging.ERROR, 'Exception', exc_info=True)
    logger(logging.DEBUG, 'Finished updating %s transfer requests status (%i requests state changed) in %s seconds' % (len(transfers_by_eid), cnt, (time.time() - tss)))
