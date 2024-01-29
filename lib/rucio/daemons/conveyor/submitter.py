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
Conveyor transfer submitter is a daemon to manage non-tape file transfers.
"""
import logging
import threading
from collections.abc import Mapping
from types import FrameType
from typing import TYPE_CHECKING, Any, Optional

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int, config_get_list, config_get_float
from rucio.common.logging import setup_logging
from rucio.common.schema import get_schema_value
from rucio.common.stopwatch import Stopwatch
from rucio.core.monitor import MetricManager
from rucio.core.request import list_and_mark_transfer_requests_and_source_replicas
from rucio.core.topology import Topology, ExpiringObjectCache
from rucio.core.transfer import DEFAULT_MULTIHOP_TOMBSTONE_DELAY, list_transfer_admin_accounts, transfer_path_str, \
    TRANSFERTOOL_CLASSES_BY_NAME, ProtocolFactory
from rucio.daemons.common import db_workqueue, ProducerConsumerDaemon
from rucio.daemons.conveyor.common import submit_transfer, get_conveyor_rses, pick_and_prepare_submission_path
from rucio.db.sqla.constants import RequestType, RequestState
from rucio.transfertool.fts3 import FTS3Transfertool
from rucio.transfertool.globus import GlobusTransferTool

if TYPE_CHECKING:
    from rucio.daemons.common import HeartbeatHandler

METRICS = MetricManager(module=__name__)
GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'conveyor-submitter'

TRANSFER_TOOLS = config_get_list('conveyor', 'transfertool', False, [])  # NOTE: This should eventually be completely removed, as it can be fetched from the request
FILTER_TRANSFERTOOL = config_get('conveyor', 'filter_transfertool', False, None)  # NOTE: TRANSFERTOOL to filter requests on
TRANSFER_TYPE = config_get('conveyor', 'transfertype', False, 'single')


def _fetch_requests(
        partition_hash_var: Optional[str],
        bulk: int,
        activity: str,
        rse_ids: Optional[list[str]],
        request_type: list[RequestType],
        ignore_availability: bool,
        filter_transfertool: Optional[str],
        metrics: MetricManager,
        cached_topology,
        set_last_processed_by: bool,
        heartbeat_handler: "HeartbeatHandler",
):
    """
    Fetches requests to be handled from the database
    """
    worker_number, total_workers, logger = heartbeat_handler.live()

    topology = cached_topology.get() if cached_topology else Topology(ignore_availability=ignore_availability)
    topology.configure_multihop(logger=logger)
    stopwatch = Stopwatch()

    required_source_rse_attrs = None
    # if filter_transfertool specified, select only the source rses which are configured for this transfertool
    if filter_transfertool:
        # if multihop is configured, we want all possible source rses. To allow multi-hopping between transfertools
        if not topology.multihop_enabled:
            required_source_rse_attrs = TRANSFERTOOL_CLASSES_BY_NAME[filter_transfertool].required_rse_attrs

    # retrieve (from the database) the transfer requests with their possible source replicas
    requests_with_sources = list_and_mark_transfer_requests_and_source_replicas(
        rse_collection=topology,
        processed_by=heartbeat_handler.short_executable if set_last_processed_by else None,
        total_workers=total_workers,
        worker_number=worker_number,
        partition_hash_var=partition_hash_var,
        limit=bulk,
        activity=activity,
        older_than=None,
        rses=rse_ids,
        request_type=request_type,
        request_state=RequestState.QUEUED,
        ignore_availability=ignore_availability,
        transfertool=filter_transfertool,
        required_source_rse_attrs=required_source_rse_attrs,
    )

    stopwatch.stop()
    total_transfers = len(requests_with_sources)

    metrics.timer('get_transfers.time_per_transfer').observe(stopwatch.elapsed / (total_transfers or 1))
    metrics.counter('get_transfers.total_transfers').inc(total_transfers)
    logger(logging.INFO, 'Got %s transfers for %s in %s seconds', total_transfers, activity, stopwatch.elapsed)

    must_sleep = False
    if total_transfers < bulk:
        must_sleep = True
        logger(logging.DEBUG, 'Only %s transfers for %s which is less than bulk %s', total_transfers, activity, bulk)

    return must_sleep, (topology, requests_with_sources)


def _handle_requests(
        batch,
        *,
        transfertools: list[str],
        schemes: Optional[list[str]],
        failover_schemes: Optional[list[str]],
        max_sources: int,
        timeout: Optional[float],
        transfertool_kwargs,
        metrics: MetricManager,
        logger=logging.log,
):
    topology, requests_with_sources = batch

    protocol_factory = ProtocolFactory()
    default_tombstone_delay = config_get_int('transfers', 'multihop_tombstone_delay', default=DEFAULT_MULTIHOP_TOMBSTONE_DELAY, expiration_time=600)
    admin_accounts = list_transfer_admin_accounts()

    transfers = pick_and_prepare_submission_path(
        requests_with_sources=requests_with_sources,
        topology=topology,
        protocol_factory=protocol_factory,
        default_tombstone_delay=default_tombstone_delay,
        admin_accounts=admin_accounts,
        failover_schemes=failover_schemes,
        schemes=schemes,
        max_sources=max_sources,
        transfertools=transfertools,
        logger=logger,
    )

    for builder, transfer_paths in transfers.items():
        # Globus Transfertool is not yet production-ready, but we need to partially activate it
        # in all submitters if we want to enable native multi-hopping between transfertools.
        # This "if" can be triggered in a FTS submitter if it tries to multi-hop from
        # a globus-only RSE via a dual-stack RSE towards an FTS-only RSE.
        #
        # Just ignore this transfer and keep it in a queued state, so that it's picked up
        # latter by that special submitter instance dedicated to globus transfers.
        #
        # TODO: remove this "if"
        if transfertools[0] != GlobusTransferTool.external_name and builder.transfertool_class == GlobusTransferTool:
            logger(logging.INFO, 'Skipping submission of following transfers: %s', [transfer_path_str(p) for p in transfer_paths])
            continue

        transfertool_obj = builder.make_transfertool(logger=logger, **transfertool_kwargs.get(builder.transfertool_class, {}))
        logger(logging.DEBUG, 'Starting to group transfers %s', transfertool_obj)
        stopwatch = Stopwatch()
        grouped_jobs = transfertool_obj.group_into_submit_jobs(transfer_paths)
        metrics.timer('bulk_group_transfer').observe(stopwatch.elapsed / (len(transfer_paths) or 1))

        logger(logging.DEBUG, 'Starting to submit transfers for %s', transfertool_obj)
        for job in grouped_jobs:
            logger(logging.DEBUG, 'submitjob: transfers=%s, job_params=%s' % ([str(t) for t in job['transfers']], job['job_params']))
            submit_transfer(transfertool_obj=transfertool_obj, transfers=job['transfers'], job_params=job['job_params'],
                            timeout=timeout, logger=logger)


def _get_max_time_in_queue_conf() -> dict[str, int]:
    """
    Retrieve and parse the max_time_in_queue configuration value into a dictionary: {"activity": int}
    """
    max_time_in_queue = {}
    timelife_conf = config_get('conveyor', 'max_time_in_queue', default='', raise_exception=False)
    if timelife_conf:
        timelife_confs = timelife_conf.split(",")
        for conf in timelife_confs:
            act, timelife = conf.split(":")
            max_time_in_queue[act.strip()] = int(timelife.strip())
    if 'default' not in max_time_in_queue:
        max_time_in_queue['default'] = 168
    return max_time_in_queue


def submitter(
        once: bool = False,
        rses: Optional[list[Mapping[str, Any]]] = None,
        partition_wait_time: int = 10,
        bulk: int = 100,
        group_bulk: int = 1,
        group_policy: str = 'rule',
        source_strategy: Optional[str] = None,
        activities: Optional[list[str]] = None,
        sleep_time: int = 600,
        max_sources: int = 4,
        archive_timeout_override: Optional[int] = None,
        filter_transfertool: Optional[str] = FILTER_TRANSFERTOOL,
        transfertools: list[str] = TRANSFER_TOOLS,
        transfertype: str = TRANSFER_TYPE,
        ignore_availability: bool = False,
        executable: str = DAEMON_NAME,
        request_type: Optional[list[RequestType]] = None,
        default_lifetime: int = 172800,
        metrics: MetricManager = METRICS,
        cached_topology=None,
        total_threads: int = 1,
):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    if not request_type:
        request_type = [RequestType.TRANSFER]

    partition_hash_var = config_get('conveyor', 'partition_hash_var', default=None, raise_exception=False)

    config_schemes = set(config_get_list('conveyor', 'scheme', raise_exception=False) or [])
    config_failover_schemes = set(config_get_list('conveyor', 'failover_scheme', raise_exception=False) or [])

    schemes_supported_by_tt = set()
    for transfertool in transfertools:
        schemes_supported_by_tt.update(TRANSFERTOOL_CLASSES_BY_NAME[transfertool].supported_schemes)

    schemes = config_schemes.intersection(schemes_supported_by_tt)
    failover_schemes = config_failover_schemes.intersection(schemes_supported_by_tt)

    if config_schemes and not schemes:
        logging.critical(f'None of the configured schemes ({list(config_schemes)}) is supported '
                         f'by any configured transfertool ({transfertools}). This configuration is invalid. Aborting')
        return
    if config_failover_schemes and not failover_schemes:
        logging.critical(f'None of the configured failover schemes ({list(config_failover_schemes)}) is supported '
                         f'by any configured transfertool ({transfertools}). This configuration is invalid. Aborting')
        return
    if config_schemes.difference(schemes):
        logging.info(f'Following schemes filtered out: {list(config_schemes.difference(schemes))}')
    if config_failover_schemes.difference(failover_schemes):
        logging.info(f'Following failover schemes filtered out: {list(config_failover_schemes.difference(failover_schemes))}')

    timeout = config_get_float('conveyor', 'submit_timeout', default=None, raise_exception=False)

    bring_online = config_get_int('conveyor', 'bring_online', default=43200, raise_exception=False)

    max_time_in_queue = _get_max_time_in_queue_conf()
    logging.debug("Maximum time in queue for different activities: %s", max_time_in_queue)

    if activities:
        activities.sort()
        executable += '--activities ' + str(activities)
    if filter_transfertool:
        executable += ' --filter-transfertool ' + filter_transfertool
    if rses:
        rse_ids = [rse['id'] for rse in rses]
    else:
        rse_ids = None

    transfertool_kwargs = {
        FTS3Transfertool: {
            'group_policy': group_policy,
            'group_bulk': group_bulk,
            'source_strategy': source_strategy,
            'max_time_in_queue': max_time_in_queue,
            'bring_online': bring_online,
            'default_lifetime': default_lifetime,
            'archive_timeout_override': archive_timeout_override,
        },
        GlobusTransferTool: {
            'group_policy': transfertype,
            'group_bulk': group_bulk,
        },
    }

    @db_workqueue(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=executable,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        activities=activities)
    def _db_producer(*, activity, heartbeat_handler):
        return _fetch_requests(
            bulk=bulk,
            filter_transfertool=filter_transfertool,
            ignore_availability=ignore_availability,
            partition_hash_var=partition_hash_var,
            rse_ids=rse_ids,
            request_type=request_type,
            metrics=metrics,
            activity=activity,
            cached_topology=cached_topology,
            set_last_processed_by=not once,
            heartbeat_handler=heartbeat_handler,
        )

    def _consumer(batch):
        return _handle_requests(
            batch,
            transfertools=transfertools,
            schemes=list(schemes),
            failover_schemes=list(failover_schemes),
            max_sources=max_sources,
            timeout=timeout,
            transfertool_kwargs=transfertool_kwargs,
            metrics=metrics,
        )

    ProducerConsumerDaemon(
        producers=[_db_producer],
        consumers=[_consumer for _ in range(total_threads)],
        graceful_stop=GRACEFUL_STOP,
    ).run()


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(
        once=False,
        group_bulk=1,
        group_policy='rule',
        rses=None,
        include_rses=None,
        exclude_rses=None,
        vos=None,
        bulk=100,
        source_strategy=None,
        activities=None,
        exclude_activities=None,
        ignore_availability=False,
        sleep_time=600,
        max_sources=4,
        archive_timeout_override=None,
        total_threads=1,
        **_kwargs
):
    """
    Starts up the conveyer threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    working_rses = None
    if rses or include_rses or exclude_rses:
        working_rses = get_conveyor_rses(rses, include_rses, exclude_rses, vos)
        logging.info("RSE selection: RSEs: %s, Include: %s, Exclude: %s", rses, include_rses, exclude_rses)
    elif multi_vo:
        working_rses = get_conveyor_rses(rses, include_rses, exclude_rses, vos)
        logging.info("RSE selection: automatic for relevant VOs")
    else:
        logging.info("RSE selection: automatic")

    logging.info('starting submitter threads')

    if exclude_activities:
        if not activities:
            if not multi_vo:
                vos = ['def']
            if vos and len(vos) == 1:
                activities = get_schema_value('ACTIVITY', vos[0])
            elif vos and len(vos) > 1:
                logging.warning('Cannot get activity list from schema when multiple VOs given, either provide `activities` argument or run on a single VO')
                activities = None
            else:
                logging.warning('Cannot get activity list from schema when no VO given, either provide `activities` argument or `vos` with a single entry')
                activities = None

        if activities is not None:
            for activity in exclude_activities:
                if activity in activities:
                    activities.remove(activity)

    cached_topology = ExpiringObjectCache(ttl=300, new_obj_fnc=lambda: Topology(ignore_availability=ignore_availability))
    submitter(
        once=once,
        rses=working_rses,
        bulk=bulk,
        group_bulk=group_bulk,
        group_policy=group_policy,
        activities=activities,
        ignore_availability=ignore_availability,
        sleep_time=sleep_time,
        max_sources=max_sources,
        source_strategy=source_strategy,
        archive_timeout_override=archive_timeout_override,
        cached_topology=cached_topology,
        total_threads=total_threads,
    )
