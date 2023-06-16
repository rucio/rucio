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

import functools
import logging
import threading
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Mapping

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int, config_get_list, config_get_float
from rucio.common.logging import setup_logging
from rucio.common.schema import get_schema_value
from rucio.common.stopwatch import Stopwatch
from rucio.core.monitor import MetricManager
from rucio.core.request import list_transfer_requests_and_source_replicas
from rucio.core.topology import Topology, ExpiringObjectCache
from rucio.core.transfer import DEFAULT_MULTIHOP_TOMBSTONE_DELAY, list_transfer_admin_accounts, transfer_path_str,\
    TRANSFERTOOL_CLASSES_BY_NAME, ProtocolFactory
from rucio.daemons.conveyor.common import submit_transfer, get_conveyor_rses, pick_and_prepare_submission_path
from rucio.daemons.common import run_daemon
from rucio.db.sqla.constants import RequestType, RequestState
from rucio.transfertool.fts3 import FTS3Transfertool
from rucio.transfertool.globus import GlobusTransferTool

if TYPE_CHECKING:
    from types import FrameType

METRICS = MetricManager(module=__name__)
graceful_stop = threading.Event()

TRANSFER_TOOLS = config_get_list('conveyor', 'transfertool', False, None)  # NOTE: This should eventually be completely removed, as it can be fetched from the request
FILTER_TRANSFERTOOL = config_get('conveyor', 'filter_transfertool', False, None)  # NOTE: TRANSFERTOOL to filter requests on
TRANSFER_TYPE = config_get('conveyor', 'transfertype', False, 'single')


def run_once(bulk, group_bulk, filter_transfertool, transfertools, ignore_availability, rse_ids,
             scheme, failover_scheme, max_sources, partition_hash_var, timeout, transfertool_kwargs,
             heartbeat_handler, activity, request_type, metrics, cached_topology):
    worker_number, total_workers, logger = heartbeat_handler.live()

    topology = cached_topology.get() if cached_topology else Topology(ignore_availability=ignore_availability)
    topology.configure_multihop(logger=logger)
    protocol_factory = ProtocolFactory()
    default_tombstone_delay = config_get_int('transfers', 'multihop_tombstone_delay', default=DEFAULT_MULTIHOP_TOMBSTONE_DELAY, expiration_time=600)

    admin_accounts = list_transfer_admin_accounts()
    stopwatch = Stopwatch()

    required_source_rse_attrs = None
    # if filter_transfertool specified, select only the source rses which are configured for this transfertool
    if filter_transfertool:
        # if multihop is configured, we want all possible source rses. To allow multi-hopping between transfertools
        if not topology.multihop_enabled:
            required_source_rse_attrs = TRANSFERTOOL_CLASSES_BY_NAME[filter_transfertool].required_rse_attrs

    # retrieve (from the database) the transfer requests with their possible source replicas
    requests_with_sources = list_transfer_requests_and_source_replicas(
        rse_collection=topology,
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

    transfers = pick_and_prepare_submission_path(
        requests_with_sources=requests_with_sources,
        topology=topology,
        protocol_factory=protocol_factory,
        default_tombstone_delay=default_tombstone_delay,
        admin_accounts=admin_accounts,
        failover_schemes=failover_scheme,
        schemes=scheme,
        max_sources=max_sources,
        transfertools=transfertools,
        logger=logger,
    )

    stopwatch.stop()
    total_transfers = len(list(hop for paths in transfers.values() for path in paths for hop in path))

    metrics.timer('get_transfers.time_per_transfer').observe(stopwatch.elapsed / (total_transfers or 1))
    metrics.counter('get_transfers.total_transfers').inc(total_transfers)
    logger(logging.INFO, 'Got %s transfers for %s in %s seconds', total_transfers, activity, stopwatch.elapsed)

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
        logger(logging.DEBUG, 'Starting to group transfers for %s (%s)', activity, transfertool_obj)
        stopwatch.restart()
        grouped_jobs = transfertool_obj.group_into_submit_jobs(transfer_paths)
        metrics.timer('bulk_group_transfer').observe(stopwatch.elapsed / (len(transfer_paths) or 1))

        logger(logging.DEBUG, 'Starting to submit transfers for %s (%s)', activity, transfertool_obj)
        for job in grouped_jobs:
            worker_number, total_workers, logger = heartbeat_handler.live()
            logger(logging.DEBUG, 'submitjob: transfers=%s, job_params=%s' % ([str(t) for t in job['transfers']], job['job_params']))
            submit_transfer(transfertool_obj=transfertool_obj, transfers=job['transfers'], job_params=job['job_params'],
                            timeout=timeout, logger=logger)

    queue_empty = False
    if total_transfers < group_bulk:
        queue_empty = True
        logger(logging.DEBUG, 'Only %s transfers for %s which is less than group bulk %s', total_transfers, activity, group_bulk)
    return queue_empty


def _get_max_time_in_queue_conf() -> "Dict[str, int]":
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
        rses: Optional[List[Mapping[str, Any]]] = None,
        partition_wait_time: int = 10,
        bulk: int = 100,
        group_bulk: int = 1,
        group_policy: str = 'rule',
        source_strategy: Optional[str] = None,
        activities: Optional[List[str]] = None,
        sleep_time: int = 600,
        max_sources: int = 4,
        archive_timeout_override: Optional[int] = None,
        filter_transfertool: Optional[str] = FILTER_TRANSFERTOOL,
        transfertools: List[str] = TRANSFER_TOOLS,
        transfertype: str = TRANSFER_TYPE,
        ignore_availability: bool = False,
        executable: str = 'conveyor-submitter',
        request_type: Optional[List[RequestType]] = None,
        default_lifetime: int = 172800,
        metrics: MetricManager = METRICS,
        cached_topology=None,
):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    if not request_type:
        request_type = [RequestType.TRANSFER]

    partition_hash_var = config_get('conveyor', 'partition_hash_var', default=None, raise_exception=False)

    scheme = config_get('conveyor', 'scheme', default=None, raise_exception=False)
    failover_scheme = config_get('conveyor', 'failover_scheme', default=None, raise_exception=False)

    timeout = config_get_float('conveyor', 'submit_timeout', default=None, raise_exception=False)

    bring_online = config_get_int('conveyor', 'bring_online', default=43200, raise_exception=False)

    max_time_in_queue = _get_max_time_in_queue_conf()
    logging.debug("Maximum time in queue for different activities: %s", max_time_in_queue)

    logger_prefix = executable
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

    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        logger_prefix=logger_prefix,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            bulk=bulk,
            group_bulk=group_bulk,
            filter_transfertool=filter_transfertool,
            transfertools=transfertools,
            ignore_availability=ignore_availability,
            scheme=scheme,
            failover_scheme=failover_scheme,
            max_sources=max_sources,
            partition_hash_var=partition_hash_var,
            rse_ids=rse_ids,
            timeout=timeout,
            transfertool_kwargs=transfertool_kwargs,
            request_type=request_type,
            metrics=metrics,
            cached_topology=cached_topology,
        ),
        activities=activities,
    )


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, group_bulk=1, group_policy='rule',
        rses=None, include_rses=None, exclude_rses=None, vos=None, bulk=100, source_strategy=None,
        activities=None, exclude_activities=None, ignore_availability=False, sleep_time=600, max_sources=4,
        archive_timeout_override=None, total_threads=1, **_kwargs):
    """
    Starts up the conveyer threads.
    """
    setup_logging()

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
                activities = [None]
            else:
                logging.warning('Cannot get activity list from schema when no VO given, either provide `activities` argument or `vos` with a single entry')
                activities = [None]

        for activity in exclude_activities:
            if activity in activities:
                activities.remove(activity)

    cached_topology = ExpiringObjectCache(ttl=300, new_obj_fnc=lambda: Topology(ignore_availability=ignore_availability))
    threads = [threading.Thread(target=submitter, kwargs={'once': once,
                                                          'rses': working_rses,
                                                          'bulk': bulk,
                                                          'group_bulk': group_bulk,
                                                          'group_policy': group_policy,
                                                          'activities': activities,
                                                          'ignore_availability': ignore_availability,
                                                          'sleep_time': sleep_time,
                                                          'max_sources': max_sources,
                                                          'source_strategy': source_strategy,
                                                          'archive_timeout_override': archive_timeout_override,
                                                          'cached_topology': cached_topology}) for _ in range(0, total_threads)]

    [thread.start() for thread in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads:
        threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]
