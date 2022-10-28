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

from configparser import NoOptionError

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int, config_get_list
from rucio.common.logging import setup_logging
from rucio.common.schema import get_schema_value
from rucio.core.monitor import MultiCounter, record_timer, Timer
from rucio.core.transfer import transfer_path_str
from rucio.daemons.conveyor.common import submit_transfer, get_conveyor_rses, next_transfers_to_submit
from rucio.daemons.common import run_daemon
from rucio.db.sqla.constants import RequestType
from rucio.transfertool.fts3 import FTS3Transfertool
from rucio.transfertool.globus import GlobusTransferTool

graceful_stop = threading.Event()

TRANSFER_TOOLS = config_get_list('conveyor', 'transfertool', False, None)  # NOTE: This should eventually be completely removed, as it can be fetched from the request
FILTER_TRANSFERTOOL = config_get('conveyor', 'filter_transfertool', False, None)  # NOTE: TRANSFERTOOL to filter requests on
TRANSFER_TYPE = config_get('conveyor', 'transfertype', False, 'single')

GET_TRANSFERS_COUNTER = MultiCounter(prom='rucio_daemons_conveyor_submitter_get_transfers', statsd='daemons.conveyor.transfer_submitter.get_transfers',
                                     documentation='Number of transfers retrieved')


def run_once(bulk, group_bulk, filter_transfertool, transfertools, ignore_availability, rse_ids,
             scheme, failover_scheme, partition_hash_var, timeout, transfertool_kwargs,
             heartbeat_handler, activity):
    worker_number, total_workers, logger = heartbeat_handler.live()

    timer = Timer()
    transfers = next_transfers_to_submit(
        total_workers=total_workers,
        worker_number=worker_number,
        partition_hash_var=partition_hash_var,
        failover_schemes=failover_scheme,
        limit=bulk,
        activity=activity,
        rses=rse_ids,
        schemes=scheme,
        filter_transfertool=filter_transfertool,
        transfertools=transfertools,
        older_than=None,
        request_type=[RequestType.TRANSFER],
        ignore_availability=ignore_availability,
        logger=logger,
    )
    total_transfers = len(list(hop for paths in transfers.values() for path in paths for hop in path))

    timer.record('daemons.conveyor.transfer_submitter.get_transfers.per_transfer', divisor=total_transfers or 1)
    GET_TRANSFERS_COUNTER.inc(total_transfers)
    record_timer('daemons.conveyor.transfer_submitter.get_transfers.transfers', total_transfers)
    logger(logging.INFO, 'Got %s transfers for %s in %s seconds', total_transfers, activity, timer.elapsed)

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
        timer = Timer()
        logger(logging.DEBUG, 'Starting to group transfers for %s (%s)', activity, transfertool_obj)
        grouped_jobs = transfertool_obj.group_into_submit_jobs(transfer_paths)
        timer.record('daemons.conveyor.transfer_submitter.bulk_group_transfer', divisor=len(transfer_paths) or 1)

        logger(logging.DEBUG, 'Starting to submit transfers for %s (%s)', activity, transfertool_obj)
        for job in grouped_jobs:
            worker_number, total_workers, logger = heartbeat_handler.live()
            logger(logging.DEBUG, 'submitjob: transfers=%s, job_params=%s' % ([str(t) for t in job['transfers']], job['job_params']))
            submit_transfer(transfertool_obj=transfertool_obj, transfers=job['transfers'], job_params=job['job_params'], submitter='transfer_submitter',
                            timeout=timeout, logger=logger)

    queue_empty = False
    if total_transfers < group_bulk:
        queue_empty = True
        logger(logging.DEBUG, 'Only %s transfers for %s which is less than group bulk %s', total_transfers, activity, group_bulk)
    return queue_empty


def submitter(once=False, rses=None, partition_wait_time=10,
              bulk=100, group_bulk=1, group_policy='rule', source_strategy=None,
              activities=None, sleep_time=600, max_sources=4, archive_timeout_override=None,
              filter_transfertool=FILTER_TRANSFERTOOL, transfertools=TRANSFER_TOOLS,
              transfertype=TRANSFER_TYPE, ignore_availability=False):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    try:
        partition_hash_var = config_get('conveyor', 'partition_hash_var')
    except NoOptionError:
        partition_hash_var = None
    try:
        scheme = config_get('conveyor', 'scheme')
    except NoOptionError:
        scheme = None
    try:
        failover_scheme = config_get('conveyor', 'failover_scheme')
    except NoOptionError:
        failover_scheme = None
    try:
        timeout = config_get('conveyor', 'submit_timeout')
        timeout = float(timeout)
    except NoOptionError:
        timeout = None

    try:
        bring_online = config_get_int('conveyor', 'bring_online')
    except NoOptionError:
        bring_online = 43200

    try:
        max_time_in_queue = {}
        timelife_conf = config_get('conveyor', 'max_time_in_queue')
        timelife_confs = timelife_conf.split(",")
        for conf in timelife_confs:
            act, timelife = conf.split(":")
            max_time_in_queue[act.strip()] = int(timelife.strip())
    except NoOptionError:
        max_time_in_queue = {}

    if 'default' not in max_time_in_queue:
        max_time_in_queue['default'] = 168
    logging.debug("Maximum time in queue for different activities: %s", max_time_in_queue)

    logger_prefix = executable = "conveyor-submitter"
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
            'default_lifetime': 172800,
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
            partition_hash_var=partition_hash_var,
            rse_ids=rse_ids,
            timeout=timeout,
            transfertool_kwargs=transfertool_kwargs,
        ),
        activities=activities,
    )


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, group_bulk=1, group_policy='rule', mock=False,
        rses=None, include_rses=None, exclude_rses=None, vos=None, bulk=100, source_strategy=None,
        activities=None, exclude_activities=None, ignore_availability=False, sleep_time=600, max_sources=4,
        archive_timeout_override=None, total_threads=1):
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
                                                          'archive_timeout_override': archive_timeout_override}) for _ in range(0, total_threads)]

    [thread.start() for thread in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads:
        threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]
