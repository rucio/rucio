# -*- coding: utf-8 -*-
# Copyright 2015-2022 CERN
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
# - Wen Guan <wen.guan@cern.ch>, 2015-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2017
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017-2021
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022

"""
Conveyor stager is a daemon to manage stagein file transfers.
"""

from __future__ import division

import functools
import logging
import threading
import time

from six.moves.configparser import NoOptionError

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.logging import setup_logging
from rucio.core.monitor import record_counter, record_timer
from rucio.core import transfer as transfer_core
from rucio.daemons.conveyor.common import submit_transfer, get_conveyor_rses, run_conveyor_daemon
from rucio.db.sqla.constants import RequestType
from rucio.transfertool.fts3 import FTS3Transfertool

graceful_stop = threading.Event()


def run_once(bulk, group_bulk, rse_ids, scheme, failover_scheme, transfertool_kwargs, total_workers, worker_number, logger, activity):
    start_time = time.time()
    transfers = transfer_core.next_transfers_to_submit(
        total_workers=total_workers,
        worker_number=worker_number,
        failover_schemes=failover_scheme,
        limit=bulk,
        activity=activity,
        rses=rse_ids,
        schemes=scheme,
        transfertools_by_name={'fts3': FTS3Transfertool},
        older_than=None,
        request_type=RequestType.STAGEIN,
        logger=logger,
    )
    total_transfers = len(list(hop for paths in transfers.values() for path in paths for hop in path))
    record_timer('daemons.conveyor.stager.get_stagein_transfers.per_transfer', (time.time() - start_time) * 1000 / (total_transfers if transfers else 1))
    record_counter('daemons.conveyor.stager.get_stagein_transfers', total_transfers)
    record_timer('daemons.conveyor.stager.get_stagein_transfers.transfers', total_transfers)
    logger(logging.INFO, 'Got %s stagein transfers for %s' % (total_transfers, activity))

    for builder, transfer_paths in transfers.items():
        transfertool_obj = builder.make_transfertool(logger=logger, **transfertool_kwargs.get(builder.transfertool_class, {}))
        logger(logging.INFO, 'Starting to group transfers for %s (%s)' % (activity, transfertool_obj))
        start_time = time.time()
        grouped_jobs = transfertool_obj.group_into_submit_jobs(transfer_paths)
        record_timer('daemons.conveyor.stager.bulk_group_transfer', (time.time() - start_time) * 1000 / (len(transfer_paths) or 1))

        logger(logging.INFO, 'Starting to submit transfers for %s (%s)' % (activity, transfertool_obj))
        for job in grouped_jobs:
            submit_transfer(transfertool_obj=transfertool_obj, transfers=job['transfers'], job_params=job['job_params'], submitter='transfer_submitter', logger=logger)

    queue_empty = False
    if total_transfers < group_bulk:
        queue_empty = True
        logger(logging.INFO, 'Only %s transfers for %s which is less than group bulk %s' % (total_transfers, activity, group_bulk))
    return queue_empty


def stager(once=False, rses=None, bulk=100, group_bulk=1, group_policy='rule',
           source_strategy=None, activities=None, sleep_time=600):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    try:
        scheme = config_get('conveyor', 'scheme')
    except NoOptionError:
        scheme = None

    try:
        failover_scheme = config_get('conveyor', 'failover_scheme')
    except NoOptionError:
        failover_scheme = None

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
    logging.debug("Maximum time in queue for different activities: %s" % max_time_in_queue)

    logger_prefix = executable = 'conveyor-stager'
    if activities:
        activities.sort()
        executable += '--activities ' + str(activities)

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
            'default_lifetime': -1,
        }
    }

    run_conveyor_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        logger_prefix=logger_prefix,
        partition_wait_time=None,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            bulk=bulk,
            group_bulk=group_bulk,
            scheme=scheme,
            failover_scheme=failover_scheme,
            rse_ids=rse_ids,
            transfertool_kwargs=transfertool_kwargs,
        ),
        activities=activities,
        heart_beat_older_than=None,
    )


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, total_threads=1, group_bulk=1, group_policy='rule',
        rses=None, include_rses=None, exclude_rses=None, vos=None, bulk=100, source_strategy=None,
        activities=[], sleep_time=600):
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
        logging.info("RSE selection: RSEs: %s, Include: %s, Exclude: %s" % (rses,
                                                                            include_rses,
                                                                            exclude_rses))
    elif multi_vo:
        working_rses = get_conveyor_rses(rses, include_rses, exclude_rses, vos)
        logging.info("RSE selection: automatic for relevant VOs")
    else:
        logging.info("RSE selection: automatic")

    if once:
        logging.info('executing one stager iteration only')
        stager(once,
               rses=working_rses,
               bulk=bulk,
               group_bulk=group_bulk,
               group_policy=group_policy,
               source_strategy=source_strategy,
               activities=activities)

    else:
        logging.info('starting stager threads')
        threads = [threading.Thread(target=stager, kwargs={'rses': working_rses,
                                                           'bulk': bulk,
                                                           'group_bulk': group_bulk,
                                                           'group_policy': group_policy,
                                                           'activities': activities,
                                                           'sleep_time': sleep_time,
                                                           'source_strategy': source_strategy}) for _ in range(0, total_threads)]

        [thread.start() for thread in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads:
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]
