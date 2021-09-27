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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2019
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2021
# - Wen Guan <wen.guan@cern.ch>, 2014-2016
# - Tomáš Kouba <tomas.kouba@cern.ch>, 2014
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2016
# - dciangot <diego.ciangottini@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Matt Snyder <msnyder@bnl.gov>, 2019-2021
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Nick Smith <nick.smith@cern.ch>, 2020-2021
# - James Perry <j.perry@epcc.ed.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021

"""
Conveyor transfer submitter is a daemon to manage non-tape file transfers.
"""

from __future__ import division

import logging
import os
import socket
import threading
import time
from collections import defaultdict

from prometheus_client import Counter
from six.moves.configparser import NoOptionError

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.schema import get_schema_value
from rucio.core import heartbeat, transfer as transfer_core
from rucio.core.monitor import record_counter, record_timer
from rucio.daemons.conveyor.common import submit_transfer, bulk_group_transfers_for_fts, bulk_group_transfers_for_globus, get_conveyor_rses
from rucio.db.sqla.constants import RequestType

graceful_stop = threading.Event()

TRANSFER_TOOL = config_get('conveyor', 'transfertool', False, None)  # NOTE: This should eventually be completely removed, as it can be fetched from the request
FILTER_TRANSFERTOOL = config_get('conveyor', 'filter_transfertool', False, None)  # NOTE: TRANSFERTOOL to filter requests on
TRANSFER_TYPE = config_get('conveyor', 'transfertype', False, 'single')

GET_TRANSFERS_COUNTER = Counter('rucio_daemons_conveyor_submitter_get_transfers', 'Number of transfers retrieved')


def submitter(once=False, rses=None, partition_wait_time=10,
              bulk=100, group_bulk=1, group_policy='rule', source_strategy=None,
              activities=None, sleep_time=600, max_sources=4, retry_other_fts=False, archive_timeout_override=None,
              filter_transfertool=FILTER_TRANSFERTOOL, transfertool=TRANSFER_TOOL, transfertype=TRANSFER_TYPE):
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
        timeout = config_get('conveyor', 'submit_timeout')
        timeout = float(timeout)
    except NoOptionError:
        timeout = None

    try:
        bring_online = config_get('conveyor', 'bring_online')
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

    activity_next_exe_time = defaultdict(time.time)
    executable = "conveyor-submitter"
    if activities:
        activities.sort()
        executable += '--activities ' + str(activities)
    if filter_transfertool:
        executable += ' --filter-transfertool ' + filter_transfertool

    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prefix = 'conveyor-submitter[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'Submitter starting with timeout %s', timeout)

    if partition_wait_time:
        time.sleep(partition_wait_time)  # To prevent running on the same partition if all the poller restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prefix = 'conveyor-submitter[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'Transfer submitter started')

    while not graceful_stop.is_set():
        if activities is None:
            activities = [None]
        if rses:
            rse_ids = [rse['id'] for rse in rses]
        else:
            rse_ids = None
        for activity in activities:
            try:
                if activity_next_exe_time[activity] > time.time():
                    graceful_stop.wait(1)
                    continue

                heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
                prefix = 'conveyor-submitter[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
                logger = formatted_logger(logging.log, prefix + '%s')

                logger(logging.INFO, 'Starting to get transfer transfers for %s', activity)
                start_time = time.time()

                transfers = transfer_core.next_transfers_to_submit(
                    total_workers=heart_beat['nr_threads'],
                    worker_number=heart_beat['assign_thread'],
                    failover_schemes=failover_scheme,
                    limit=bulk,
                    activity=activity,
                    rses=rse_ids,
                    schemes=scheme,
                    retry_other_fts=retry_other_fts,
                    transfertool=filter_transfertool,
                    older_than=None,
                    request_type=RequestType.TRANSFER,
                    logger=logger,
                )
                total_transfers = len(list(hop for paths in transfers.values() for path in paths for hop in path))

                record_timer('daemons.conveyor.transfer_submitter.get_transfers.per_transfer', (time.time() - start_time) * 1000 / (total_transfers or 1))
                record_counter('daemons.conveyor.transfer_submitter.get_transfers', total_transfers)
                GET_TRANSFERS_COUNTER.inc(total_transfers)
                record_timer('daemons.conveyor.transfer_submitter.get_transfers.transfers', total_transfers)
                logger(logging.INFO, 'Got %s transfers for %s in %s seconds', total_transfers, activity, time.time() - start_time)

                grouped_jobs = {}
                for external_host, transfer_paths in transfers.items():
                    start_time = time.time()
                    logger(logging.INFO, 'Starting to group transfers for %s (%s)', activity, external_host)
                    for transfer_path in transfer_paths:
                        for i, hop in enumerate(transfer_path):
                            hop.init_legacy_transfer_definition(bring_online=bring_online, default_lifetime=172800, logger=logger)
                            if len(transfer_path) > 1:
                                hop['multihop'] = True
                                hop['initial_request_id'] = transfer_path[-1].rws.request_id
                                hop['parent_request'] = transfer_path[i - 1].rws.request_id if i > 0 else None
                    if transfertool in ['fts3', 'mock']:
                        grouped_jobs = bulk_group_transfers_for_fts(transfer_paths, group_policy, group_bulk, source_strategy, max_time_in_queue, archive_timeout_override=archive_timeout_override)
                    elif transfertool == 'globus':
                        grouped_jobs = bulk_group_transfers_for_globus(transfer_paths, transfertype, group_bulk)
                    else:
                        logger(logging.ERROR, 'Unknown transfer tool')
                    record_timer('daemons.conveyor.transfer_submitter.bulk_group_transfer', (time.time() - start_time) * 1000 / (len(transfer_paths) or 1))

                    logger(logging.INFO, 'Starting to submit transfers for %s (%s)', activity, external_host)
                    for job in grouped_jobs:
                        logger(logging.DEBUG, 'submitjob: %s' % job)
                        submit_transfer(external_host=external_host, job=job, submitter='transfer_submitter',
                                        timeout=timeout, logger=logger, transfertool=transfertool)

                if total_transfers < group_bulk:
                    logger(logging.INFO, 'Only %s transfers for %s which is less than group bulk %s, sleep %s seconds', total_transfers, activity, group_bulk, sleep_time)
                    if activity_next_exe_time[activity] < time.time():
                        activity_next_exe_time[activity] = time.time() + sleep_time
            except Exception:
                logger(logging.CRITICAL, 'Exception', exc_info=True)

        if once:
            break

    logger(logging.INFO, 'Graceful stop requested')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logger(logging.INFO, 'Graceful stop done')
    return


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, group_bulk=1, group_policy='rule', mock=False,
        rses=None, include_rses=None, exclude_rses=None, vos=None, bulk=100, source_strategy=None,
        activities=None, exclude_activities=None, sleep_time=600, max_sources=4, retry_other_fts=False,
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
                                                          'sleep_time': sleep_time,
                                                          'max_sources': max_sources,
                                                          'source_strategy': source_strategy,
                                                          'retry_other_fts': retry_other_fts,
                                                          'archive_timeout_override': archive_timeout_override}) for _ in range(0, total_threads)]

    [thread.start() for thread in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads:
        threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]
