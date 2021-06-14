# -*- coding: utf-8 -*-
# Copyright 2015-2021 CERN
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

"""
Conveyor stager is a daemon to manage stagein file transfers.
"""

from __future__ import division

import logging
import os
import socket
import threading
import time
from collections import defaultdict

from six.moves.configparser import NoOptionError

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool
from rucio.common.logging import formatted_logger, setup_logging
from rucio.core import heartbeat
from rucio.core.monitor import record_counter, record_timer
from rucio.core.request import set_requests_state
from rucio.core.staging import get_stagein_requests_and_source_replicas
from rucio.daemons.conveyor.common import submit_transfer, bulk_group_transfer, get_conveyor_rses
from rucio.db.sqla.constants import RequestState

graceful_stop = threading.Event()


def stager(once=False, rses=None, mock=False, bulk=100, group_bulk=1, group_policy='rule',
           source_strategy=None, activities=None, sleep_time=600, retry_other_fts=False):
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
    logging.debug("Maximum time in queue for different activities: %s" % max_time_in_queue)

    activity_next_exe_time = defaultdict(time.time)
    executable = 'conveyor-stager'
    if activities:
        activities.sort()
        executable += '--activities ' + str(activities)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prefix = 'conveyor-stager[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'Stager starting with bring_online %s seconds' % (bring_online))

    time.sleep(10)  # To prevent running on the same partition if all the poller restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prefix = 'conveyor-stager[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'Stager started')

    while not graceful_stop.is_set():

        try:
            heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
            prefix = 'conveyor-stager[%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
            logger = formatted_logger(logging.log, prefix + '%s')

            if activities is None:
                activities = [None]
            if rses:
                rse_ids = [rse['id'] for rse in rses]
            else:
                rse_ids = None

            for activity in activities:
                if activity_next_exe_time[activity] > time.time():
                    graceful_stop.wait(1)
                    continue

                logger(logging.INFO, 'Starting to get stagein transfers for %s' % (activity))
                start_time = time.time()
                transfers = __get_stagein_transfers(total_workers=heart_beat['nr_threads'],
                                                    worker_number=heart_beat['assign_thread'],
                                                    failover_schemes=failover_scheme,
                                                    limit=bulk,
                                                    activity=activity,
                                                    rses=rse_ids,
                                                    mock=mock,
                                                    schemes=scheme,
                                                    bring_online=bring_online,
                                                    retry_other_fts=retry_other_fts,
                                                    logger=logger)
                record_timer('daemons.conveyor.stager.get_stagein_transfers.per_transfer', (time.time() - start_time) * 1000 / (len(transfers) if transfers else 1))
                record_counter('daemons.conveyor.stager.get_stagein_transfers', len(transfers))
                record_timer('daemons.conveyor.stager.get_stagein_transfers.transfers', len(transfers))
                logger(logging.INFO, 'Got %s stagein transfers for %s' % (len(transfers), activity))

                # group transfers
                logger(logging.INFO, 'Starting to group transfers for %s' % (activity))
                start_time = time.time()
                grouped_jobs = bulk_group_transfer(transfers, group_policy, group_bulk, source_strategy, max_time_in_queue)
                record_timer('daemons.conveyor.stager.bulk_group_transfer', (time.time() - start_time) * 1000 / (len(transfers) if transfers else 1))

                logger(logging.INFO, 'Starting to submit transfers for %s' % (activity))
                # submit transfers
                for external_host in grouped_jobs:
                    for job in grouped_jobs[external_host]:
                        # submit transfers
                        submit_transfer(external_host=external_host, job=job, submitter='transfer_submitter', logger=logger)

                if len(transfers) < group_bulk:
                    logger(logging.INFO, 'Only %s transfers for %s which is less than group bulk %s, sleep %s seconds' % (len(transfers), activity, group_bulk, sleep_time))
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


def run(once=False, total_threads=1, group_bulk=1, group_policy='rule', mock=False,
        rses=None, include_rses=None, exclude_rses=None, vos=None, bulk=100, source_strategy=None,
        activities=[], sleep_time=600, retry_other_fts=False):
    """
    Starts up the conveyer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if mock:
        logging.info('mock source replicas: enabled')

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
               mock=mock,
               bulk=bulk,
               group_bulk=group_bulk,
               group_policy=group_policy,
               source_strategy=source_strategy,
               activities=activities,
               retry_other_fts=retry_other_fts)

    else:
        logging.info('starting stager threads')
        threads = [threading.Thread(target=stager, kwargs={'rses': working_rses,
                                                           'bulk': bulk,
                                                           'group_bulk': group_bulk,
                                                           'group_policy': group_policy,
                                                           'activities': activities,
                                                           'mock': mock,
                                                           'sleep_time': sleep_time,
                                                           'source_strategy': source_strategy,
                                                           'retry_other_fts': retry_other_fts}) for _ in range(0, total_threads)]

        [thread.start() for thread in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads:
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]


def __get_stagein_transfers(total_workers=0, worker_number=0, failover_schemes=None, limit=None, activity=None, older_than=None,
                            rses=None, mock=False, schemes=None, bring_online=43200, retry_other_fts=False, session=None, logger=logging.log):

    transfers, reqs_no_source = get_stagein_requests_and_source_replicas(total_workers=total_workers,
                                                                         worker_number=worker_number,
                                                                         limit=limit,
                                                                         activity=activity,
                                                                         older_than=older_than,
                                                                         rses=rses,
                                                                         mock=mock,
                                                                         schemes=schemes,
                                                                         bring_online=bring_online,
                                                                         retry_other_fts=retry_other_fts,
                                                                         failover_schemes=failover_schemes,
                                                                         session=session,
                                                                         logger=logger)

    set_requests_state(reqs_no_source, RequestState.NO_SOURCES, logger=logger)
    return transfers
