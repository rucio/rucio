# Copyright 2015-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Wen Guan <wguan.icedew@gmail.com>, 2015-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2017
# - Vincent Garonne <vgaronne@gmail.com>, 2016-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

"""
Conveyor stager is a daemon to manage stagein file transfers.
"""

from __future__ import division

import logging
import os
import socket
import sys
import threading
import time
import traceback

from collections import defaultdict
try:
    from ConfigParser import NoOptionError  # py2
except Exception:
    from configparser import NoOptionError  # py3

from rucio.common.config import config_get
from rucio.core import heartbeat
from rucio.core.monitor import record_counter, record_timer
from rucio.core.request import set_requests_state
from rucio.core.staging import get_stagein_requests_and_source_replicas
from rucio.daemons.conveyor.common import submit_transfer, bulk_group_transfer, get_conveyor_rses
from rucio.db.sqla.constants import RequestState

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

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
    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
    logging.info(prepend_str + 'Stager starting with bring_online %s seconds' % (bring_online))

    time.sleep(10)  # To prevent running on the same partition if all the poller restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
    logging.info(prepend_str + 'Stager started')

    while not graceful_stop.is_set():

        try:
            heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
            prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])

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

                logging.info(prepend_str + 'Starting to get stagein transfers for %s' % (activity))
                start_time = time.time()
                transfers = __get_stagein_transfers(total_workers=heart_beat['nr_threads'] - 1,
                                                    worker_number=heart_beat['assign_thread'],
                                                    failover_schemes=failover_scheme,
                                                    limit=bulk,
                                                    activity=activity,
                                                    rses=rse_ids,
                                                    mock=mock,
                                                    schemes=scheme,
                                                    bring_online=bring_online,
                                                    retry_other_fts=retry_other_fts)
                record_timer('daemons.conveyor.stager.get_stagein_transfers.per_transfer', (time.time() - start_time) * 1000 / (len(transfers) if transfers else 1))
                record_counter('daemons.conveyor.stager.get_stagein_transfers', len(transfers))
                record_timer('daemons.conveyor.stager.get_stagein_transfers.transfers', len(transfers))
                logging.info(prepend_str + 'Got %s stagein transfers for %s' % (len(transfers), activity))

                # group transfers
                logging.info(prepend_str + 'Starting to group transfers for %s' % (activity))
                start_time = time.time()
                grouped_jobs = bulk_group_transfer(transfers, group_policy, group_bulk, source_strategy, max_time_in_queue)
                record_timer('daemons.conveyor.stager.bulk_group_transfer', (time.time() - start_time) * 1000 / (len(transfers) if transfers else 1))

                logging.info(prepend_str + 'Starting to submit transfers for %s' % (activity))
                # submit transfers
                for external_host in grouped_jobs:
                    for job in grouped_jobs[external_host]:
                        # submit transfers
                        submit_transfer(external_host=external_host, job=job, submitter='transfer_submitter', logging_prepend_str=prepend_str)

                if len(transfers) < group_bulk:
                    logging.info(prepend_str + 'Only %s transfers for %s which is less than group bulk %s, sleep %s seconds' % (len(transfers), activity, group_bulk, sleep_time))
                    if activity_next_exe_time[activity] < time.time():
                        activity_next_exe_time[activity] = time.time() + sleep_time
        except Exception:
            logging.critical(prepend_str + '%s' % (traceback.format_exc()))

        if once:
            break

    logging.info(prepend_str + 'Graceful stop requested')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info(prepend_str + 'Graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, total_threads=1, group_bulk=1, group_policy='rule',
        mock=False, rses=None, include_rses=None, exclude_rses=None, bulk=100, source_strategy=None,
        activities=[], sleep_time=600, retry_other_fts=False):
    """
    Starts up the conveyer threads.
    """

    if mock:
        logging.info('mock source replicas: enabled')

    working_rses = None
    if rses or include_rses or exclude_rses:
        working_rses = get_conveyor_rses(rses, include_rses, exclude_rses)
        logging.info("RSE selection: RSEs: %s, Include: %s, Exclude: %s" % (rses,
                                                                            include_rses,
                                                                            exclude_rses))
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
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.isAlive()]


def __get_stagein_transfers(total_workers=0, worker_number=0, failover_schemes=None, limit=None, activity=None, older_than=None,
                            rses=None, mock=False, schemes=None, bring_online=43200, retry_other_fts=False, session=None):

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
                                                                         session=session)

    set_requests_state(reqs_no_source, RequestState.NO_SOURCES)
    return transfers
