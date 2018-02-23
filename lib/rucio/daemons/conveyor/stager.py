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

"""
Conveyor stager is a daemon to manage stagein file transfers.
"""

import logging
import os
import socket
import sys
import threading
import time
import traceback

from collections import defaultdict
from ConfigParser import NoOptionError
from threadpool import ThreadPool, makeRequests

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


def stager(once=False, rses=[], mock=False,
           process=0, total_processes=1, thread=0, total_threads=1,
           bulk=100, group_bulk=1, group_policy='rule', fts_source_strategy='auto',
           activities=None, sleep_time=600, retry_other_fts=False):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    logging.info('Stager starting - process (%i/%i) thread (%i)' % (process,
                                                                    total_processes,
                                                                    total_threads))

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

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb = heartbeat.live(executable, hostname, pid, hb_thread)

    logging.info('Stager started - process (%i/%i) thread (%i/%i)' % (process, total_processes,
                                                                      hb['assign_thread'], hb['nr_threads']))

    threadPool = ThreadPool(total_threads)
    activity_next_exe_time = defaultdict(time.time)

    while not graceful_stop.is_set():

        try:
            hb = heartbeat.live(executable, hostname, pid, hb_thread)

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

                logging.info("%s:%s Starting to get stagein transfers for %s" % (process, hb['assign_thread'], activity))
                ts = time.time()
                transfers = __get_stagein_transfers(process=process,
                                                    total_processes=total_processes,
                                                    thread=hb['assign_thread'],
                                                    total_threads=hb['nr_threads'],
                                                    failover_schemes=failover_scheme,
                                                    limit=bulk,
                                                    activity=activity,
                                                    rses=rse_ids,
                                                    mock=mock,
                                                    schemes=scheme,
                                                    bring_online=bring_online,
                                                    retry_other_fts=retry_other_fts)
                record_timer('daemons.conveyor.stager.get_stagein_transfers.per_transfer', (time.time() - ts) * 1000 / (len(transfers) if len(transfers) else 1))
                record_counter('daemons.conveyor.stager.get_stagein_transfers', len(transfers))
                record_timer('daemons.conveyor.stager.get_stagein_transfers.transfers', len(transfers))
                logging.info("%s:%s Got %s stagein transfers for %s" % (process, hb['assign_thread'], len(transfers), activity))

                # group transfers
                logging.info("%s:%s Starting to group transfers for %s" % (process, hb['assign_thread'], activity))
                ts = time.time()
                grouped_jobs = bulk_group_transfer(transfers, group_policy, group_bulk, fts_source_strategy, max_time_in_queue)
                record_timer('daemons.conveyor.stager.bulk_group_transfer', (time.time() - ts) * 1000 / (len(transfers) if len(transfers) else 1))

                logging.info("%s:%s Starting to submit transfers for %s" % (process, hb['assign_thread'], activity))
                # submit transfers
                for external_host in grouped_jobs:
                    for job in grouped_jobs[external_host]:
                        # submit transfers
                        # job_requests = makeRequests(submit_transfer, args_list=[((external_host, job, 'transfer_submitter', process, thread), {})])
                        job_requests = makeRequests(submit_transfer, args_list=[((), {'external_host': external_host, 'job': job, 'submitter': 'transfer_submitter', 'process': process, 'thread': hb['assign_thread']})])
                        [threadPool.putRequest(job_req) for job_req in job_requests]
                threadPool.wait()

                if len(transfers) < group_bulk:
                    logging.info('%i:%i - only %s transfers for %s which is less than group bulk %s, sleep %s seconds' % (process, hb['assign_thread'], len(transfers), activity, group_bulk, sleep_time))
                    if activity_next_exe_time[activity] < time.time():
                        activity_next_exe_time[activity] = time.time() + sleep_time
        except:
            logging.critical('%s:%s %s' % (process, hb['assign_thread'], traceback.format_exc()))

        if once:
            break

    logging.info('%s:%s graceful stop requested' % (process, hb['assign_thread']))

    threadPool.dismissWorkers(total_threads, do_join=True)
    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('%s:%s graceful stop done' % (process, hb['assign_thread']))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False,
        process=0, total_processes=1, total_threads=1, group_bulk=1, group_policy='rule',
        mock=False, rses=[], include_rses=None, exclude_rses=None, bulk=100, fts_source_strategy='auto',
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
               fts_source_strategy=fts_source_strategy,
               activities=activities,
               retry_other_fts=retry_other_fts)

    else:
        logging.info('starting stager threads')
        threads = [threading.Thread(target=stager, kwargs={'process': process,
                                                           'total_processes': total_processes,
                                                           'total_threads': total_threads,
                                                           'rses': working_rses,
                                                           'bulk': bulk,
                                                           'group_bulk': group_bulk,
                                                           'group_policy': group_policy,
                                                           'activities': activities,
                                                           'mock': mock,
                                                           'sleep_time': sleep_time,
                                                           'fts_source_strategy': fts_source_strategy,
                                                           'retry_other_fts': retry_other_fts})]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            threads = [t.join(timeout=3.14) for t in threads if t and t.isAlive()]


def __get_stagein_transfers(process=None, total_processes=None, thread=None, total_threads=None, failover_schemes=None,
                            limit=None, activity=None, older_than=None, rses=None, mock=False, schemes=None, bring_online=43200,
                            retry_other_fts=False, session=None):

    transfers, reqs_no_source = get_stagein_requests_and_source_replicas(process=process,
                                                                         total_processes=total_processes,
                                                                         thread=thread,
                                                                         total_threads=total_threads,
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
