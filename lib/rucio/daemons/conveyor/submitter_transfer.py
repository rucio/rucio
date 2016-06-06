# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015
# - Wen Guan, <wen.guan@cern.ch>, 2014-2015

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

from rucio.daemons.conveyor.submitter_utils import get_rses, get_transfer_transfers, bulk_group_transfer, submit_transfer, schedule_requests

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def submitter(once=False, rses=[], mock=False,
              process=0, total_processes=1, total_threads=1,
              bulk=100, group_bulk=1, group_policy='rule', fts_source_strategy='auto',
              activities=None, sleep_time=600, max_sources=4, retry_other_fts=False):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    logging.info('Transfer submitter starting - process (%i/%i) threads (%i)' % (process,
                                                                                 total_processes,
                                                                                 total_threads))

    try:
        scheme = config_get('conveyor', 'scheme')
    except NoOptionError:
        scheme = None
    try:
        cachedir = config_get('conveyor', 'cachedir')
    except NoOptionError:
        cachedir = None
    try:
        timeout = config_get('conveyor', 'submit_timeout')
        timeout = float(timeout)
    except NoOptionError:
        timeout = None

    try:
        bring_online = config_get('conveyor', 'bring_online')
    except NoOptionError:
        bring_online = 43200

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb = heartbeat.live(executable, hostname, pid, hb_thread)

    logging.info('Transfer submitter started - process (%i/%i) threads (%i/%i) timeout (%s)' % (process, total_processes,
                                                                                                hb['assign_thread'], hb['nr_threads'],
                                                                                                timeout))

    threadPool = ThreadPool(total_threads)
    activity_next_exe_time = defaultdict(time.time)
    sleeping = False

    while not graceful_stop.is_set():

        try:

            if not sleeping:
                hb = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
                logging.info('Transfer submitter - thread (%i/%i) bulk(%i)' % (hb['assign_thread'], hb['nr_threads'], bulk))

                sleeping = True

            if activities is None:
                activities = [None]
            if rses:
                rse_ids = [rse['id'] for rse in rses]
            else:
                rse_ids = None

            for activity in activities:
                if activity_next_exe_time[activity] > time.time():
                    time.sleep(1)
                    continue
                sleeping = False

                logging.info("%s:%s Starting to get transfer transfers for %s" % (process, hb['assign_thread'], activity))
                ts = time.time()
                transfers = get_transfer_transfers(process=process, total_processes=total_processes, thread=hb['assign_thread'], total_threads=hb['nr_threads'],
                                                   limit=bulk, activity=activity, rses=rse_ids, schemes=scheme, mock=mock, max_sources=max_sources, bring_online=bring_online, retry_other_fts=retry_other_fts)
                record_timer('daemons.conveyor.transfer_submitter.get_transfer_transfers.per_transfer', (time.time() - ts) * 1000 / (len(transfers) if len(transfers) else 1))
                record_counter('daemons.conveyor.transfer_submitter.get_transfer_transfers', len(transfers))
                record_timer('daemons.conveyor.transfer_submitter.get_transfer_transfers.transfers', len(transfers))
                logging.info("%s:%s Got %s transfers for %s" % (process, hb['assign_thread'], len(transfers), activity))

                # group transfers
                logging.info("%s:%s Starting to group transfers for %s" % (process, hb['assign_thread'], activity))
                ts = time.time()
                grouped_jobs = bulk_group_transfer(transfers, group_policy, group_bulk, fts_source_strategy)
                record_timer('daemons.conveyor.transfer_submitter.bulk_group_transfer', (time.time() - ts) * 1000 / (len(transfers) if len(transfers) else 1))

                logging.info("%s:%s Starting to submit transfers for %s" % (process, hb['assign_thread'], activity))
                for external_host in grouped_jobs:
                    for job in grouped_jobs[external_host]:
                        # submit transfers
                        # job_requests = makeRequests(submit_transfer, args_list=[((external_host, job, 'transfer_submitter', process, thread), {})])
                        job_requests = makeRequests(submit_transfer, args_list=[((), {'external_host': external_host, 'job': job, 'submitter': 'transfer_submitter', 'process': process,
                                                                                      'thread': hb['assign_thread'], 'cachedir': cachedir, 'timeout': timeout})])
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


def throttler(once=False, sleep_time=600):
    """
    Main loop to check rse transfer limits.
    """

    logging.info('Throttler starting')

    executable = 'throttler'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb = heartbeat.live(executable, hostname, pid, hb_thread)

    logging.info('Throttler started - thread (%i/%i) timeout (%s)' % (hb['assign_thread'], hb['nr_threads'], sleep_time))

    current_time = time.time()
    while not graceful_stop.is_set():

        try:
            hb = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            logging.info('Throttler - thread (%i/%i)' % (hb['assign_thread'], hb['nr_threads']))
            if hb['assign_thread'] != 0:
                logging.info('Throttler thread id is not 0, will sleep. Only thread 0 will work')
                while time.time() < current_time + sleep_time:
                    time.sleep(1)
                    if graceful_stop.is_set() or once:
                        break
                current_time = time.time()
                continue

            logging.info("Throttler thread %s - schedule requests" % hb['assign_thread'])
            schedule_requests()

            while time.time() < current_time + sleep_time:
                time.sleep(1)
                if graceful_stop.is_set() or once:
                    break
            current_time = time.time()
        except:
            logging.critical('Throtter thread %s - %s' % (hb['assign_thread'], traceback.format_exc()))

        if once:
            break

    logging.info('Throtter thread %s - graceful stop requested' % (hb['assign_thread']))

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('Throtter thread %s - graceful stop done' % (hb['assign_thread']))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False,
        process=0, total_processes=1, total_threads=1, group_bulk=1, group_policy='rule',
        mock=False, rses=[], include_rses=None, exclude_rses=None, bulk=100, fts_source_strategy='auto',
        activities=None, sleep_time=600, max_sources=4, retry_other_fts=False):
    """
    Starts up the conveyer threads.
    """

    if mock:
        logging.info('mock source replicas: enabled')

    working_rses = None
    if rses or include_rses or exclude_rses:
        working_rses = get_rses(rses, include_rses, exclude_rses)
        logging.info("RSE selection: RSEs: %s, Include: %s, Exclude: %s" % (rses,
                                                                            include_rses,
                                                                            exclude_rses))
    else:
        logging.info("RSE selection: automatic")

    logging.info('starting submitter threads')
    threads = [threading.Thread(target=submitter, kwargs={'once': once,
                                                          'process': process,
                                                          'total_processes': total_processes,
                                                          'total_threads': total_threads,
                                                          'rses': working_rses,
                                                          'bulk': bulk,
                                                          'group_bulk': group_bulk,
                                                          'group_policy': group_policy,
                                                          'activities': activities,
                                                          'mock': mock,
                                                          'sleep_time': sleep_time,
                                                          'max_sources': max_sources,
                                                          'fts_source_strategy': fts_source_strategy,
                                                          'retry_other_fts': retry_other_fts})]

    logging.info('starting throttler thread')
    throttler_thread = threading.Thread(target=throttler, kwargs={'once': once, 'sleep_time': sleep_time})

    threads.append(throttler_thread)
    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while len(threads) > 0:
        threads = [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
