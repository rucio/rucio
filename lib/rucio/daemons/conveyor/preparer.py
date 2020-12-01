# -*- coding: utf-8 -*-
# Copyright 2020 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import logging
import os
import socket
import sys
import threading
from time import time
from typing import TYPE_CHECKING

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.exception import RucioException
from rucio.core import heartbeat
from rucio.core.request import preparer_update_requests, minimum_distance_requests
from rucio.core.transfer import __list_transfer_requests_and_source_replicas
from rucio.db.sqla.constants import RequestState

if TYPE_CHECKING:
    from typing import Optional
    from sqlalchemy.orm import Session

graceful_stop = threading.Event()


def stop():
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, threads=1, sleep_time=10, bulk=100):
    """
    Running the preparer daemon either once or by default in a loop until stop is called.
    """
    config_loglevel = config_get('common', 'loglevel', raise_exception=False, default='DEBUG').upper()
    logging.basicConfig(stream=sys.stdout,
                        level=config_loglevel,
                        format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    def preparer_kwargs():
        # not sure if this is needed for threading.Thread, but it always returns a fresh dictionary
        return {'once': once, 'sleep_time': sleep_time, 'bulk': bulk}

    threads = [threading.Thread(target=preparer, name=f'conveyor-preparer-{i}', kwargs=preparer_kwargs(), daemon=True) for i in range(threads)]
    for thr in threads:
        thr.start()

    all_running = True
    while all_running:
        for thr in threads:
            thr.join(timeout=3.14)
            if not thr.is_alive() or graceful_stop.is_set():
                all_running = False
                break

    if graceful_stop.is_set() or once:
        logging.info('conveyor-preparer: gracefully stopping')
    else:
        logging.warning('conveyor-preparer: stopping out of the ordinary')
        graceful_stop.set()

    for thr in threads:
        thr.join(timeout=3.14)

    logging.info('conveyor-preparer: stopped')


def preparer(once, sleep_time, bulk):
    # Make an initial heartbeat so that all instanced daemons have the correct worker number on the next try
    executable = 'conveyor-preparer'
    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()
    worker_number = current_thread
    total_workers = '?'
    heartbeat.sanity_check(executable=executable, hostname=hostname, pid=pid, thread=current_thread)

    try:
        graceful_stop.wait(10)  # gathering of daemons/threads on first start
        while not graceful_stop.is_set():
            start_time = time()

            pulse = heartbeat.live(executable=executable, hostname=hostname, pid=pid, thread=current_thread)
            worker_number = pulse['assign_thread']
            total_workers = pulse['nr_threads']

            try:
                updated_msg = run_once(total_workers=total_workers, worker_number=worker_number, limit=bulk)
            except RucioException:
                logging.exception('conveyor-preparer[%s/%s] errored with a RucioException, retrying later' % (worker_number, total_workers))
                updated_msg = 'errored'

            if once:
                break

            end_time = time()
            time_diff = end_time - start_time
            logging.info('conveyor-preparer[%s/%s] %s, taking %.3f seconds' % (worker_number, total_workers, updated_msg, time_diff))
            if time_diff < sleep_time:
                sleep_remaining = sleep_time - time_diff
                logging.info('conveyor-preparer[%s/%s] sleeping for a while :  %.2f seconds' % (worker_number, total_workers, sleep_remaining))
                graceful_stop.wait(sleep_remaining)

        logging.info('conveyor-preparer[%s/%s]: gracefully stopping' % (worker_number, total_workers))

    finally:
        heartbeat.die(executable=executable, hostname=hostname, pid=pid, thread=current_thread)


def run_once(total_workers: int = 0, worker_number: int = 0, limit: "Optional[int]" = None, session: "Optional[Session]" = None) -> str:
    req_sources = __list_transfer_requests_and_source_replicas(
        total_workers=total_workers,
        worker_number=worker_number,
        limit=limit,
        request_state=RequestState.PREPARING,
        session=session
    )
    if not req_sources:
        return 'had nothing to do'

    count = preparer_update_requests(minimum_distance_requests(req_sources), session=session)
    return f'updated {count}/{limit} requests'
