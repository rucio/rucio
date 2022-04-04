# -*- coding: utf-8 -*-
# Copyright 2020-2022 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022

import functools
import logging
import threading
from time import time
from typing import TYPE_CHECKING

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.exception import RucioException
from rucio.common.logging import setup_logging
from rucio.core.request import preparer_update_requests, reduce_requests, sort_requests_minimum_distance, \
    get_transfertool_filter, get_supported_transfertools, rse_lookup_filter, list_transfer_requests_and_source_replicas
from rucio.daemons.conveyor.common import run_conveyor_daemon
from rucio.db.sqla.constants import RequestState

if TYPE_CHECKING:
    from typing import Optional
    from sqlalchemy.orm import Session
    from rucio.daemons.conveyor.common import HeartbeatHandler

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
    setup_logging()

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


def preparer(once, sleep_time, bulk, partition_wait_time=10):
    # Make an initial heartbeat so that all instanced daemons have the correct worker number on the next try
    logger_prefix = executable = 'conveyor-preparer'

    run_conveyor_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        logger_prefix=logger_prefix,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            bulk=bulk
        ),
        activities=None,
    )


def run_once(bulk: int = 100, heartbeat_handler: "Optional[HeartbeatHandler]" = None, session: "Optional[Session]" = None, **kwargs) -> bool:
    if heartbeat_handler:
        worker_number, total_workers, logger = heartbeat_handler.live()
    else:
        # This is used in tests
        worker_number, total_workers, logger = 0, 0, logging.log

    start_time = time()
    try:
        req_sources = list_transfer_requests_and_source_replicas(
            total_workers=total_workers,
            worker_number=worker_number,
            limit=bulk,
            request_state=RequestState.PREPARING,
            session=session
        )
        if not req_sources:
            count = 0
            updated_msg = 'had nothing to do'
        else:
            transfertool_filter = get_transfertool_filter(lambda rse_id: get_supported_transfertools(rse_id=rse_id, session=session))
            requests = reduce_requests(req_sources, [rse_lookup_filter, sort_requests_minimum_distance, transfertool_filter], logger=logger)
            count = preparer_update_requests(requests, session=session)
            updated_msg = f'updated {count}/{bulk} requests'
    except RucioException:
        logger(logging.ERROR, 'errored with a RucioException, retrying later', exc_info=True)
        count = 0
        updated_msg = 'errored'
    logger(logging.INFO, '%s, taking %.3f seconds' % (updated_msg, time() - start_time))

    queue_empty = False
    if count < bulk:
        queue_empty = True
    return queue_empty
