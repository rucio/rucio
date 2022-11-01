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

import functools
import logging
import threading
from time import time
from typing import TYPE_CHECKING

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get_list
from rucio.common.exception import RucioException
from rucio.common.logging import setup_logging
from rucio.core import transfer as transfer_core
from rucio.core.request import set_requests_state_if_possible, list_transfer_requests_and_source_replicas
from rucio.core.transfer import prepare_transfers, list_transfer_admin_accounts, build_transfer_paths
from rucio.core.topology import Topology
from rucio.db.sqla.constants import RequestState, RequestType
from rucio.daemons.common import run_daemon

if TYPE_CHECKING:
    from typing import Optional, List
    from sqlalchemy.orm import Session
    from rucio.daemons.common import HeartbeatHandler

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
    transfertools = config_get_list('conveyor', 'transfertool', False, None)

    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        logger_prefix=logger_prefix,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            transfertools=transfertools,
            bulk=bulk,
        ),
        activities=None,
    )


def run_once(
        transfertools: "Optional[List[str]]" = None,
        bulk: int = 100,
        heartbeat_handler: "Optional[HeartbeatHandler]" = None,
        session: "Optional[Session]" = None,
        **kwargs
) -> bool:
    if heartbeat_handler:
        worker_number, total_workers, logger = heartbeat_handler.live()
    else:
        # This is used in tests
        worker_number, total_workers, logger = 0, 0, logging.log
    if not transfertools:
        transfertools = list(transfer_core.TRANSFERTOOL_CLASSES_BY_NAME)

    start_time = time()
    requests_handled = 0
    try:
        admin_accounts = list_transfer_admin_accounts()
        topology = Topology.create_from_config(logger=logger)
        requests_with_sources = list_transfer_requests_and_source_replicas(
            total_workers=total_workers,
            worker_number=worker_number,
            limit=bulk,
            request_state=RequestState.PREPARING,
            request_type=[RequestType.TRANSFER, RequestType.STAGEIN],
            session=session
        )
        ret = build_transfer_paths(
            topology=topology,
            requests_with_sources=list(requests_with_sources.values()),
            admin_accounts=admin_accounts,
            preparer_mode=True,
            logger=logger,
            session=session,
        )
        requests_handled = sum(len(i) for i in ret)
        if not requests_handled:
            updated_msg = 'had nothing to do'
        else:
            candidate_paths, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source, _ = ret
            updated_reqs, reqs_no_transfertool = prepare_transfers(candidate_paths, transfertools=transfertools, logger=logger, session=session)
            updated_msg = f'updated {len(updated_reqs)}/{bulk} requests'

            if reqs_no_transfertool:
                logger(logging.INFO, "Ignoring request because of unsupported transfertool: %s", reqs_no_transfertool)
            reqs_no_source.update(reqs_no_transfertool)
            if reqs_no_source:
                logger(logging.INFO, "Marking requests as no-sources: %s", reqs_no_source)
                set_requests_state_if_possible(reqs_no_source, RequestState.NO_SOURCES, logger=logger)
            if reqs_only_tape_source:
                logger(logging.INFO, "Marking requests as only-tape-sources: %s", reqs_only_tape_source)
                set_requests_state_if_possible(reqs_only_tape_source, RequestState.ONLY_TAPE_SOURCES, logger=logger)
            if reqs_scheme_mismatch:
                logger(logging.INFO, "Marking requests as scheme-mismatch: %s", reqs_scheme_mismatch)
                set_requests_state_if_possible(reqs_scheme_mismatch, RequestState.MISMATCH_SCHEME, logger=logger)
    except RucioException:
        logger(logging.ERROR, 'errored with a RucioException, retrying later', exc_info=True)
        updated_msg = 'errored'
    logger(logging.INFO, '%s, taking %.3f seconds' % (updated_msg, time() - start_time))

    must_sleep = False
    if requests_handled < bulk / 2:
        logger(logging.INFO, "Only %s transfers, which is less than half of the bulk %s", requests_handled, bulk)
        must_sleep = True
    return must_sleep
