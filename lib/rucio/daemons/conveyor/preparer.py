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

import logging
import threading
from time import time
from types import FrameType
from typing import TYPE_CHECKING, Optional

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get_list
from rucio.common.exception import RucioException
from rucio.common.logging import setup_logging
from rucio.core import transfer as transfer_core
from rucio.core.request import transition_requests_state_if_possible, list_and_mark_transfer_requests_and_source_replicas
from rucio.core.topology import Topology, ExpiringObjectCache
from rucio.core.transfer import prepare_transfers, list_transfer_admin_accounts, build_transfer_paths, ProtocolFactory
from rucio.daemons.common import db_workqueue, ProducerConsumerDaemon
from rucio.db.sqla.constants import RequestState, RequestType

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from rucio.daemons.common import HeartbeatHandler

GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'conveyor-preparer'


def stop(signum: Optional[int] = None, frame: Optional[FrameType] = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(
        once=False,
        threads=1,
        sleep_time=10,
        bulk=100,
        ignore_availability: bool = False
):
    """
    Running the preparer daemon either once or by default in a loop until stop is called.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    cached_topology = ExpiringObjectCache(ttl=300, new_obj_fnc=lambda: Topology(ignore_availability=ignore_availability))

    preparer(
        once=once,
        sleep_time=sleep_time,
        bulk=bulk,
        ignore_availability=ignore_availability,
        cached_topology=cached_topology,
        total_threads=threads
    )


def preparer(
        once,
        sleep_time: int = 10,
        bulk: int = 100,
        ignore_availability: bool = False,
        partition_wait_time: int = 10,
        transfertools=None,
        cached_topology=None,
        total_threads=1
):
    # Make an initial heartbeat so that all instanced daemons have the correct worker number on the next try
    executable = DAEMON_NAME
    if not transfertools:
        transfertools = config_get_list('conveyor', 'transfertool', False, None)

    @db_workqueue(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=executable,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time)
    def _db_producer(*, activity: str, heartbeat_handler: "HeartbeatHandler"):
        return _fetch_requests(
            bulk=bulk,
            ignore_availability=ignore_availability,
            cached_topology=cached_topology,
            heartbeat_handler=heartbeat_handler,
            set_last_processed_by=not once,
        )

    def _consumer(batch):
        return _handle_requests(
            batch,
            transfertools=transfertools,
            bulk=bulk,
        )

    ProducerConsumerDaemon(
        producers=[_db_producer],
        consumers=[_consumer for _ in range(total_threads)],
        graceful_stop=GRACEFUL_STOP,
    ).run()


def _fetch_requests(
        bulk: int,
        ignore_availability: bool,
        cached_topology,
        heartbeat_handler: "HeartbeatHandler",
        set_last_processed_by: bool,
        *,
        session: "Optional[Session]" = None,
):
    worker_number, total_workers, logger = heartbeat_handler.live()
    topology = cached_topology.get() if cached_topology else Topology(ignore_availability=ignore_availability)
    topology.configure_multihop(logger=logger, session=session)
    requests_with_sources = list_and_mark_transfer_requests_and_source_replicas(
        rse_collection=topology,
        processed_by=heartbeat_handler.short_executable if set_last_processed_by else None,
        total_workers=total_workers,
        worker_number=worker_number,
        limit=bulk,
        request_state=RequestState.PREPARING,
        request_type=[RequestType.TRANSFER, RequestType.STAGEIN],
        ignore_availability=ignore_availability,
        session=session,
    )
    must_sleep = False
    if len(requests_with_sources) < bulk / 2:
        logger(logging.INFO, "Only %s transfers, which is less than half of the bulk %s", len(requests_with_sources), bulk)
        must_sleep = True
    return must_sleep, (topology, requests_with_sources)


def _handle_requests(
        batch,
        *,
        transfertools: Optional[list[str]] = None,
        bulk: int = 100,
        logger=logging.log,
):
    topology, requests_with_sources = batch

    if not transfertools:
        transfertools = list(transfer_core.TRANSFERTOOL_CLASSES_BY_NAME)

    start_time = time()
    try:
        admin_accounts = list_transfer_admin_accounts()

        ret = build_transfer_paths(
            topology=topology,
            protocol_factory=ProtocolFactory(),
            requests_with_sources=list(requests_with_sources.values()),
            admin_accounts=admin_accounts,
            preparer_mode=True,
            logger=logger,
        )
        requests_handled = sum(len(i) for i in ret)
        if not requests_handled:
            updated_msg = 'had nothing to do'
        else:
            candidate_paths, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source, _ = ret
            updated_reqs, reqs_no_transfertool = prepare_transfers(candidate_paths, transfertools=transfertools, logger=logger)
            updated_msg = f'updated {len(updated_reqs)}/{bulk} requests'

            if reqs_no_transfertool:
                logger(logging.INFO, "Ignoring request because of unsupported transfertool: %s", reqs_no_transfertool)
            reqs_no_source.update(reqs_no_transfertool)
            if reqs_no_source:
                logger(logging.INFO, "Marking requests as no-sources: %s", reqs_no_source)
                transition_requests_state_if_possible(reqs_no_source, RequestState.NO_SOURCES, logger=logger)
            if reqs_only_tape_source:
                logger(logging.INFO, "Marking requests as only-tape-sources: %s", reqs_only_tape_source)
                transition_requests_state_if_possible(reqs_only_tape_source, RequestState.ONLY_TAPE_SOURCES, logger=logger)
            if reqs_scheme_mismatch:
                logger(logging.INFO, "Marking requests as scheme-mismatch: %s", reqs_scheme_mismatch)
                transition_requests_state_if_possible(reqs_scheme_mismatch, RequestState.MISMATCH_SCHEME, logger=logger)
    except RucioException:
        logger(logging.ERROR, 'errored with a RucioException, retrying later', exc_info=True)
        updated_msg = 'errored'
    logger(logging.INFO, '%s, taking %.3f seconds' % (updated_msg, time() - start_time))
