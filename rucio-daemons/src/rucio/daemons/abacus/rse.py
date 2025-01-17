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

"""
Abacus-RSE is a daemon to update RSE counters.
"""

import logging
import threading
import time
from typing import TYPE_CHECKING

import rucio.core.db.sqla.util
from rucio.core.common import exception
from rucio.core.common.logging import setup_logging
from rucio.core.common.utils import get_thread_with_periodic_running_function
from rucio.core.rse_counter import fill_rse_counter_history_table, get_updated_rse_counters, update_rse_counter
from rucio.daemons.common import HeartbeatHandler, run_daemon

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

graceful_stop = threading.Event()
DAEMON_NAME = 'abacus-rse'


def rse_update(
        once: bool = False,
        sleep_time: int = 10
) -> None:
    """
    Main loop to check and update the RSE Counters.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=run_once,
    )


def run_once(
        heartbeat_handler: HeartbeatHandler,
        **_kwargs
) -> None:
    worker_number, total_workers, logger = heartbeat_handler.live()

    # Select a bunch of rses for to update for this worker
    start = time.time()  # NOQA
    rse_ids = get_updated_rse_counters(total_workers=total_workers,
                                       worker_number=worker_number)
    logger(logging.DEBUG, 'Index query time %f size=%d' % (time.time() - start, len(rse_ids)))

    # If the list is empty, sent the worker to sleep
    if not rse_ids:
        logger(logging.INFO, 'did not get any work')
        return

    for rse_id in rse_ids:
        worker_number, total_workers, logger = heartbeat_handler.live()
        if graceful_stop.is_set():
            break
        start_time = time.time()
        update_rse_counter(rse_id=rse_id)
        logger(logging.DEBUG, 'update of rse "%s" took %f' % (rse_id, time.time() - start_time))


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(
        once: bool = False,
        threads: int = 1,
        fill_history_table: bool = False,
        sleep_time: int = 10
) -> None:
    """
    Starts up the Abacus-RSE threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.core.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.info('main: executing one iteration only')
        rse_update(once)
    else:
        logging.info('main: starting threads')
        thread_list = [threading.Thread(target=rse_update, kwargs={'once': once, 'sleep_time': sleep_time}) for i in
                       range(0, threads)]
        if fill_history_table:
            thread_list.append(get_thread_with_periodic_running_function(3600, fill_rse_counter_history_table, graceful_stop))
        [t.start() for t in thread_list]
        logging.info('main: waiting for interrupts')
        # Interruptible joins require a timeout.
        while thread_list[0].is_alive():
            [t.join(timeout=3.14) for t in thread_list]
