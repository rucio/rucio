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

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging
from rucio.core.rse import list_rses
from rucio.core.rse_counter_obsolete import check_obsolete_replicas
from rucio.daemons.common import HeartbeatHandler, run_daemon

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

graceful_stop = threading.Event()
DAEMON_NAME = 'abacus-rse-obsolete'


def rse_update(
        once: bool = False,
        sleep_time: int = 3600
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
        **_kwargs: object
) -> None:

    start_time = time.time()
    _, _, logger = heartbeat_handler.live()
    rses = list_rses()  # NOQA
    for rse in rses:
        if graceful_stop.is_set():
            break
        start = time.time()
        check_obsolete_replicas(rse['id'])
        logger(logging.DEBUG, 'Obsolete replica backlog query for RSE %s took %f s.' % (rse['id'], time.time() - start))

    logger(logging.DEBUG, 'update of all RSEs took %f s.' % (time.time() - start_time))


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(
        once: bool = False,
        sleep_time: int = 3600
) -> None:
    """
    Starts up the Abacus-RSE threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.info('main: executing one iteration only')
        rse_update(once)
    else:
        logging.info('main: starting the RSE usage thread')
        thread_list = [threading.Thread(target=rse_update, kwargs={'once': once, 'sleep_time': sleep_time})]
        [t.start() for t in thread_list]
        logging.info('main: waiting for interrupts')
        # Interruptible joins require a timeout.
        while thread_list[0].is_alive():
            [t.join(timeout=3.14) for t in thread_list]
