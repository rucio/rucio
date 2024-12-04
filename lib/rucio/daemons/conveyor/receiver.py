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
Conveyor is a daemon to manage file transfers.
"""
import json
import logging
import threading
import time
import traceback
from typing import TYPE_CHECKING, Any

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.policy import get_policy
from rucio.common.stomp_utils import Connection, ListenerBase, StompConnectionManager
from rucio.core import request as request_core
from rucio.core import transfer as transfer_core
from rucio.core.monitor import MetricManager
from rucio.daemons.common import HeartbeatHandler
from rucio.db.sqla.session import transactional_session
from rucio.transfertool.fts3 import FTS3CompletionMessageTransferStatusReport

if TYPE_CHECKING:
    from types import FrameType

    from sqlalchemy.orm import Session
    from stomp.utils import Frame

    from rucio.common.types import LoggerFunction

logging.getLogger("stomp").setLevel(logging.CRITICAL)

METRICS = MetricManager(module=__name__)
GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'conveyor-receiver'


class Receiver(ListenerBase):

    def __init__(self,
                 conn: Connection,
                 id_: str,
                 total_threads: int,
                 transfer_stats_manager: request_core.TransferStatsManager,
                 all_vos: bool = False,
                 logger: "LoggerFunction" = logging.log,
                 **kwargs: dict) -> None:
        super().__init__(conn, logger, **kwargs)
        self.__all_vos = all_vos
        self.__id = id_
        self.__total_threads = total_threads
        self._transfer_stats_manager = transfer_stats_manager

    @METRICS.count_it
    def on_message(self, frame: "Frame") -> None:
        msg = json.loads(frame.body)  # type: ignore

        if not self.__all_vos:
            if 'vo' not in msg or msg['vo'] != get_policy():
                return

        if 'job_metadata' in msg.keys() \
           and isinstance(msg['job_metadata'], dict) \
           and 'issuer' in msg['job_metadata'].keys() \
           and str(msg['job_metadata']['issuer']) == 'rucio':

            if ('job_state' in msg.keys() and (str(msg['job_state']) != 'ACTIVE'
                                               or msg.get('job_multihop', False) is True)):
                METRICS.counter('message_rucio').inc()

                self._perform_request_update(msg)

    @transactional_session
    def _perform_request_update(
        self,
        msg: dict[str, Any],
        *,
        session: "Session | None",
        logger: "LoggerFunction" = logging.log
    ) -> None:
        external_host = msg.get('endpnt', None)
        request_id = msg['file_metadata'].get('request_id', None)
        try:
            tt_status_report = FTS3CompletionMessageTransferStatusReport(external_host,
                                                                         request_id=request_id,
                                                                         fts_message=msg)
            if tt_status_report.get_db_fields_to_update(session=session, logger=logger):  # type: ignore
                logging.info('RECEIVED %s', tt_status_report)

                ret = transfer_core.update_transfer_state(
                    tt_status_report=tt_status_report,
                    stats_manager=self._transfer_stats_manager,
                    session=session,
                    logger=logger,
                )
                if ret:
                    METRICS.counter('update_request_state.{updated}').labels(updated=True).inc(delta=ret)
                else:
                    METRICS.counter('update_request_state.{updated}').labels(updated=False).inc()
        except Exception:
            logging.critical(traceback.format_exc())


def receiver(id_: str,
             total_threads: int = 1,
             all_vos: bool = False,
             logger: "LoggerFunction" = logging.log):
    """
    Main loop to consume messages from the FTS3 producer.
    """
    logger(logging.INFO, 'receiver starting')

    conn_mgr = StompConnectionManager(config_section='messaging-fts3', logger=logger)

    logger(logging.INFO, 'receiver started')

    with (HeartbeatHandler(executable=DAEMON_NAME, renewal_interval=30),
          request_core.TransferStatsManager() as transfer_stats_manager):

        conn_mgr.set_listener_factory('rucio-messaging-fts3', Receiver,
                                      id_=id_,
                                      total_threads=total_threads,
                                      transfer_stats_manager=transfer_stats_manager,
                                      all_vos=all_vos,
                                      heartbeats=conn_mgr.config.heartbeats)

        while not GRACEFUL_STOP.is_set():

            conn_mgr.subscribe(id_='rucio-messaging-fts3', ack='auto')

            time.sleep(1)

        conn_mgr.disconnect()


def stop(signum: "int | None" = None, frame: "FrameType | None" = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(once: bool = False, total_threads: int = 1) -> None:
    """
    Starts up the receiver thread
    """
    setup_logging(process_name=DAEMON_NAME)
    logger = formatted_logger(logging.log, DAEMON_NAME + ' %s')

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logger(logging.INFO, 'starting receiver thread')
    threads = []
    for i in range(total_threads):
        rec_thread = threading.Thread(target=receiver,
                                      kwargs={'id_': i, 'logger': logger, 'total_threads': total_threads})
        rec_thread.start()
        threads.append(rec_thread)

    logger(logging.INFO, 'waiting for interrupts')

    while [thread.join(timeout=3.14) for thread in threads if thread.is_alive()]:
        pass
