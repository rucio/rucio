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
from functools import partial
from typing import TYPE_CHECKING, Any, Optional

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int, config_get_list
from rucio.common.logging import setup_logging
from rucio.common.policy import get_policy
from rucio.common.stomp_controller import StompController
from rucio.core import request as request_core
from rucio.core import transfer as transfer_core
from rucio.core.monitor import MetricManager
from rucio.daemons.common import HeartbeatHandler
from rucio.db.sqla.session import transactional_session
from rucio.transfertool.fts3 import FTS3CompletionMessageTransferStatusReport

if TYPE_CHECKING:
    from types import FrameType

    from sqlalchemy.orm import Session
    from stomp import Connection
    from stomp.utils import Frame

    from rucio.common.types import LoggerFunction

logging.getLogger("stomp").setLevel(logging.CRITICAL)

METRICS = MetricManager(module=__name__)
GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'conveyor-receiver'


class Receiver:

    def __init__(
            self,
            broker: str,
            conn: "Connection",
            id_: str,
            total_threads: int,
            transfer_stats_manager: request_core.TransferStatsManager,
            all_vos: bool = False
    ):
        self.__all_vos = all_vos
        self.__broker = broker
        self.__conn = conn
        self.__id = id_
        self.__total_threads = total_threads
        self._transfer_stats_manager = transfer_stats_manager

    @METRICS.count_it
    def on_error(self, frame: "Frame") -> None:
        logging.error('[%s] %s' % (self.__broker, frame.body))

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

            if 'job_state' in msg.keys() and (str(msg['job_state']) != 'ACTIVE' or msg.get('job_multihop', False) is True):
                METRICS.counter('message_rucio').inc()

                self._perform_request_update(msg)

    @transactional_session
    def _perform_request_update(
        self,
        msg: dict[str, Any],
        *,
        session: Optional["Session"] = None,
        logger: "LoggerFunction" = logging.log
    ) -> None:
        external_host = msg.get('endpnt', None)
        request_id = msg['file_metadata'].get('request_id', None)
        try:
            tt_status_report = FTS3CompletionMessageTransferStatusReport(external_host, request_id=request_id, fts_message=msg)
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


def receiver(
        id_: str,
        total_threads: int = 1,
        all_vos: bool = False
) -> None:
    """
    Main loop to consume messages from the FTS3 producer.
    """

    logging.info('receiver starting')

    brokers = config_get_list('messaging-fts3', 'brokers')
    use_ssl = config_get_bool('messaging-fts3', 'use_ssl', default=True)
    username = None
    password = None
    if not use_ssl:
        username = config_get('messaging-fts3', 'username')
        password = config_get('messaging-fts3', 'password')
        port = config_get_int('messaging-fts3', 'nonssl_port')
    else:
        port = config_get_int('messaging-fts3', 'port')
    vhost = config_get('messaging-fts3', 'broker_virtual_host', raise_exception=False)
    ssl_key_file = config_get('messaging-fts3', 'ssl_key_file', raise_exception=False)
    ssl_cert_file = config_get('messaging-fts3', 'ssl_cert_file', raise_exception=False)
    destination = config_get('messaging-fts3', 'destination')
    subscription_id = config_get('messaging-fts3', 'subscription_id', default='rucio-messaging-fts3')
    listener_name = config_get('messaging-fts3', 'listener_name', default='rucio-messaging-fts3')

    controller = StompController(
        brokers=brokers,
        port=port,
        use_ssl=use_ssl,
        vhost=vhost,
        username=username,
        password=password,
        ssl_key_file=ssl_key_file,
        ssl_cert_file=ssl_cert_file,
        timeout=None,
        reconnect_attempts=999,
        logger=logging.log
    )
    controller.setup_connections()

    logging.info('receiver started')

    with (HeartbeatHandler(executable=DAEMON_NAME, renewal_interval=30) as heartbeat_handler,
          request_core.TransferStatsManager() as transfer_stats_manager):
        while not GRACEFUL_STOP.is_set():

            _, _, logger = heartbeat_handler.live()

            controller.connect_and_subscribe(
                destination=destination,
                listener_name=listener_name,
                listener=partial(Receiver,
                                 id_=id_,
                                 total_threads=total_threads,
                                 transfer_stats_manager=transfer_stats_manager,
                                 all_vos=all_vos),
                subscription_id=subscription_id,
                ack='auto',
                metric=METRICS,
                logger=logger
            )
            time.sleep(1)

        controller.disconnect()


def stop(signum: Optional[int] = None, frame: Optional["FrameType"] = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(
        once: bool = False,
        total_threads: int = 1
) -> None:
    """
    Starts up the receiver thread
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('starting receiver thread')
    threads = [threading.Thread(target=receiver, kwargs={'id_': i,
                                                         'total_threads': total_threads}) for i in range(0, total_threads)]

    [thread.start() for thread in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads:
        threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]
