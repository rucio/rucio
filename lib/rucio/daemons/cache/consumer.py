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
Cache consumer is a daemon to retrieve rucio cache operation information to synchronize rucio catalog.
"""

import json
import logging
import threading
import time
from traceback import format_exc
from typing import TYPE_CHECKING

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging, formatted_logger
from rucio.common.stomp_utils import StompConnectionManager, ListenerBase
from rucio.common.types import InternalScope, LoggerFunction
from rucio.core.monitor import MetricManager
from rucio.core.rse import get_rse_id
from rucio.core.volatile_replica import add_volatile_replicas, delete_volatile_replicas

if TYPE_CHECKING:
    from types import FrameType

    from stomp.utils import Frame

logging.getLogger("stomp").setLevel(logging.CRITICAL)

METRICS = MetricManager(module=__name__)
GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'cache-consumer'


class AMQConsumer(ListenerBase):
    """
    class Consumer
    """

    @METRICS.count_it
    def on_message(self, frame: "Frame") -> None:
        """
        on_message
        """
        try:
            msg = json.loads(frame.body)  # type: ignore
            self._logger(logging.DEBUG, 'Message received: %s', msg)
            if isinstance(msg, dict) and 'operation' in msg.keys():
                for f in msg['files']:
                    f['scope'] = InternalScope(f['scope'])
                if 'rse_id' in msg:
                    rse_id = msg['rse_id']
                else:
                    rse_id = get_rse_id(rse=msg['rse'], vo=msg.get('vo', 'def'))

                rse_vo_str = msg['rse']
                if 'vo' in msg and msg['vo'] != 'def':
                    rse_vo_str = f"{rse_vo_str} on {msg['vo']}"
                if msg['operation'] == 'add_replicas':
                    self._logger(logging.INFO, "add_replicas to RSE %s: %s", rse_vo_str, str(msg['files']))
                    add_volatile_replicas(rse_id=rse_id, replicas=msg['files'])
                elif msg['operation'] == 'delete_replicas':
                    self._logger(logging.INFO, "delete_replicas to RSE %s: %s", rse_vo_str, str(msg['files']))
                    delete_volatile_replicas(rse_id=rse_id, replicas=msg['files'])
            else:
                self._logger(logging.DEBUG, 'Check failed: %s %s', isinstance(msg, dict), "operation" in msg.keys())
        except:
            self._logger(logging.ERROR, str(format_exc()))


def consumer(id_: int, num_thread: int = 1, logger: LoggerFunction = logging.log) -> None:
    """
    Main loop to consume messages from the Rucio Cache producer.
    """
    logger(logging.INFO, 'Rucio Cache consumer starting')

    conn_mgr = StompConnectionManager(config_section='messaging-cache', logger=logger)

    logger(logging.INFO, 'consumer started')

    conn_mgr.set_listener_factory('rucio-cache-consumer', AMQConsumer, heartbeats=conn_mgr.config.heartbeats)

    while not GRACEFUL_STOP.is_set():

        conn_mgr.subscribe(id_='rucio-cache-messaging', ack='auto')
        time.sleep(1)

    logger(logging.INFO, 'graceful stop requested')
    conn_mgr.disconnect()
    logger(logging.INFO, 'graceful stop done')


def stop(signum: "int | None" = None, frame: "FrameType | None" = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(num_thread: int = 1) -> None:
    """
    Starts up the rucio cache consumer thread
    """
    setup_logging(process_name=DAEMON_NAME)
    logger = formatted_logger(logging.log, DAEMON_NAME + ' %s')

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logger(logging.INFO, 'starting consumer thread')
    threads = []
    for i in range(num_thread):
        con_thread = threading.Thread(target=consumer, kwargs={'id_': i, 'num_thread': num_thread, 'logger': logger})
        con_thread.start()
        threads.append(con_thread)

    logger(logging.INFO, 'waiting for interrupts')

    while [thread.join(timeout=3.14) for thread in threads if thread.is_alive()]:
        pass
