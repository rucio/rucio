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
from rucio.common.config import config_get, config_get_int, config_get_bool, config_get_list
from rucio.common.logging import setup_logging, formatted_logger
from rucio.common.stomp_utils import StompConnectionManager
from rucio.common.types import InternalScope
from rucio.core.monitor import MetricManager
from rucio.core.rse import get_rse_id
from rucio.core.volatile_replica import add_volatile_replicas, delete_volatile_replicas

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

logging.getLogger("stomp").setLevel(logging.CRITICAL)

METRICS = MetricManager(module=__name__)
GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'cache-consumer'


class AMQConsumer(object):
    """
    class Consumer
    """

    def __init__(self, broker, conn, logger):
        """
        __init__
        """
        self.__broker = broker
        self.__conn = conn
        self.__logger = logger

    @METRICS.count_it
    def on_heartbeat_timeout(self):
        self.__conn.disconnect()

    @METRICS.count_it
    def on_error(self, frame):
        """
        on_error
        """
        self.__logger(logging.ERROR, 'Message receive error: [%s] %s' % (self.__broker, frame.body))

    @METRICS.count_it
    def on_message(self, frame):
        """
        on_message
        """
        try:
            msg = json.loads(frame.body)
            self.__logger(logging.DEBUG, 'Message received: %s ' % msg)
            if isinstance(msg, dict) and 'operation' in msg.keys():
                for f in msg['files']:
                    f['scope'] = InternalScope(f['scope'])
                if 'rse_id' in msg:
                    rse_id = msg['rse_id']
                else:
                    rse_id = get_rse_id(rse=msg['rse'], vo=msg.get('vo', 'def'))

                rse_vo_str = msg['rse']
                if 'vo' in msg and msg['vo'] != 'def':
                    rse_vo_str = '{} on {}'.format(rse_vo_str, msg['vo'])
                if msg['operation'] == 'add_replicas':
                    self.__logger(logging.INFO, 'add_replicas to RSE %s: %s ' % (rse_vo_str, str(msg['files'])))
                    add_volatile_replicas(rse_id=rse_id, replicas=msg['files'])
                elif msg['operation'] == 'delete_replicas':
                    self.__logger(logging.INFO, 'delete_replicas to RSE %s: %s ' % (rse_vo_str, str(msg['files'])))
                    delete_volatile_replicas(rse_id=rse_id, replicas=msg['files'])
            else:
                self.__logger(logging.DEBUG, 'Check failed: %s %s '
                              % (isinstance(msg, dict), 'operation' in msg.keys()))
        except:
            self.__logger(logging.ERROR, str(format_exc()))


def consumer(id_, num_thread=1):
    """
    Main loop to consume messages from the Rucio Cache producer.
    """

    logger = formatted_logger(logging.log, DAEMON_NAME + ' %s')

    logger(logging.INFO, 'Rucio Cache consumer starting')

    brokers = config_get_list('messaging-cache', 'brokers')

    use_ssl = config_get_bool('messaging-cache', 'use_ssl', default=True, raise_exception=False)
    if not use_ssl:
        username = config_get('messaging-cache', 'username')
        password = config_get('messaging-cache', 'password')
    destination = config_get('messaging-cache', 'destination')
    subscription_id = 'rucio-cache-messaging'

    vhost = config_get('messaging-cache', 'broker_virtual_host', raise_exception=False)
    port = config_get_int('messaging-cache', 'port')
    reconnect_attempts = config_get_int('messaging-cache', 'reconnect_attempts', default=100)
    ssl_key_file = config_get('messaging-cache', 'ssl_key_file', raise_exception=False)
    ssl_cert_file = config_get('messaging-cache', 'ssl_cert_file', raise_exception=False)

    stomp_conn_mngr = StompConnectionManager()
    conns, _ = stomp_conn_mngr.re_configure(
        brokers=brokers,
        port=port,
        use_ssl=use_ssl,
        vhost=vhost,
        reconnect_attempts=reconnect_attempts,
        ssl_key_file=ssl_key_file,
        ssl_cert_file=ssl_cert_file,
        timeout=None,
        logger=logger
    )

    logger(logging.INFO, 'consumer started')

    while not GRACEFUL_STOP.is_set():
        for conn in conns:
            if not conn.is_connected():
                host_port = conn.transport._Transport__host_and_ports[0]

                logger(logging.INFO, 'connecting to %s' % host_port[0])
                METRICS.counter('reconnect.{host}').labels(host=host_port[0]).inc()
                conn.set_listener('rucio-cache-consumer', AMQConsumer(broker=host_port, conn=conn, logger=logger))
                if not use_ssl:
                    conn.connect(username, password)
                else:
                    conn.connect()

                conn.subscribe(destination=destination, ack='auto', id=subscription_id)
        time.sleep(1)

    logger(logging.INFO, 'graceful stop requested')
    stomp_conn_mngr.disconnect()
    logger(logging.INFO, 'graceful stop done')


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(num_thread=1):
    """
    Starts up the rucio cache consumer thread
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('starting consumer thread')
    threads = [threading.Thread(target=consumer, kwargs={'id_': i, 'num_thread': num_thread})
               for i in range(0, num_thread)]

    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
