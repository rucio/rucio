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
Conveyor is a daemon to manage file transfers.
"""

import json
import logging
import socket
import threading
import time
import traceback
from types import FrameType
from typing import Optional

import stomp

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.logging import setup_logging
from rucio.common.policy import get_policy
from rucio.core import transfer as transfer_core
from rucio.core import request as request_core
from rucio.core.monitor import MetricManager
from rucio.daemons.common import HeartbeatHandler
from rucio.db.sqla.session import transactional_session
from rucio.transfertool.fts3 import FTS3CompletionMessageTransferStatusReport

logging.getLogger("stomp").setLevel(logging.CRITICAL)

METRICS = MetricManager(module=__name__)
GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'conveyor-receiver'


class Receiver(object):

    def __init__(self, broker, id_, total_threads, transfer_stats_manager: request_core.TransferStatsManager, all_vos=False):
        self.__all_vos = all_vos
        self.__broker = broker
        self.__id = id_
        self.__total_threads = total_threads
        self._transfer_stats_manager = transfer_stats_manager

    @METRICS.count_it
    def on_error(self, frame):
        logging.error('[%s] %s' % (self.__broker, frame.body))

    @METRICS.count_it
    def on_message(self, frame):
        msg = json.loads(frame.body)

        if not self.__all_vos:
            if 'vo' not in msg or msg['vo'] != get_policy():
                return

        if 'job_metadata' in msg.keys() \
           and isinstance(msg['job_metadata'], dict) \
           and 'issuer' in msg['job_metadata'].keys() \
           and str(msg['job_metadata']['issuer']) == str('rucio'):

            if 'job_state' in msg.keys() and (str(msg['job_state']) != str('ACTIVE') or msg.get('job_multihop', False) is True):
                METRICS.counter('message_rucio').inc()

                self._perform_request_update(msg)

    @transactional_session
    def _perform_request_update(self, msg, *, session=None, logger=logging.log):
        external_host = msg.get('endpnt', None)
        request_id = msg['file_metadata'].get('request_id', None)
        try:
            tt_status_report = FTS3CompletionMessageTransferStatusReport(external_host, request_id=request_id, fts_message=msg)
            if tt_status_report.get_db_fields_to_update(session=session, logger=logger):
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


def receiver(id_, total_threads=1, all_vos=False):
    """
    Main loop to consume messages from the FTS3 producer.
    """

    logging.info('receiver starting')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('messaging-fts3', 'brokers').split(',')]
    except Exception:
        raise Exception('Could not load brokers from configuration')

    logging.info('resolving broker dns alias: %s' % brokers_alias)

    brokers_resolved = []
    for broker in brokers_alias:
        addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        brokers_resolved.extend(ai[4][0] for ai in addrinfos)

    logging.info('brokers resolved to %s', brokers_resolved)

    logging.info('checking authentication method')
    use_ssl = True
    try:
        use_ssl = config_get_bool('messaging-fts3', 'use_ssl')
    except:
        logging.info('could not find use_ssl in configuration -- please update your rucio.cfg')

    port = config_get_int('messaging-fts3', 'port')
    vhost = config_get('messaging-fts3', 'broker_virtual_host', raise_exception=False)
    if not use_ssl:
        username = config_get('messaging-fts3', 'username')
        password = config_get('messaging-fts3', 'password')
        port = config_get_int('messaging-fts3', 'nonssl_port')

    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            logging.info('setting up username/password authentication: %s' % broker)
        else:
            logging.info('setting up ssl cert/key authentication: %s' % broker)
        con = stomp.Connection12(host_and_ports=[(broker, port)],
                                 vhost=vhost,
                                 reconnect_attempts_max=999)
        if use_ssl:
            con.set_ssl(
                key_file=config_get('messaging-fts3', 'ssl_key_file'),
                cert_file=config_get('messaging-fts3', 'ssl_cert_file'),
            )
        conns.append(con)

    logging.info('receiver started')

    with (HeartbeatHandler(executable=DAEMON_NAME, renewal_interval=30) as heartbeat_handler,
          request_core.TransferStatsManager() as transfer_stats_manager):
        while not GRACEFUL_STOP.is_set():

            _, _, logger = heartbeat_handler.live()

            for conn in conns:

                if not conn.is_connected():
                    logger(logging.INFO, 'connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                    METRICS.counter('reconnect.{host}').labels(host=conn.transport._Transport__host_and_ports[0][0].split('.')[0]).inc()

                    conn.set_listener(
                        'rucio-messaging-fts3',
                        Receiver(
                            broker=conn.transport._Transport__host_and_ports[0],
                            id_=id_,
                            total_threads=total_threads,
                            transfer_stats_manager=transfer_stats_manager,
                            all_vos=all_vos
                        ))
                    if not use_ssl:
                        conn.connect(username, password, wait=True)
                    else:
                        conn.connect(wait=True)
                    conn.subscribe(destination=config_get('messaging-fts3', 'destination'),
                                   id='rucio-messaging-fts3',
                                   ack='auto')
            time.sleep(1)

        for conn in conns:
            try:
                conn.disconnect()
            except Exception:
                pass


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(once=False, total_threads=1):
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
