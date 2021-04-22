# -*- coding: utf-8 -*-
# Copyright 2014-2020 CERN
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
# - Wen Guan <wen.guan@cern.ch>, 2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2017-2021
# - Robert Illingworth <illingwo@fnal.gov>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021

"""
Fax consumer is a daemon to retrieve rucio cache operation information to synchronize rucio catalog.
"""

import json
import logging
import socket
import threading
import time
from traceback import format_exc

import stomp

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get, config_get_int
from rucio.common.logging import setup_logging
from rucio.common.types import InternalScope
from rucio.core.monitor import record_counter
from rucio.core.rse import get_rse_id
from rucio.core.volatile_replica import add_volatile_replicas, delete_volatile_replicas

logging.getLogger("stomp").setLevel(logging.CRITICAL)

GRACEFUL_STOP = threading.Event()


class Consumer(object):
    '''
    class Consumer
    '''
    def __init__(self, broker, account, id, num_thread):
        '''
        __init__
        '''
        self.__broker = broker
        self.__account = account
        self.__id = id
        self.__num_thread = num_thread

    def on_error(self, frame):
        '''
        on_error
        '''
        record_counter('daemons.cache.consumer.error')
        logging.error('[%s] %s' % (self.__broker, frame.body))

    def on_message(self, frame):
        '''
        on_message
        '''
        record_counter('daemons.cache.consumer2.message')
        try:
            msg = json.loads(frame.body)
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
                    logging.info('add_replicas to RSE %s: %s ' % (rse_vo_str, str(msg['files'])))
                    add_volatile_replicas(rse_id=rse_id, replicas=msg['files'])
                elif msg['operation'] == 'delete_replicas':
                    logging.info('delete_replicas to RSE %s: %s ' % (rse_vo_str, str(msg['files'])))
                    delete_volatile_replicas(rse_id=rse_id, replicas=msg['files'])
        except:
            logging.error(str(format_exc()))


def consumer(id, num_thread=1):
    """
    Main loop to consume messages from the Rucio Cache producer.
    """

    logging.info('Rucio Cache consumer starting')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('messaging-cache', 'brokers').split(',')]
    except:
        raise Exception('Could not load rucio cache brokers from configuration')

    logging.info('resolving rucio cache broker dns alias: %s' % brokers_alias)

    brokers_resolved = []
    for broker in brokers_alias:
        addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        brokers_resolved.extend(ai[4][0] for ai in addrinfos)

    logging.debug('Rucio cache brokers resolved to %s', brokers_resolved)

    conns = {}
    for broker in brokers_resolved:
        conn = stomp.Connection(host_and_ports=[(broker, config_get_int('messaging-cache', 'port'))],
                                use_ssl=True,
                                ssl_key_file=config_get('messaging-cache', 'ssl_key_file'),
                                ssl_cert_file=config_get('messaging-cache', 'ssl_cert_file'),
                                vhost=config_get('messaging-cache', 'broker_virtual_host', raise_exception=False)
                                )
        conns[conn] = Consumer(conn.transport._Transport__host_and_ports[0], account=config_get('messaging-cache', 'account'), id=id, num_thread=num_thread)

    logging.info('consumer started')

    while not GRACEFUL_STOP.is_set():

        for conn in conns:

            if not conn.is_connected():
                logging.info('connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                record_counter('daemons.messaging.cache.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0].split('.')[0])

                conn.set_listener('rucio-cache-messaging', conns[conn])
                conn.connect()
                conn.subscribe(destination=config_get('messaging-cache', 'destination'),
                               id='rucio-cache-messaging',
                               ack='auto')

        time.sleep(1)

    logging.info('graceful stop requested')

    for conn in conns:
        try:
            conn.disconnect()
        except:
            pass

    logging.info('graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(num_thread=1):
    """
    Starts up the rucio cache consumer thread
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    logging.info('starting consumer thread')
    threads = [threading.Thread(target=consumer, kwargs={'id': i, 'num_thread': num_thread}) for i in range(0, num_thread)]

    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads[0].isAlive():
        [t.join(timeout=3.14) for t in threads]
