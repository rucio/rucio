# Copyright 2014-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Wen Guan <wguan.icedew@gmail.com>, 2014
# - Vincent Garonne <vgaronne@gmail.com>, 2016-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2017

"""
Fax consumer is a daemon to retrieve rucio cache operation information to synchronize rucio catalog.
"""

from traceback import format_exc

import logging
import ssl
import sys
import threading
import time

import dns.resolver
import json
import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.monitor import record_counter
from rucio.core.volatile_replica import add_volatile_replicas, delete_volatile_replicas


logging.getLogger("stomp").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

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

    def on_error(self, headers, message):
        '''
        on_error
        '''
        record_counter('daemons.cache.consumer.error')
        logging.error('[%s] %s' % (self.__broker, message))

    def on_message(self, headers, message):
        '''
        on_message
        '''
        record_counter('daemons.cache.consumer2.message')
        try:
            msg = json.loads(message)
            if isinstance(msg, dict) and 'operation' in msg.keys():
                if msg['operation'] == 'add_replicas':
                    logging.info('add_replicas to RSE %s: %s ' % (msg['rse'], str(msg['files'])))
                    add_volatile_replicas(rse=msg['rse'], replicas=msg['files'])
                elif msg['operation'] == 'delete_replicas':
                    logging.info('delete_replicas to RSE %s: %s ' % (msg['rse'], str(msg['files'])))
                    delete_volatile_replicas(rse=msg['rse'], replicas=msg['files'])
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
        brokers_resolved.append([str(tmp_broker) for tmp_broker in dns.resolver.query(broker, 'A')])
    brokers_resolved = [item for sublist in brokers_resolved for item in sublist]

    logging.debug('Rucio cache brokers resolved to %s', brokers_resolved)

    conns = {}
    for broker in brokers_resolved:
        conn = stomp.Connection(host_and_ports=[(broker, config_get_int('messaging-cache', 'port'))],
                                use_ssl=True,
                                ssl_key_file=config_get('messaging-cache', 'ssl_key_file'),
                                ssl_cert_file=config_get('messaging-cache', 'ssl_cert_file'),
                                ssl_version=ssl.PROTOCOL_TLSv1)
        conns[conn] = Consumer(conn.transport._Transport__host_and_ports[0], account=config_get('messaging-cache', 'account'), id=id, num_thread=num_thread)

    logging.info('consumer started')

    while not GRACEFUL_STOP.is_set():

        for conn in conns:

            if not conn.is_connected():
                logging.info('connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                record_counter('daemons.messaging.cache.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0].split('.')[0])

                conn.set_listener('rucio-cache-messaging', conns[conn])
                conn.start()
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

    logging.info('starting consumer thread')
    threads = [threading.Thread(target=consumer, kwargs={'id': i, 'num_thread': num_thread}) for i in xrange(0, num_thread)]

    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while t.isAlive():
        t.join(timeout=3.14)
