# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014

"""
Conveyor is a daemon to manage file transfers.
"""

import logging
import sys
import threading
import time

import dns.resolver
import json
import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.monitor import record_counter
from rucio.core.request import set_request_state
from rucio.db.constants import FTSState, RequestState

logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("stomp").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


class Consumer(object):

    def __init__(self, broker):
        self.__broker = broker

    def on_error(self, headers, message):
        record_counter('daemons.conveyor.consumer.error')
        logging.error('[%s] %s' % (self.__broker, message))

    def on_message(self, headers, message):
        record_counter('daemons.conveyor.consumer.message')

        msg = json.loads(message[:-1])  # message always ends with an unparseable EOT character

        if isinstance(msg['job_metadata'], dict) \
           and 'issuer' in msg['job_metadata'].keys() \
           and msg['job_metadata']['issuer'].startswith('rucio-transfertool') \
           and 'request_id' in msg['job_metadata'].keys():
            if str(msg['job_state']) == str(FTSState.FINISHED):
                logging.info('%s: DONE', msg['job_metadata']['request_id'])
                set_request_state(msg['job_metadata']['request_id'], RequestState.DONE)
            elif str(msg['job_state']) == str(FTSState.FAILED):
                logging.info('%s: FAILED', msg['job_metadata']['request_id'])
                set_request_state(msg['job_metadata']['request_id'], RequestState.FAILED)


def consumer(once=False, process=0, total_processes=1, thread=0, total_threads=1):
    """
    Main loop to consume messages from the FTS3 producer.
    """

    logging.info('consumer starting')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('messaging-fts3', 'brokers').split(',')]
    except:
        raise Exception('Could not load brokers from configuration')

    logging.info('resolving broker dns alias: %s' % brokers_alias)

    brokers_resolved = []
    for broker in brokers_alias:
        brokers_resolved.append([str(tmp_broker) for tmp_broker in dns.resolver.query(broker, 'A')])
    brokers_resolved = [item for sublist in brokers_resolved for item in sublist]

    logging.debug('brokers resolved to %s', brokers_resolved)

    conns = []
    for broker in brokers_resolved:
        conns.append(stomp.Connection(host_and_ports=[(broker, config_get_int('messaging-fts3', 'port'))],
                                      use_ssl=True,
                                      ssl_key_file=config_get('messaging-fts3', 'ssl_key_file'),
                                      ssl_cert_file=config_get('messaging-fts3', 'ssl_cert_file')))

    logging.info('consumer started')

    while not graceful_stop.is_set():

        for conn in conns:

            if not conn.is_connected():
                logging.info('connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                record_counter('daemons.messaging.fts3.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0].split('.')[0])

                conn.set_listener('rucio-messaging-fts3', Consumer(broker=conn.transport._Transport__host_and_ports[0]))
                conn.start()
                conn.connect()
                conn.subscribe(destination=config_get('messaging-fts3', 'destination'),
                               id='rucio-messaging-fts3',
                               ack='auto',
                               headers={'selector': 'vo = \'%s\'' % config_get('messaging-fts3', 'voname')})

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

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1):
    """
    Starts up the consumer threads
    """

    logging.info('starting consumer threads')
    threads = [threading.Thread(target=consumer, kwargs={'process': process, 'total_processes': total_processes, 'thread': i, 'total_threads': total_threads}) for i in xrange(0, total_threads)]

    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while len(threads) > 0:
        [t.join(timeout=3.14) for t in threads if t is not None and t.isAlive()]
