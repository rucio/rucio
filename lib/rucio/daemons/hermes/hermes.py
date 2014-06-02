#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

"""
Hermes is a daemon to deliver messages to an asynchronous broker.
"""

import json
import logging
import random
import sys
import threading
import time

import dns.resolver
import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.message import retrieve_messages, delete_messages
from rucio.core.monitor import record_counter
from rucio.db.session import get_session

logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("stomp").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


class Deliver(object):

    def __init__(self, broker):
        self.__broker = broker
        self.__session = get_session()


def deliver_messages(once=False):
    """
    Main loop to deliver messages to a broker.
    """

    logging.info('hermes starting')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('messaging-hermes', 'brokers').split(',')]
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
        conns.append(stomp.Connection(host_and_ports=[(broker, config_get_int('messaging-hermes', 'port'))],
                                      use_ssl=True,
                                      ssl_key_file=config_get('messaging-hermes', 'ssl_key_file'),
                                      ssl_cert_file=config_get('messaging-hermes', 'ssl_cert_file')))

    logging.info('hermes started')

    while not graceful_stop.is_set():

        for conn in conns:

            if not conn.is_connected():
                logging.info('connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                record_counter('daemons.hermes.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0].split('.')[0])

                conn.start()
                conn.connect()

        tmp = retrieve_messages()
        if tmp == []:
            time.sleep(1)
        else:
            to_delete = []
            for t in tmp:
                try:
                    random.sample(conns, 1)[0].send(body=json.dumps({'event_type': str(t['event_type']).lower(),
                                                                     'payload': t['payload'],
                                                                     'created_at': str(t['created_at'])}),
                                                    destination=config_get('messaging-hermes', 'destination'))
                except ValueError:
                    logging.warn('Cannot serialize payload to JSON: %s' % str(t['payload']))
                    continue
                except Exception, e:
                    logging.warn('Could not deliver message: ' % str(e))
                    continue

                to_delete.append(t['id'])

            delete_messages(to_delete)
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


def run(once=False, src=None, dst=None):
    """
    Starts up the hermes threads.
    """

    if once:
        logging.info('executing one hermes deliver iteration only')
        deliver_messages(once=True)

    else:

        logging.info('starting hermes deliver thread')
        t = threading.Thread(target=deliver_messages)
        t.start()
        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while t.isAlive():
            t.join(timeout=3.14)
