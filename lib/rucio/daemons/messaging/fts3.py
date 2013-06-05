# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

"""
This daemon consumes STOMP notifications of FTS3.
"""

import datetime
import threading
import time

import json
import stomp

from rucio.db.constants import FTSState, RequestState
from rucio.core.monitor import record
from rucio.core.request import set_request_state
from rucio.common.config import config_get, config_get_int

graceful_stop = threading.Event()


class Consumer(object):

    def __init__(self, broker):
        self.__broker = broker

    def on_error(self, headers, message):
        record('messaging.fts3.error')
        print '[%s %s] ERROR: %s' % (self.__broker, datetime.datetime.now(), message)

    def on_message(self, headers, message):
        record('messaging.fts3.message')
        msg = json.loads(message[:-1])  # message always ends with an unparseable EOT character

        if msg['job_metadata'] != '':
            if msg['job_state'] == FTSState.FINISHED:
                set_request_state(msg['job_metadata']['request_id'], RequestState.DONE)


def consumer():
    """
    Main loop to consume messages from the FTS3 producer.
    """

    print 'consumer: starting'

    brokers = []
    try:
        brokers = [b.strip() for b in config_get('messaging-fts3', 'brokers').split(',')]
    except:
        raise Exception('Could not load brokers from configuration')

    conns = []
    for broker in brokers:
        conns.append(stomp.Connection(host_and_ports=[(broker, config_get_int('messaging-fts3', 'port'))],
                                      use_ssl=True,
                                      ssl_key_file=config_get('messaging-fts3', 'ssl_key_file'),
                                      ssl_cert_file=config_get('messaging-fts3', 'ssl_cert_file')))

    print 'consumer: started'

    while not graceful_stop.is_set():

        for conn in conns:

            if not conn.is_connected():

                print 'consumer: connecting to', conn._Connection__host_and_ports[0][0]
                record('messaging.fts3.reconnect.%s' % conn._Connection__host_and_ports[0][0].split('.')[0])

                conn.set_listener('rucio-messaging-fts3', Consumer(broker=conn._Connection__host_and_ports[0]))
                conn.start()
                conn.connect(headers={'client-id': 'rucio-messaging-fts3'}, wait=True)
                conn.subscribe(destination=config_get('messaging-fts3', 'destination'),
                               ack='auto',
                               headers={'selector': 'vo = \'atlas\''})

        time.sleep(1)

    print 'submitter: graceful stop requested'

    for conn in conns:
        try:
            conn.disconnect()
        except:
            pass

    print 'submitter: graceful stop done'


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run():
    """
    Starts up the messenger threads
    """

    print 'main: starting threads'

    thread = threading.Thread(target=consumer)
    thread.start()

    print 'main: waiting for interrupts'

    # Interruptible joins require a timeout.
    while thread.is_alive:
        thread.join(timeout=3.14)
