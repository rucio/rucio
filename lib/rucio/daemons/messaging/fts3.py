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

import threading
import time
import traceback

import stomp


graceful_stop = threading.Event()


class Consumer(object):

    def on_error(self, headers, message):
        print 'Error: %s' % message

    def on_message(self, headers, message):
        print 'Message: %s' % message


def consumer():
    """
    Main loop to consume messages from the FTS3 producer.
    """

    print 'consumer: starting'

    conn = stomp.Connection(host_and_ports=[('gridmsg107.cern.ch', 6162), ('gridmsg108.cern.ch', 6162), ('gridmsg109.cern.ch', 6162)],
                            use_ssl=True,
                            ssl_key_file='/home/mario/.ssh/hostkey.pem',
                            ssl_cert_file='/home/mario/.ssh/hostcert.pem')

    print 'consumer: started'

    while not graceful_stop.is_set():

        try:

            if not conn.is_connected():

                print 'consumer: connecting'

                conn.set_listener('rucio-messaging-fts3', Consumer())
                conn.start()
                conn.connect(headers={'client-id': 'rucio-messaging-fts3'}, wait=True)
                conn.subscribe(destination='/queue/Consumer.test_fts3.transfer.fts_monitoring_state',
                               ack='auto',
                               headers={'selector': 'vo = \'atlas\''})

            time.sleep(0.1)

        except:
            print traceback.format_exc()

    print 'submitter: graceful stop requested'

    conn.disconnect()

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
