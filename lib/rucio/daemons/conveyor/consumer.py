# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014

"""
Conveyor is a daemon to manage file transfers.
"""

import hashlib
import logging
import sys
import threading
import time
import traceback

import dns.resolver
import json
import stomp

from rucio.common.config import config_get, config_get_int
from rucio.core.monitor import record_counter
from rucio.daemons.conveyor.common import update_request_state
from rucio.db.constants import RequestState, FTSCompleteState

logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("stomp").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


class Consumer(object):

    def __init__(self, broker, id, total_threads):
        self.__broker = broker
        self.__id = id
        self.__total_threads = total_threads

    def on_error(self, headers, message):
        record_counter('daemons.conveyor.consumer.error')
        logging.error('[%s] %s' % (self.__broker, message))

    def on_message(self, headers, message):
        record_counter('daemons.conveyor.consumer.message_all')

        msg = json.loads(message[:-1])  # message always ends with an unparseable EOT character
        if 'job_metadata' in msg.keys() \
           and isinstance(msg['job_metadata'], dict) \
           and 'issuer' in msg['job_metadata'].keys() \
           and str(msg['job_metadata']['issuer']) == str('rucio'):

            if 'job_m_replica' in msg.keys() and 'job_state' in msg.keys() \
               and (str(msg['job_m_replica']) == str('false') or (str(msg['job_m_replica']) == str('true') and str(msg['job_state']) != str('ACTIVE'))):
                request_id = msg['job_metadata']['request_id']
                if not int(hashlib.md5(request_id).hexdigest(), 16) % self.__total_threads == self.__id:
                    return

                response = {'new_state': None,
                            'transfer_id': msg.get('tr_id').split("__")[-1],
                            'job_state': msg.get('t_final_transfer_state', None),
                            'src_url': msg.get('src_url', None),
                            'dst_url': msg.get('dst_url', None),
                            'duration': (float(msg.get('tr_timestamp_complete', 0)) - float(msg.get('tr_timestamp_start', 0)))/1000,
                            'reason': msg.get('t__error_message', None),
                            'scope': msg['job_metadata'].get('scope', None),
                            'name': msg['job_metadata'].get('name', None),
                            'src_rse': msg['job_metadata'].get('src_rse', None),
                            'dst_rse': msg['job_metadata'].get('dst_rse', None),
                            'request_id': msg['job_metadata'].get('request_id', None),
                            'activity': msg['job_metadata'].get('activity', None),
                            'dest_rse_id': msg['job_metadata'].get('dest_rse_id', None),
                            'previous_attempt_id': msg['job_metadata'].get('previous_attempt_id', None),
                            'adler32': msg['job_metadata'].get('adler32', None),
                            'md5': msg['job_metadata'].get('md5', None),
                            'filesize': msg['job_metadata'].get('filesize', None),
                            'external_host': msg.get('endpnt', None),
                            'job_m_replica': msg.get('job_m_replica', None),
                            'details': {'files': msg['job_metadata']}}

                record_counter('daemons.conveyor.consumer.message_rucio')
                if str(msg['t_final_transfer_state']) == str(FTSCompleteState.OK):
                    response['new_state'] = RequestState.DONE
                elif str(msg['t_final_transfer_state']) == str(FTSCompleteState.ERROR):
                    response['new_state'] = RequestState.FAILED

                try:
                    if response['new_state']:
                        logging.debug('DID %s:%s FROM %s TO %s STATE %s' % (msg['job_metadata']['scope'],
                                                                            msg['job_metadata']['name'],
                                                                            msg['job_metadata']['src_rse'],
                                                                            msg['job_metadata']['dst_rse'],
                                                                            response['new_state']))

                        update_request_state(response)
                        record_counter('daemons.conveyor.consumer.update_request_state')
                except:
                    logging.critical(traceback.format_exc())


def consumer(id, total_threads=1):
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

                conn.set_listener('rucio-messaging-fts3', Consumer(broker=conn.transport._Transport__host_and_ports[0], id=id, total_threads=total_threads))
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
    Starts up the consumer thread
    """

    logging.info('starting consumer thread')
    threads = [threading.Thread(target=consumer, kwargs={'id': i, 'total_threads': total_threads}) for i in xrange(0, total_threads)]
    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while t.isAlive():
        t.join(timeout=3.14)
