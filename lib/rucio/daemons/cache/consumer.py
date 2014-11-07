# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wguan@cern.ch>, 2014

"""
Fax consumer is a daemon to retrieve rucio cache operation information to synchronize rucio catalog.
"""

import logging
import ssl
import sys
import threading
import time

import dns.resolver
import json
import stomp

from traceback import format_exc

from rucio.api.did import get_metadata
from rucio.api.replica import add_replicas, delete_replicas
from rucio.api.rse import get_rse
from rucio.common.config import config_get, config_get_int
from rucio.common import exception
from rucio.common.schema import validate_schema
from rucio.core.monitor import record_counter

VOLATILE_ERROR = -1
DID_NOT_FOUND = -2
META_MISMATCH = -3
ADD_REPLICA_ERROR = -4
DEL_REPLICA_ERROR = -5


logging.getLogger("stomp").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


class RSE_Volatile:
    def __init__(self):
        self.__rses = {}

    def get_volatile(self, rse):
        if rse in self.__rses:
            return self.__rses[rse]

        rse_attributes = get_rse(rse)
        self.__rses[rse] = rse_attributes["volatile"]
        return self.__rses[rse]


def cache_add_replicas(rse, files, account, lifetime):
    """ Rucio Cache add replicas """

    return_code = 0
    for file in files:
        # check metadata
        try:
            metadata = get_metadata(file["scope"], file["name"])
        except exception.DataIdentifierNotFound:
            logging.error("%s:%s not found. Skip to add it to replicas" % (file["scope"], file["name"]))
            logging.error(str(format_exc()))
            return_code = DID_NOT_FOUND
            continue
        if int(metadata["bytes"]) != int(file["bytes"]) or metadata["adler32"] != file["adler32"]:
            logging.error("%s:%s(bytes:%s, adler32:%s) has different size or checksum with metadata(bytes:%s, adler32:%s). Skip to add it to replicas" % (file["scope"], file["name"], file["bytes"], file["adler32"], metadata["bytes"], metadata["adler32"]))
            return_code = META_MISMATCH
            continue

        # add replica
        try:
            add_replicas(rse, [file], issuer=account)
        except exception.Duplicate:
            logging.warn("%s:%s already exists in %s with error details: %s" % (file["scope"], file["name"], rse, str(format_exc())))
            return_code = ADD_REPLICA_ERROR

    return return_code


def cache_delete_replicas(rse, files, account):
    """ Rucio Cache delete replicas """

    return_code = 0
    for file in files:
        # delete replica
        try:
            delete_replicas(rse, [file], issuer=account)
        except exception.ReplicaNotFound:
            logging.warn("%s:%s doesn't exists in %s, cannot delete, with error details: %s" % (file["scope"], file["name"], rse, str(format_exc())))
            return_code = DEL_REPLICA_ERROR

    return return_code


class Consumer(object):

    def __init__(self, broker, account, id, num_thread):
        self.__broker = broker
        self.__account = account
        self.__id = id
        self.__num_thread = num_thread
        self.__rse_volatile = RSE_Volatile()

    def on_error(self, headers, message):
        record_counter('daemons.cache.consumer.error')
        logging.error('[%s] %s' % (self.__broker, message))

    def on_message(self, headers, message):
        record_counter('daemons.cache.consumer2.message')

        msg = json.loads(message)
        id = msg['id']
        if id % self.__num_thread == self.__id:
            self.message_handle(msg['payload'])

    def message_handle(self, msg):
        record_counter('daemons.cache.consumer.message_handle.message')

        try:
            if isinstance(msg, dict) and 'operation' in msg.keys():
                if msg['operation'] == 'add_replicas':
                    validate_schema(name='cache_add_replicas', obj=msg)
                    if 'rse' in msg.keys() and 'files' in msg.keys():
                        logging.debug('[%s] %s %s %s' % (self.__broker, msg['operation'], msg['rse'], msg['files']))
                        try:
                            if not self.__rse_volatile.get_volatile(msg['rse']):
                                logging.error("%s volatile is not True, Rucio Cache should not update it." % (msg['rse']))
                            else:
                                cache_add_replicas(rse=msg['rse'], files=msg['files'], account=self.__account, lifetime=msg['lifetime'])
                        except Exception, e:
                            logging.error('[%s] %s %s %s %s with error details: %s' % (self.__broker, msg['operation'], msg['rse'], msg['files'], str(e), str(format_exc())))

                if msg['operation'] == 'delete_replicas':
                    validate_schema(name='cache_delete_replicas', obj=msg)
                    if 'rse' in msg.keys() and 'files' in msg.keys():
                        logging.debug('[%s] %s %s %s' % (self.__broker, msg['operation'], msg['rse'], msg['files']))
                        try:
                            if not self.__rse_volatile.get_volatile(msg['rse']):
                                logging.error("%s volatile is not True, Rucio Cache should not update it." % (msg['rse']))
                            else:
                                cache_delete_replicas(rse=msg['rse'], files=msg['files'], account=self.__account)
                        except Exception, e:
                            logging.error('[%s] %s %s %s %s with error details: %s' % (self.__broker, msg['operation'], msg['rse'], msg['files'], str(e), str(format_exc())))

        except Exception, e:
            logging.error('[%s] %s %s %s %s with error details: %s' % (self.__broker, msg['operation'], msg['rse'], msg['files'], str(e), str(format_exc())))
            return


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

    while not graceful_stop.is_set():

        for conn in conns:

            if not conn.is_connected():
                logging.info('connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                record_counter('daemons.messaging.cache.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0].split('.')[0])

                conn.set_listener('rucio-cache-messaging', conns[conn])
                conn.start()
                conn.connect()
                conn.subscribe(destination=config_get('messaging-cache', 'destination'),
                               id='rucio-cache-messaging',
                               ack='auto',
                               headers={'selector': 'vo = \'%s\'' % config_get('messaging-cache', 'voname')})

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


def run(num_thread=1):
    """
    Starts up the rucio cache consumer thread
    """

    logging.info('starting consumer thread')
    threads = [threading.Thread(target=consumer, kwargs={'id': i, 'num_thread': num_thread}) for i in xrange(0, num_thread)]

    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while (t.isAlive()):
        t.join(timeout=3.14)
