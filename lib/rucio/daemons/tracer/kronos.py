# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

"""
This daemon consumes tracer messages from ActiveMQ and updates the atime for replicas.
"""

from datetime import datetime
from dns import resolver
import logging
from ssl import PROTOCOL_TLSv1
from sys import stdout
from threading import Event, Thread
from time import sleep, time
from traceback import format_exc
from Queue import Queue

from json import loads as jloads
from stomp import Connection

from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.core.monitor import record_counter, record_timer
from rucio.core.did import touch_dids, list_parent_dids
from rucio.core.lock import touch_dataset_locks
from rucio.core.replica import touch_replicas
from rucio.db.constants import DIDType

logging.getLogger("stomp").setLevel(logging.CRITICAL)

logging.basicConfig(stream=stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = Event()


class AMQConsumer(object):
    def __init__(self, broker, conn, chunksize, subscription_id, excluded_usrdns, dataset_queue):
        self.__broker = broker
        self.__conn = conn
        self.__reports = []
        self.__ids = []
        self.__chunksize = chunksize
        self.__subscription_id = subscription_id
        # excluded states empty for the moment, maybe that should be recosidered in the future
        self.__excluded_states = set([])
        # exclude specific usrdns like GangaRBT
        self.__excluded_usrdns = excluded_usrdns
        self.__dataset_queue = dataset_queue

    def on_error(self, headers, message):
        record_counter('daemons.tracer.kronos.error')
        logging.error('[%s] %s' % (self.__broker, message))

    def on_message(self, headers, message):
        record_counter('daemons.tracer.kronos.reports')

        appversion = 'dq2'
        id = headers['message-id']
        if 'appversion' in headers:
            appversion = headers['appversion']

        try:
            if appversion == 'dq2':
                self.__conn.ack(id, self.__subscription_id)
                return
            else:
                report = jloads(message)
        except:
            # message is corrupt, not much to do here
            # send count to graphite, send ack to broker and return
            record_counter('daemons.tracer.kronos.json_error')
            logging.error('json error')
            self.__conn.ack(id, self.__subscription_id)
            return

        self.__ids.append(id)
        self.__reports.append(report)

        try:
            logging.debug('message received: %s %s %s' % (str(report['eventType']), report['filename'], report['remoteSite']))
        except:
            pass

        if len(self.__ids) >= self.__chunksize:
            self.__update_atime()
            for id in self.__ids:
                self.__conn.ack(id, self.__subscription_id)

            self.__reports = []
            self.__ids = []

    def __update_atime(self):
        """
        Bulk update atime.
        """
        replicas = []
        for report in self.__reports:
            try:
                # check if scope in report. if not skip this one.
                if 'scope' not in report:
                    record_counter('daemons.tracer.kronos.missing_scope')
                    continue
                else:
                    record_counter('daemons.tracer.kronos.with_scope')

                # for the moment only report with eventType get* are handled.
                if not report['eventType'].startswith('get'):
                    continue
                record_counter('daemons.tracer.kronos.total_get')
                if report['eventType'] == 'get':
                    record_counter('daemons.tracer.kronos.dq2clients')
                elif report['eventType'] == 'get_sm':
                    record_counter('daemons.tracer.kronos.panda_production')
                elif report['eventType'] == 'get_sm_a':
                    record_counter('daemons.tracer.kronos.panda_analysis')
                else:
                    record_counter('daemons.tracer.kronos.other_get')

                # check if the report has the right state.
                if report['clientState'] in self.__excluded_states:
                    continue

                if report['usrdn'] in self.__excluded_usrdns:
                    continue
                if not report['remoteSite']:
                    continue
                replicas.append({'name': report['filename'], 'scope': report['scope'], 'rse': report['remoteSite'], 'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix'])})
            except (KeyError, AttributeError):
                logging.error(format_exc())
                record_counter('daemons.tracer.kronos.report_error')
                continue

            for did in list_parent_dids(report['scope'], report['filename']):
                if did['type'] != DIDType.DATASET:
                    continue
                self.__dataset_queue.put({'scope': did['scope'], 'name': did['name'], 'did_type': did['type'], 'rse': report['remoteSite'], 'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix'])})

        logging.info(replicas)

        try:
            ts = time()
            touch_replicas(replicas)
            record_timer('daemons.tracer.kronos.update_atime', (time() - ts) * 1000)
        except:
            logging.error(format_exc())
            record_counter('daemons.tracer.kronos.update_error')

        logging.info('updated %d replicas' % len(replicas))


def kronos_file(once=False, process=0, total_processes=1, thread=0, total_threads=1, brokers_resolved=None, dataset_queue=None):
    """
    Main loop to consume tracer reports.
    """

    logging.info('tracer consumer starting')

    chunksize = config_get_int('tracer-kronos', 'chunksize')
    prefetch_size = config_get_int('tracer-kronos', 'prefetch_size')
    subscription_id = config_get('tracer-kronos', 'subscription_id')

    use_ssl = True
    try:
        use_ssl = config_get_bool('tracer-kronos', 'use_ssl')
    except:
        pass

    if not use_ssl:
        username = config_get('tracer-kronos', 'username')
        password = config_get('tracer-kronos', 'password')

    excluded_usrdns = set(config_get('tracer-kronos', 'excluded_usrdns').split(','))

    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            conns.append(Connection(host_and_ports=[(broker, config_get_int('tracer-kronos', 'port'))],
                                    use_ssl=False,
                                    reconnect_attempts_max=config_get_int('tracer-kronos', 'reconnect_attempts')))
        else:
            conns.append(Connection(host_and_ports=[(broker, config_get_int('tracer-kronos', 'port'))],
                                    use_ssl=True,
                                    ssl_key_file=config_get('tracer-kronos', 'ssl_key_file'),
                                    ssl_cert_file=config_get('tracer-kronos', 'ssl_cert_file'),
                                    ssl_version=PROTOCOL_TLSv1,
                                    reconnect_attempts_max=config_get_int('tracer-kronos', 'reconnect_attempts')))

    logging.info('tracer consumer started')

    while not graceful_stop.is_set():
        for conn in conns:
            if not conn.is_connected():
                logging.info('connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                record_counter('daemons.tracer.kronos.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0].split('.')[0])
                conn.set_listener('rucio-tracer-kronos', AMQConsumer(broker=conn.transport._Transport__host_and_ports[0], conn=conn, chunksize=chunksize, subscription_id=subscription_id, excluded_usrdns=excluded_usrdns, dataset_queue=dataset_queue))
                conn.start()
                if not use_ssl:
                    conn.connect(username, password)
                else:
                    conn.connect()
                conn.subscribe(destination=config_get('tracer-kronos', 'queue'), ack='client-individual', id=subscription_id, headers={'activemq.prefetchSize': prefetch_size})
        sleep(1)

    logging.info('graceful stop requested')

    for conn in conns:
        try:
            conn.disconnect()
        except:
            pass

    logging.info('graceful stop done')


def kronos_dataset(once=False, process=0, total_processes=1, thread=0, total_threads=1, dataset_queue=None):
    dataset_wait = config_get_int('tracer-kronos', 'dataset_wait')
    start = datetime.now()
    while not graceful_stop.is_set():
        if (datetime.now() - start).seconds > dataset_wait:
            __update_datasets(dataset_queue)
            start = datetime.now()
        sleep(10)
    # once again for the backlog
    logging.info('cleaning dataset backlog before shutdown...')
    __update_datasets(dataset_queue)


def __update_datasets(dataset_queue):
    len_ds = dataset_queue.qsize()
    datasets = {}
    dslocks = {}
    logging.info('(kronos_dataset) trying to fetch %d datasets from queue' % len_ds)
    for i in xrange(0, len_ds):
        dataset = dataset_queue.get()
        did = dataset['scope'] + ":" + dataset['name']
        rse = dataset['rse']
        if did not in datasets:
            datasets[did] = dataset['accessed_at']
        else:
            datasets[did] = max(datasets[did], dataset['accessed_at'])

        if did not in dslocks:
            dslocks[did] = {}
        if rse not in dslocks[did]:
            dslocks[did][rse] = dataset['accessed_at']
        else:
            dslocks[did][rse] = max(dataset['accessed_at'], dslocks[did][rse])

    update_dids = []
    update_dslocks = []
    for did, accessed_at in datasets.items():
        scope, name = did.split(':')
        update_dids.append({'scope': scope, 'name': name, 'type': DIDType.DATASET, 'accessed_at': accessed_at})

    for did, rses in dslocks.items():
        scope, name = did.split(':')
        for rse, accessed_at in rses.items():
            update_dslocks.append({'scope': scope, 'name': name, 'rse': rse, 'accessed_at': accessed_at})

    logging.info('(kronos_dataset) trying to update %d datasets atime' % len(update_dids))
    touch_dids(update_dids)
    touch_dataset_locks(update_dslocks)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1):
    """
    Starts up the consumer threads
    """
    logging.info('resolving brokers')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('tracer-kronos', 'brokers').split(',')]
    except:
        raise Exception('Could not load brokers from configuration')

    logging.info('resolving broker dns alias: %s' % brokers_alias)

    brokers_resolved = []
    for broker in brokers_alias:
        brokers_resolved.append([str(tmp_broker) for tmp_broker in resolver.query(broker, 'A')])
    brokers_resolved = [item for sublist in brokers_resolved for item in sublist]

    logging.debug('brokers resolved to %s', brokers_resolved)

    dataset_queue = Queue()
    logging.info('starting tracer consumer threads')
    threads = []
    for i in xrange(0, total_threads):
        threads.append(Thread(target=kronos_file, kwargs={'process': process, 'total_processes': total_processes, 'thread': i, 'total_threads': total_threads, 'brokers_resolved': brokers_resolved, 'dataset_queue': dataset_queue}))
        threads.append(Thread(target=kronos_dataset, kwargs={'process': process, 'total_processes': total_processes, 'thread': i, 'total_threads': total_threads, 'dataset_queue': dataset_queue}))

    [t.start() for t in threads]

    logging.info('waiting for interrupts')

    while len(threads) > 0:
        [t.join(timeout=3) for t in threads if t and t.isAlive()]
