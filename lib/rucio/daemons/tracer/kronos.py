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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2021
# - Ralph Vigne <ralph.vigne@cern.ch>, 2014
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015-2021
# - Wen Guan <wen.guan@cern.ch>, 2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Robert Illingworth <illingwo@fnal.gov>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

"""
This daemon consumes tracer messages from ActiveMQ and updates the atime for replicas.
"""

import logging
import re
import socket
from datetime import datetime
from json import loads as jloads, dumps as jdumps
from os import getpid
from threading import Event, Thread, current_thread
from time import sleep, time

from stomp import Connection

import rucio.db.sqla.util
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.exception import ConfigNotFound, RSENotFound, DatabaseException
from rucio.common.logging import setup_logging, formatted_logger
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.config import get
from rucio.core.did import touch_dids, list_parent_dids
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.lock import touch_dataset_locks
from rucio.core.monitor import record_counter, record_timer
from rucio.core.replica import touch_replica, touch_collection_replicas, declare_bad_file_replicas
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import DIDType, BadFilesStatus

try:
    from Queue import Queue  # py2
except ImportError:
    from queue import Queue  # py3


logging.getLogger("stomp").setLevel(logging.CRITICAL)

graceful_stop = Event()


class AMQConsumer(object):
    def __init__(self, broker, conn, queue, chunksize, subscription_id, excluded_usrdns, dataset_queue, bad_files_patterns, logger=logging.log):
        self.__broker = broker
        self.__conn = conn
        self.__queue = queue
        self.__reports = []
        self.__ids = []
        self.__chunksize = chunksize
        self.__subscription_id = subscription_id
        # excluded states empty for the moment, maybe that should be recosidered in the future
        self.__excluded_states = set([])
        # exclude specific usrdns like GangaRBT
        self.__excluded_usrdns = excluded_usrdns
        self.__dataset_queue = dataset_queue
        self.__bad_files_patterns = bad_files_patterns
        self.__logger = logger

    def on_heartbeat_timeout(self):
        record_counter('daemons.tracer.kronos.heartbeat.lost')
        self.__conn.disconnect()

    def on_error(self, frame):
        record_counter('daemons.tracer.kronos.error')
        self.__logger(logging.ERROR, 'Message receive error: [%s] %s' % (self.__broker, frame.body))

    def on_message(self, frame):
        record_counter('daemons.tracer.kronos.reports')

        appversion = 'dq2'
        msg_id = frame.headers['message-id']
        if 'appversion' in frame.headers:
            appversion = frame.headers['appversion']

        if 'resubmitted' in frame.headers:
            record_counter('daemons.tracer.kronos.received_resubmitted')
            self.__logger(logging.WARNING, 'got a resubmitted report')

        try:
            if appversion == 'dq2':
                self.__conn.ack(msg_id, self.__subscription_id)
                return
            else:
                report = jloads(frame.body)
        except Exception:
            # message is corrupt, not much to do here
            # send count to graphite, send ack to broker and return
            record_counter('daemons.tracer.kronos.json_error')
            self.__logger(logging.ERROR, 'json error', exc_info=True)
            self.__conn.ack(msg_id, self.__subscription_id)
            return

        self.__ids.append(msg_id)
        self.__reports.append(report)

        try:
            self.__logger(logging.DEBUG, 'message received: %s %s %s' % (str(report['eventType']), report['filename'], report['remoteSite']))
        except Exception:
            pass

        if len(self.__ids) >= self.__chunksize:
            self.__update_atime()
            for msg_id in self.__ids:
                self.__conn.ack(msg_id, self.__subscription_id)

            self.__reports = []
            self.__ids = []

    def __update_atime(self):
        """
        Bulk update atime.
        """
        replicas = []
        rses = []
        for report in self.__reports:
            if 'vo' not in report:
                report['vo'] = 'def'

            try:
                # Identify suspicious files
                try:
                    if self.__bad_files_patterns and report['eventType'] in ['get_sm', 'get_sm_a', 'get'] and 'clientState' in report and report['clientState'] not in ['DONE', 'FOUND_ROOT', 'ALREADY_DONE']:
                        for pattern in self.__bad_files_patterns:
                            if 'stateReason' in report and report['stateReason'] and isinstance(report['stateReason'], str) and pattern.match(report['stateReason']):
                                reason = report['stateReason'][:255]
                                if 'url' not in report or not report['url']:
                                    self.__logger(logging.ERROR, 'Missing url in the following trace : ' + str(report))
                                else:
                                    try:
                                        surl = report['url']
                                        declare_bad_file_replicas([surl, ], reason=reason, issuer=InternalAccount('root', vo=report['vo']), status=BadFilesStatus.SUSPICIOUS)
                                        self.__logger(logging.INFO, 'Declare suspicious file %s with reason %s' % (report['url'], reason))
                                    except Exception as error:
                                        self.__logger(logging.ERROR, 'Failed to declare suspicious file' + str(error))
                except Exception as error:
                    self.__logger(logging.ERROR, 'Problem with bad trace : %s . Error %s' % (str(report), str(error)))

                # check if scope in report. if not skip this one.
                if 'scope' not in report:
                    record_counter('daemons.tracer.kronos.missing_scope')
                    if report['eventType'] != 'touch':
                        continue
                else:
                    record_counter('daemons.tracer.kronos.with_scope')
                    report['scope'] = InternalScope(report['scope'], report['vo'])

                # handle all events starting with get* and download and touch events.
                if not report['eventType'].startswith('get') and not report['eventType'].startswith('sm_get') and not report['eventType'] == 'download' and not report['eventType'] == 'touch':
                    continue
                if report['eventType'].endswith('_es'):
                    continue
                record_counter('daemons.tracer.kronos.total_get')
                if report['eventType'] == 'get':
                    record_counter('daemons.tracer.kronos.dq2clients')
                elif report['eventType'] == 'get_sm' or report['eventType'] == 'sm_get':
                    if report['eventVersion'] == 'aCT':
                        record_counter('daemons.tracer.kronos.panda_production_act')
                    else:
                        record_counter('daemons.tracer.kronos.panda_production')
                elif report['eventType'] == 'get_sm_a' or report['eventType'] == 'sm_get_a':
                    if report['eventVersion'] == 'aCT':
                        record_counter('daemons.tracer.kronos.panda_analysis_act')
                    else:
                        record_counter('daemons.tracer.kronos.panda_analysis')
                elif report['eventType'] == 'download':
                    record_counter('daemons.tracer.kronos.rucio_download')
                elif report['eventType'] == 'touch':
                    record_counter('daemons.tracer.kronos.rucio_touch')
                else:
                    record_counter('daemons.tracer.kronos.other_get')

                if report['eventType'] == 'download' or report['eventType'] == 'touch':
                    report['usrdn'] = report['account']

                if report['usrdn'] in self.__excluded_usrdns:
                    continue
                # handle touch and non-touch traces differently
                if report['eventType'] != 'touch':
                    # check if the report has the right state.
                    if 'eventVersion' in report:
                        if report['eventVersion'] != 'aCT':
                            if report['clientState'] in self.__excluded_states:
                                continue

                    if 'remoteSite' not in report:
                        continue
                    if not report['remoteSite']:
                        continue

                    if 'filename' not in report:
                        if 'name' in report:
                            report['filename'] = report['name']

                    rses = report['remoteSite'].strip().split(',')
                    for rse in rses:
                        try:
                            rse_id = get_rse_id(rse=rse, vo=report['vo'])
                        except RSENotFound:
                            self.__logger(logging.WARNING, "Cannot lookup rse_id for %s. Will skip this report.", rse)
                            record_counter('daemons.tracer.kronos.rse_not_found')
                            continue
                        replicas.append({'name': report['filename'], 'scope': report['scope'], 'rse': rse, 'rse_id': rse_id, 'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix']),
                                         'traceTimeentryUnix': report['traceTimeentryUnix'], 'eventVersion': report['eventVersion']})
                else:
                    # if touch event and if datasetScope is in the report then it means
                    # that there is no file scope/name and therefore only the dataset is
                    # put in the queue to be updated and the rest is skipped.
                    rse_id = None
                    rse = None
                    if 'remoteSite' in report:
                        rse = report['remoteSite']
                        try:
                            rse_id = get_rse_id(rse=rse, vo=report['vo'])
                        except RSENotFound:
                            self.__logger(logging.WARNING, "Cannot lookup rse_id for %s.", rse)
                            record_counter('daemons.tracer.kronos.rse_not_found')
                    if 'datasetScope' in report:
                        self.__dataset_queue.put({'scope': InternalScope(report['datasetScope'], vo=report['vo']),
                                                  'name': report['dataset'],
                                                  'rse_id': rse_id,
                                                  'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix'])})
                        continue
                    else:
                        if 'remoteSite' not in report:
                            continue
                        replicas.append({'name': report['filename'],
                                         'scope': report['scope'],
                                         'rse': rse,
                                         'rse_id': rse_id,
                                         'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix'])})

            except (KeyError, AttributeError):
                self.__logger(logging.ERROR, "Cannot handle report.", exc_info=True)
                record_counter('daemons.tracer.kronos.report_error')
                continue
            except Exception:
                self.__logger(logging.ERROR, "Exception", exc_info=True)
                continue

            for did in list_parent_dids(report['scope'], report['filename']):
                if did['type'] != DIDType.DATASET:
                    continue
                # do not update _dis datasets
                if did['scope'].external == 'panda' and '_dis' in did['name']:
                    continue
                for rse in rses:
                    try:
                        rse_id = get_rse_id(rse=rse, vo=report['vo'])
                    except RSENotFound:
                        self.__logger(logging.WARNING, "Cannot lookup rse_id for %s. Will skip this report.", rse)
                        record_counter('daemons.tracer.kronos.rse_not_found')
                        continue
                    self.__dataset_queue.put({'scope': did['scope'], 'name': did['name'], 'did_type': did['type'], 'rse_id': rse_id, 'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix'])})

        if not len(replicas):
            return

        self.__logger(logging.DEBUG, "trying to update replicas: %s", replicas)

        try:
            start_time = time()
            for replica in replicas:
                # if touch replica hits a locked row put the trace back into queue for later retry
                if not touch_replica(replica):
                    resubmit = {'filename': replica['name'],
                                'scope': replica['scope'].external,
                                'remoteSite': replica['rse'],
                                'traceTimeentryUnix': replica['traceTimeentryUnix'],
                                'eventType': 'get',
                                'usrdn': 'someuser',
                                'clientState': 'DONE',
                                'eventVersion': replica['eventVersion']}
                    if replica['scope'].vo != 'def':
                        resubmit['vo'] = replica['scope'].vo
                    self.__conn.send(body=jdumps(resubmit), destination=self.__queue, headers={'appversion': 'rucio', 'resubmitted': '1'})
                    record_counter('daemons.tracer.kronos.sent_resubmitted')
                    self.__logger(logging.WARNING, 'hit locked row, resubmitted to queue')
            record_timer('daemons.tracer.kronos.update_atime', (time() - start_time) * 1000)
        except Exception:
            self.__logger(logging.ERROR, "Cannot update replicas.", exc_info=True)
            record_counter('daemons.tracer.kronos.update_error')

        self.__logger(logging.INFO, 'updated %d replica(s)' % len(replicas))


def __get_broker_conns(brokers, port, use_ssl, vhost, reconnect_attempts, ssl_key_file, ssl_cert_file, timeout, logger=logging.log):
    logger(logging.DEBUG, 'resolving broker dns alias: %s' % brokers)

    brokers_resolved = []
    for broker in brokers:
        addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        brokers_resolved.extend(ai[4][0] for ai in addrinfos)

    logger(logging.DEBUG, 'broker resolved to %s', brokers_resolved)
    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            conns.append(Connection(host_and_ports=[(broker, port)],
                                    use_ssl=False,
                                    vhost=vhost,
                                    timeout=timeout,
                                    heartbeats=(0, 1000),
                                    reconnect_attempts_max=reconnect_attempts))
        else:
            conns.append(Connection(host_and_ports=[(broker, port)],
                                    use_ssl=True,
                                    ssl_key_file=ssl_key_file,
                                    ssl_cert_file=ssl_cert_file,
                                    vhost=vhost,
                                    timeout=timeout,
                                    heartbeats=(0, 1000),
                                    reconnect_attempts_max=reconnect_attempts))
    return conns


def kronos_file(thread=0, dataset_queue=None, sleep_time=60):
    """
    Main loop to consume tracer reports.
    """

    logging.info('kronos_file[%i/?] starting', thread)

    executable = 'kronos-file'
    hostname = socket.gethostname()
    pid = getpid()
    hb_thread = current_thread()

    chunksize = config_get_int('tracer-kronos', 'chunksize')
    prefetch_size = config_get_int('tracer-kronos', 'prefetch_size')
    subscription_id = config_get('tracer-kronos', 'subscription_id')
    try:
        bad_files_patterns = []
        pattern = get(section='kronos', option='bad_files_patterns', session=None)
        pattern = str(pattern)
        patterns = pattern.split(",")
        for pat in patterns:
            bad_files_patterns.append(re.compile(pat.strip()))
    except ConfigNotFound:
        bad_files_patterns = []
    except Exception as error:
        logging.log(logging.ERROR, 'kronos_file[%i/?] Failed to get bad_file_patterns %s', thread, str(error))
        bad_files_patterns = []

    use_ssl = True
    try:
        use_ssl = config_get_bool('tracer-kronos', 'use_ssl')
    except Exception:
        pass

    if not use_ssl:
        username = config_get('tracer-kronos', 'username')
        password = config_get('tracer-kronos', 'password')

    excluded_usrdns = set(config_get('tracer-kronos', 'excluded_usrdns').split(','))
    vhost = config_get('tracer-kronos', 'broker_virtual_host', raise_exception=False)

    brokers_alias = [b.strip() for b in config_get('tracer-kronos', 'brokers').split(',')]
    port = config_get_int('tracer-kronos', 'port')
    reconnect_attempts = config_get_int('tracer-kronos', 'reconnect_attempts')
    ssl_key_file = config_get('tracer-kronos', 'ssl_key_file', raise_exception=False)
    ssl_cert_file = config_get('tracer-kronos', 'ssl_cert_file', raise_exception=False)

    sanity_check(executable=executable, hostname=hostname)
    while not graceful_stop.is_set():
        start_time = time()
        heart_beat = live(executable, hostname, pid, hb_thread)
        prepend_str = 'kronos-file[%i/%i] ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
        logger = formatted_logger(logging.log, prepend_str + '%s')
        conns = __get_broker_conns(brokers=brokers_alias,
                                   port=port,
                                   use_ssl=use_ssl,
                                   vhost=vhost,
                                   reconnect_attempts=reconnect_attempts,
                                   ssl_key_file=ssl_key_file,
                                   ssl_cert_file=ssl_cert_file,
                                   timeout=sleep_time,
                                   logger=logger)
        for conn in conns:
            if not conn.is_connected():
                logger(logging.INFO, 'connecting to %s' % str(conn.transport._Transport__host_and_ports[0]))
                record_counter('daemons.tracer.kronos.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0])
                conn.set_listener('rucio-tracer-kronos', AMQConsumer(broker=conn.transport._Transport__host_and_ports[0],
                                                                     conn=conn,
                                                                     queue=config_get('tracer-kronos', 'queue'),
                                                                     chunksize=chunksize,
                                                                     subscription_id=subscription_id,
                                                                     excluded_usrdns=excluded_usrdns,
                                                                     dataset_queue=dataset_queue,
                                                                     bad_files_patterns=bad_files_patterns,
                                                                     logger=logger))
                if not use_ssl:
                    conn.connect(username, password)
                else:
                    conn.connect()
                conn.subscribe(destination=config_get('tracer-kronos', 'queue'), ack='client-individual', id=subscription_id, headers={'activemq.prefetchSize': prefetch_size})

        tottime = time() - start_time
        if tottime < sleep_time:
            logger(logging.INFO, 'Will sleep for %s seconds' % (sleep_time - tottime))
            sleep(sleep_time - tottime)

    logger(logging.INFO, 'graceful stop requested')

    for conn in conns:
        try:
            conn.disconnect()
        except Exception:
            pass

    die(executable=executable, hostname=hostname, pid=pid, thread=thread)
    logger(logging.INFO, 'graceful stop done')


def kronos_dataset(thread=0, dataset_queue=None, sleep_time=60):
    logging.info('kronos-dataset[%d/?] starting', thread)

    executable = 'kronos-dataset'
    hostname = socket.gethostname()
    pid = getpid()
    hb_thread = current_thread()

    dataset_wait = config_get_int('tracer-kronos', 'dataset_wait')
    start = datetime.now()
    sanity_check(executable=executable, hostname=hostname)
    while not graceful_stop.is_set():
        start_time = time()
        heart_beat = live(executable, hostname, pid, hb_thread)
        prepend_str = 'kronos-dataset[%i/%i] ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
        logger = formatted_logger(logging.log, prepend_str + '%s')
        if (datetime.now() - start).seconds > dataset_wait:
            __update_datasets(dataset_queue, logger=logger)
            start = datetime.now()

        tottime = time() - start_time
        if tottime < sleep_time:
            logger(logging.INFO, 'Will sleep for %s seconds' % (sleep_time - tottime))
            sleep(sleep_time - tottime)

    die(executable=executable, hostname=hostname, pid=pid, thread=thread)

    # once again for the backlog
    logger(logging.INFO, 'cleaning dataset backlog before shutdown...')
    __update_datasets(dataset_queue)


def __update_datasets(dataset_queue, logger=logging.log):
    len_ds = dataset_queue.qsize()
    datasets = {}
    dslocks = {}
    now = time()
    for _ in range(0, len_ds):
        dataset = dataset_queue.get()
        did = '%s:%s' % (dataset['scope'].internal, dataset['name'])
        rse = dataset['rse_id']
        if did not in datasets:
            datasets[did] = dataset['accessed_at']
        else:
            datasets[did] = max(datasets[did], dataset['accessed_at'])

        if rse is None:
            continue
        if did not in dslocks:
            dslocks[did] = {}
        if rse not in dslocks[did]:
            dslocks[did][rse] = dataset['accessed_at']
        else:
            dslocks[did][rse] = max(dataset['accessed_at'], dslocks[did][rse])
    logger(logging.INFO, 'fetched %d datasets from queue (%ds)' % (len_ds, time() - now))

    total, failed, start = 0, 0, time()
    for did, accessed_at in datasets.items():
        scope, name = did.split(':')
        scope = InternalScope(scope, fromExternal=False)
        update_did = {'scope': scope, 'name': name, 'type': DIDType.DATASET, 'accessed_at': accessed_at}
        # if update fails, put back in queue and retry next time
        if not touch_dids((update_did,)):
            update_did['rse_id'] = None
            dataset_queue.put(update_did)
            failed += 1
        total += 1
    logger(logging.INFO, 'update done for %d datasets, %d failed (%ds)' % (total, failed, time() - start))

    total, failed, start = 0, 0, time()
    for did, rses in dslocks.items():
        scope, name = did.split(':')
        scope = InternalScope(scope, fromExternal=False)
        for rse, accessed_at in rses.items():
            update_dslock = {'scope': scope, 'name': name, 'rse_id': rse, 'accessed_at': accessed_at}
            # if update fails, put back in queue and retry next time
            if not touch_dataset_locks((update_dslock,)):
                dataset_queue.put(update_dslock)
                failed += 1
            total += 1
    logger(logging.INFO, 'update done for %d locks, %d failed (%ds)' % (total, failed, time() - start))

    total, failed, start = 0, 0, time()
    for did, rses in dslocks.items():
        scope, name = did.split(':')
        scope = InternalScope(scope, fromExternal=False)
        for rse, accessed_at in rses.items():
            update_dslock = {'scope': scope, 'name': name, 'rse_id': rse, 'accessed_at': accessed_at}
            # if update fails, put back in queue and retry next time
            if not touch_collection_replicas((update_dslock,)):
                dataset_queue.put(update_dslock)
                failed += 1
            total += 1
    logger(logging.INFO, 'update done for %d collection replicas, %d failed (%ds)' % (total, failed, time() - start))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(threads=1, sleep_time_datasets=60, sleep_time_files=60):
    """
    Starts up the consumer threads
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    dataset_queue = Queue()
    logging.info('starting tracer consumer threads')

    thread_list = []
    for thread in range(0, threads):
        thread_list.append(Thread(target=kronos_file, kwargs={'thread': thread,
                                                              'sleep_time': sleep_time_files,
                                                              'dataset_queue': dataset_queue}))
        thread_list.append(Thread(target=kronos_dataset, kwargs={'thread': thread,
                                                                 'sleep_time': sleep_time_datasets,
                                                                 'dataset_queue': dataset_queue}))

    [thread.start() for thread in thread_list]

    logging.info('waiting for interrupts')

    while len(thread_list) > 0:
        thread_list = [thread.join(timeout=3) for thread in thread_list if thread and thread.isAlive()]
