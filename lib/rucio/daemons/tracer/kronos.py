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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2014
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015
# - Wen Guan <wguan.icedew@gmail.com>, 2015
# - Cedric Serfon <cedric.serfon@cern,ch>, 2018
# - Robert Illingworth <illingwo@fnal.gov>, 2018
#
# PY3K COMPATIBLE

"""
This daemon consumes tracer messages from ActiveMQ and updates the atime for replicas.
"""

import logging
import re
import socket

from datetime import datetime
from json import loads as jloads, dumps as jdumps
from os import getpid
try:
    from Queue import Queue  # py2
except ImportError:
    from queue import Queue  # py3
from sys import stdout
from threading import Event, Thread, current_thread
from time import sleep, time
from traceback import format_exc

from stomp import Connection

from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.exception import ConfigNotFound
from rucio.core.monitor import record_counter, record_timer
from rucio.core.config import get
from rucio.core.did import touch_dids, list_parent_dids
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.lock import touch_dataset_locks
from rucio.core.replica import touch_replica, touch_collection_replicas, declare_bad_file_replicas
from rucio.db.sqla.constants import DIDType, BadFilesStatus

logging.getLogger("stomp").setLevel(logging.CRITICAL)

logging.basicConfig(stream=stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = Event()


class AMQConsumer(object):
    def __init__(self, broker, conn, queue, chunksize, subscription_id, excluded_usrdns, dataset_queue, bad_files_patterns):
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

    def on_error(self, headers, message):
        record_counter('daemons.tracer.kronos.error')
        logging.error('[%s] %s' % (self.__broker, message))

    def on_message(self, headers, message):
        record_counter('daemons.tracer.kronos.reports')

        appversion = 'dq2'
        msg_id = headers['message-id']
        if 'appversion' in headers:
            appversion = headers['appversion']

        if 'resubmitted' in headers:
            record_counter('daemons.tracer.kronos.received_resubmitted')
            logging.warning('(kronos_file) got a resubmitted report')

        try:
            if appversion == 'dq2':
                self.__conn.ack(msg_id, self.__subscription_id)
                return
            else:
                report = jloads(message)
        except Exception:
            # message is corrupt, not much to do here
            # send count to graphite, send ack to broker and return
            record_counter('daemons.tracer.kronos.json_error')
            logging.error('(kronos_file) json error')
            self.__conn.ack(msg_id, self.__subscription_id)
            return

        self.__ids.append(msg_id)
        self.__reports.append(report)

        try:
            logging.debug('(kronos_file) message received: %s %s %s' % (str(report['eventType']), report['filename'], report['remoteSite']))
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
            try:
                # Identify suspicious files
                try:
                    if self.__bad_files_patterns and report['eventType'] in ['get_sm', 'get_sm_a', 'get'] and 'clientState' in report and report['clientState'] not in ['DONE', 'FOUND_ROOT', 'ALREADY_DONE']:
                        for pattern in self.__bad_files_patterns:
                            if 'stateReason' in report and report['stateReason'] and isinstance(report['stateReason'], str) and pattern.match(report['stateReason']):
                                reason = report['stateReason'][:255]
                                if 'url' not in report or not report['url']:
                                    logging.error('Missing url in the following trace : ' + str(report))
                                else:
                                    try:
                                        surl = report['url']
                                        declare_bad_file_replicas([surl, ], reason=reason, issuer='root', status=BadFilesStatus.SUSPICIOUS)
                                        logging.info('Declare suspicious file %s with reason %s' % (report['url'], reason))
                                    except Exception as error:
                                        logging.error('Failed to declare suspicious file' + str(error))
                except Exception as error:
                    logging.error('Problem with bad trace : %s . Error %s' % (str(report), str(error)))

                # check if scope in report. if not skip this one.
                if 'scope' not in report:
                    record_counter('daemons.tracer.kronos.missing_scope')
                    if report['eventType'] != 'touch':
                        continue
                else:
                    record_counter('daemons.tracer.kronos.with_scope')

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
                        replicas.append({'name': report['filename'], 'scope': report['scope'], 'rse': rse, 'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix']),
                                         'traceTimeentryUnix': report['traceTimeentryUnix'], 'eventVersion': report['eventVersion']})
                else:
                    # if touch event and if datasetScope is in the report then it means
                    # that there is no file scope/name and therefore only the dataset is
                    # put in the queue to be updated and the rest is skipped.
                    if 'datasetScope' in report:
                        rse = None
                        if 'remoteSite' in report:
                            rse = report['remoteSite']
                        self.__dataset_queue.put({'scope': report['datasetScope'], 'name': report['dataset'], 'rse': rse, 'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix'])})
                        continue
                    else:
                        if 'remoteSite' not in report:
                            continue
                        replicas.append({'name': report['filename'], 'scope': report['scope'], 'rse': report['remoteSite'], 'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix'])})

            except (KeyError, AttributeError):
                logging.error(format_exc())
                record_counter('daemons.tracer.kronos.report_error')
                continue

            for did in list_parent_dids(report['scope'], report['filename']):
                if did['type'] != DIDType.DATASET:
                    continue
                # do not update _dis datasets
                if did['scope'] == 'panda' and '_dis' in did['name']:
                    continue
                for rse in rses:
                    self.__dataset_queue.put({'scope': did['scope'], 'name': did['name'], 'did_type': did['type'], 'rse': rse, 'accessed_at': datetime.utcfromtimestamp(report['traceTimeentryUnix'])})

        logging.debug(replicas)

        try:
            start_time = time()
            for replica in replicas:
                # if touch replica hits a locked row put the trace back into queue for later retry
                if not touch_replica(replica):
                    resubmit = {'filename': replica['name'], 'scope': replica['scope'], 'remoteSite': replica['rse'], 'traceTimeentryUnix': replica['traceTimeentryUnix'],
                                'eventType': 'get', 'usrdn': 'someuser', 'clientState': 'DONE', 'eventVersion': replica['eventVersion']}
                    self.__conn.send(body=jdumps(resubmit), destination=self.__queue, headers={'appversion': 'rucio', 'resubmitted': '1'})
                    record_counter('daemons.tracer.kronos.sent_resubmitted')
                    logging.warning('(kronos_file) hit locked row, resubmitted to queue')
            record_timer('daemons.tracer.kronos.update_atime', (time() - start_time) * 1000)
        except Exception:
            logging.error(format_exc())
            record_counter('daemons.tracer.kronos.update_error')

        logging.info('(kronos_file) updated %d replicas' % len(replicas))


def kronos_file(once=False, thread=0, brokers_resolved=None, dataset_queue=None, sleep_time=60):
    """
    Main loop to consume tracer reports.
    """

    logging.info('tracer consumer starting')

    hostname = socket.gethostname()
    pid = getpid()
    thread = current_thread()

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
        logging.error('(kronos_file) Failed to get bad_file_patterns' + str(error))
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

    conns = []
    for broker in brokers_resolved:
        if not use_ssl:
            conns.append(Connection(host_and_ports=[(broker, config_get_int('tracer-kronos', 'port'))],
                                    use_ssl=False,
                                    vhost=vhost,
                                    reconnect_attempts_max=config_get_int('tracer-kronos', 'reconnect_attempts')))
        else:
            conns.append(Connection(host_and_ports=[(broker, config_get_int('tracer-kronos', 'port'))],
                                    use_ssl=True,
                                    ssl_key_file=config_get('tracer-kronos', 'ssl_key_file'),
                                    ssl_cert_file=config_get('tracer-kronos', 'ssl_cert_file'),
                                    vhost=vhost,
                                    reconnect_attempts_max=config_get_int('tracer-kronos', 'reconnect_attempts')))

    logging.info('(kronos_file) tracer consumer started')

    sanity_check(executable='kronos-file', hostname=hostname)
    while not graceful_stop.is_set():
        start_time = time()
        live(executable='kronos-file', hostname=hostname, pid=pid, thread=thread)
        for conn in conns:
            if not conn.is_connected():
                logging.info('(kronos_file) connecting to %s' % conn.transport._Transport__host_and_ports[0][0])
                record_counter('daemons.tracer.kronos.reconnect.%s' % conn.transport._Transport__host_and_ports[0][0].split('.')[0])
                conn.set_listener('rucio-tracer-kronos', AMQConsumer(broker=conn.transport._Transport__host_and_ports[0],
                                                                     conn=conn,
                                                                     queue=config_get('tracer-kronos', 'queue'),
                                                                     chunksize=chunksize,
                                                                     subscription_id=subscription_id,
                                                                     excluded_usrdns=excluded_usrdns,
                                                                     dataset_queue=dataset_queue,
                                                                     bad_files_patterns=bad_files_patterns))
                conn.start()
                if not use_ssl:
                    conn.connect(username, password)
                else:
                    conn.connect()
                conn.subscribe(destination=config_get('tracer-kronos', 'queue'), ack='client-individual', id=subscription_id, headers={'activemq.prefetchSize': prefetch_size})
        tottime = time() - start_time
        if tottime < sleep_time:
            logging.info('(kronos_file) Will sleep for %s seconds' % (sleep_time - tottime))
            sleep(sleep_time - tottime)

    logging.info('(kronos_file) graceful stop requested')

    for conn in conns:
        try:
            conn.disconnect()
        except Exception:
            pass

    die(executable='kronos-file', hostname=hostname, pid=pid, thread=thread)
    logging.info('(kronos_file) graceful stop done')


def kronos_dataset(once=False, thread=0, dataset_queue=None, sleep_time=60):
    logging.info('(kronos_dataset) starting')

    hostname = socket.gethostname()
    pid = getpid()
    thread = current_thread()

    dataset_wait = config_get_int('tracer-kronos', 'dataset_wait')
    start = datetime.now()
    sanity_check(executable='kronos-dataset', hostname=hostname)
    while not graceful_stop.is_set():
        start_time = time()
        live(executable='kronos-dataset', hostname=hostname, pid=pid, thread=thread)
        if (datetime.now() - start).seconds > dataset_wait:
            __update_datasets(dataset_queue)
            start = datetime.now()
        tottime = time() - start_time
        if tottime < sleep_time:
            logging.info('(kronos_dataset) Will sleep for %s seconds' % (sleep_time - tottime))
            sleep(sleep_time - tottime)
    # once again for the backlog
    die(executable='kronos-dataset', hostname=hostname, pid=pid, thread=thread)
    logging.info('(kronos_dataset) cleaning dataset backlog before shutdown...')
    __update_datasets(dataset_queue)


def __update_datasets(dataset_queue):
    len_ds = dataset_queue.qsize()
    datasets = {}
    dslocks = {}
    now = time()
    for _ in range(0, len_ds):
        dataset = dataset_queue.get()
        did = dataset['scope'] + ":" + dataset['name']
        rse = dataset['rse']
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
    logging.debug('(kronos_dataset) fetched %d datasets from queue (%ds)' % (len_ds, time() - now))

    total, failed, start = 0, 0, time()
    for did, accessed_at in datasets.items():
        scope, name = did.split(':')
        update_did = {'scope': scope, 'name': name, 'type': DIDType.DATASET, 'accessed_at': accessed_at}
        # if update fails, put back in queue and retry next time
        if not touch_dids((update_did,)):
            update_did['rse'] = None
            dataset_queue.put(update_did)
            failed += 1
        total += 1
    logging.debug('(kronos_dataset) did update for %d datasets, %d failed (%ds)' % (total, failed, time() - start))

    total, failed, start = 0, 0, time()
    for did, rses in dslocks.items():
        scope, name = did.split(':')
        for rse, accessed_at in rses.items():
            update_dslock = {'scope': scope, 'name': name, 'rse': rse, 'accessed_at': accessed_at}
            # if update fails, put back in queue and retry next time
            if not touch_dataset_locks((update_dslock,)):
                dataset_queue.put(update_dslock)
                failed += 1
            total += 1
    logging.debug('(kronos_dataset) did update for %d locks, %d failed (%ds)' % (total, failed, time() - start))

    total, failed, start = 0, 0, time()
    for did, rses in dslocks.items():
        scope, name = did.split(':')
        for rse, accessed_at in rses.items():
            update_dslock = {'scope': scope, 'name': name, 'rse': rse, 'accessed_at': accessed_at}
            # if update fails, put back in queue and retry next time
            if not touch_collection_replicas((update_dslock,)):
                dataset_queue.put(update_dslock)
                failed += 1
            total += 1
    logging.debug('(kronos_dataset) did update for %d collection replicas, %d failed (%ds)' % (total, failed, time() - start))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, threads=1, sleep_time_datasets=60, sleep_time_files=60):
    """
    Starts up the consumer threads
    """
    logging.info('resolving brokers')

    brokers_alias = []
    brokers_resolved = []
    try:
        brokers_alias = [b.strip() for b in config_get('tracer-kronos', 'brokers').split(',')]
    except Exception:
        raise Exception('Could not load brokers from configuration')

    logging.info('resolving broker dns alias: %s' % brokers_alias)

    brokers_resolved = []
    for broker in brokers_alias:
        addrinfos = socket.getaddrinfo(broker, 0, socket.AF_INET, 0, socket.IPPROTO_TCP)
        brokers_resolved.extend(ai[4][0] for ai in addrinfos)

    logging.debug('brokers resolved to %s', brokers_resolved)

    dataset_queue = Queue()
    logging.info('starting tracer consumer threads')

    thread_list = []
    for thread in range(0, threads):
        thread_list.append(Thread(target=kronos_file, kwargs={'thread': thread,
                                                              'sleep_time': sleep_time_files,
                                                              'brokers_resolved': brokers_resolved,
                                                              'dataset_queue': dataset_queue}))
        thread_list.append(Thread(target=kronos_dataset, kwargs={'thread': thread,
                                                                 'sleep_time': sleep_time_datasets,
                                                                 'dataset_queue': dataset_queue}))

    [thread.start() for thread in thread_list]

    logging.info('waiting for interrupts')

    while thread_list > 0:
        thread_list = [thread.join(timeout=3) for thread in thread_list if thread and thread.isAlive()]
