# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2015-2016

"""
Dynamic data placement daemon.
"""

import logging
from datetime import datetime
from json import dumps
from Queue import Queue
from requests import post
from sys import stdout
from time import sleep

from threading import Event, Thread

from rucio.client import Client
from rucio.common.config import config_get
from rucio.daemons.c3po.collectors.free_space import FreeSpaceCollector
from rucio.daemons.c3po.collectors.jedi_did import JediDIDCollector
from rucio.daemons.c3po.collectors.workload import WorkloadCollector

logging.basicConfig(stream=stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(filename)s\t%(levelname)s\t%(message)s')

graceful_stop = Event()


def read_free_space(once=False, thread=0, waiting_time=1800):
    """
    Thread to collect the space usage information for RSEs.
    """

    free_space_collector = FreeSpaceCollector()
    w = waiting_time
    while not graceful_stop.is_set():
        if w < waiting_time:
            w += 10
            sleep(10)
            continue

        logging.info('collecting free space')
        free_space_collector.collect_free_space()
        w = 0


def read_workload(once=False, thread=0, waiting_time=1800):
    """
    Thread to collect the workload information from PanDA.
    """

    workload_collector = WorkloadCollector()
    w = waiting_time
    while not graceful_stop.is_set():
        if w < waiting_time:
            w += 10
            sleep(10)
            continue

        logging.info('collecting workload')
        workload_collector.collect_workload()
        w = 0


def print_workload(once=False, thread=0, waiting_time=600):
    """
    Thread to regularly output the workload to logs for debugging.
    """

    workload_collector = WorkloadCollector()
    w = waiting_time
    while not graceful_stop.is_set():
        if w < waiting_time:
            w += 10
            sleep(10)
            continue

        logging.info('Number of sites cached %d' % len(workload_collector.get_sites()))
        for site in workload_collector.get_sites():
            logging.info('%s: %d / %d / %d' % (site, workload_collector.get_cur_jobs(site), workload_collector.get_avg_jobs(site), workload_collector.get_max_jobs(site)))
        w = 0


def read_dids(once=False, thread=0, did_collector=None, waiting_time=60):
    """
    Thread to collect DIDs for the placement algorithm.
    """

    w = waiting_time
    while not graceful_stop.is_set():
        if w < waiting_time:
            w += 10
            sleep(10)
            continue

        did_collector.get_dids()
        w = 0


def create_rule(client, did, src_rse, dst_rse):
    logging.debug('create rule for %s from %s to %s' % (did, src_rse, dst_rse))

    r = client.add_replication_rule([did, ], 1, dst_rse, lifetime=604800, account='c3po', source_replica_expression=src_rse, activity='Data Brokering', asynchronous=True)

    logging.debug(r)


def place_replica(once=False, thread=0, did_queue=None, waiting_time=100, dry_run=False):
    """
    Thread to run the placement algorithm to decide if and where to put new replicas.
    """
    client = None

    if not dry_run:
        client = Client(auth_type='x509_proxy', account='c3po', creds={'client_proxy': '/opt/rucio/etc/ddmadmin.long.proxy'})

    algorithms = config_get('c3po', 'algorithms').strip().split(',')

    instances = {}
    for algorithm in algorithms:
        module_path = 'rucio.daemons.c3po.algorithms.' + algorithm
        module = __import__(module_path, globals(), locals(), ['PlacementAlgorithm'])
        instance = module.PlacementAlgorithm()
        instances[algorithm] = instance

    elastic_url = config_get('c3po', 'elastic_url')
    w = waiting_time
    while not graceful_stop.is_set():
        if w < waiting_time:
            w += 10
            sleep(10)
            continue
        len_dids = did_queue.qsize()

        if len_dids > 0:
            logging.debug('%d did(s) in queue' % len_dids)
        else:
            logging.debug('no dids in queue')

        for i in xrange(0, len_dids):
            did = did_queue.get()
            for algorithm, instance in instances.items():
                logging.info('(%s) Retrieved %s:%s from queue. Run placement algorithm' % (algorithm, did[0], did[1]))
                decision = instance.place(did)
                decision['@timestamp'] = datetime.utcnow().isoformat()
                decision['algorithm'] = algorithm

                # write the output to ES for further analysis
                index_url = elastic_url + '/rucio-c3po-decisions-' + datetime.utcnow().strftime('%Y-%m-%d') + '/record/'
                r = post(index_url, data=dumps(decision))
                if r.status_code != 201:
                    logging.error(r)
                    logging.error('(%s) could not write to ElasticSearch' % (algorithm))

                logging.debug(decision)
                if 'error_reason' in decision:
                    logging.error('(%s) The placement algorithm ran into an error: %s' % (algorithm, decision['error_reason']))
                    continue

                logging.info('(%s) Decided to place a new replica for %s on %s' % (algorithm, decision['did'], decision['destination_rse']))

                if not dry_run:
                    # DO IT!
                    create_rule(client, {'scope': did[0], 'name': did[1]}, decision.get('source_rse'), decision.get('destination_rse'))

        w = 0


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, threads=1, only_workload=False, dry_run=False):
    """
    Starts up the main thread
    """
    logging.info('activating C-3PO')

    thread_list = []

    if only_workload:
        logging.info('running in workload-collector-only mode')
        thread_list.append(Thread(target=read_workload, name='read_workload', kwargs={'thread': 0, 'waiting_time': 1800}))
        thread_list.append(Thread(target=print_workload, name='print_workload', kwargs={'thread': 0, 'waiting_time': 600}))
    else:
        logging.info('running in placement mode')
        did_queue = Queue()
        dc = JediDIDCollector(did_queue)

        thread_list.append(Thread(target=read_free_space, name='read_free_space', kwargs={'thread': 0, 'waiting_time': 1800}))
        thread_list.append(Thread(target=read_dids, name='read_dids', kwargs={'thread': 0, 'did_collector': dc}))
        thread_list.append(Thread(target=place_replica, name='place_replica', kwargs={'thread': 0, 'did_queue': did_queue, 'waiting_time': 10, 'dry_run': dry_run}))

    [t.start() for t in thread_list]

    logging.info('waiting for interrupts')

    while len(thread_list) > 0:
        [t.join(timeout=3) for t in thread_list if t and t.isAlive()]
