# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2015

import logging
from datetime import datetime
from json import dumps
from requests import post
from sys import stdout
from time import sleep
from Queue import Queue

from threading import Event, Thread

from rucio.common.config import config_get
from rucio.daemons.c3po.collectors.mock_did import MockDIDCollector
from rucio.daemons.c3po.collectors.workload import WorkloadCollector

logging.basicConfig(stream=stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = Event()


def read_workload(once=False, thread=0, waiting_time=1800):
    workload_collector = WorkloadCollector()
    w = waiting_time
    while not graceful_stop.is_set():
        if w >= waiting_time:
            logging.info('collecting workload')
            workload_collector.collect_workload()
            w = 0
        else:
            w += 10
            sleep(10)


def print_workload(once=False, thread=0, waiting_time=600):
    workload_collector = WorkloadCollector()
    w = waiting_time
    while not graceful_stop.is_set():
        if w >= waiting_time:
            logging.info("Number of sites cached %d" % len(workload_collector.get_sites()))
            for site in workload_collector.get_sites():
                logging.info("%s: %d / %d / %d" % (site, workload_collector.get_cur_jobs(site), workload_collector.get_avg_jobs(site), workload_collector.get_max_jobs(site)))
            w = 0
        else:
            w += 10
            sleep(10)


def read_dids(once=False, thread=0, did_collector=None):
    while not graceful_stop.is_set():
        did_collector.get_dids()
        sleep(10)


def place_replica(once=False, thread=0, did_queue=None):
    algorithm = config_get('c3po', 'placement_algorithm')
    module_path = 'rucio.daemons.c3po.algorithms.' + algorithm
    module = __import__(module_path, globals(), locals(), ['PlacementAlgorithm'])
    instance = module.PlacementAlgorithm()

    while not graceful_stop.is_set():
        len_dids = did_queue.qsize()
        if len_dids > 0:
            logging.debug("%d did(s) in queue" % len_dids)
        else:
            logging.debug("no dids in queue")

        for i in xrange(0, len_dids):
            did = did_queue.get()
            logging.info("Retrieved %s:%s from queue. Run placement algorithm" % (did[0], did[1]))
            decision = instance.place(did)
            decision['@timestamp'] = datetime.utcnow().isoformat()
            r = post('http://aianalytics01.cern.ch:9200/rucio-c3po-decisions/record/', data=dumps(decision))
            logging.info(decision)

        sleep(100)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the main thread
    """
    logging.info('activating C-3PO')

    did_queue = Queue()
    dc = MockDIDCollector(did_queue)

    thread_list = []
    thread_list.append(Thread(target=read_workload, kwargs={'thread': 0, 'waiting_time': 1800}))
    thread_list.append(Thread(target=print_workload, kwargs={'thread': 0, 'waiting_time': 600}))
    thread_list.append(Thread(target=read_dids, kwargs={'thread': 0, 'did_collector': dc}))
    thread_list.append(Thread(target=place_replica, kwargs={'thread': 0, 'did_queue': did_queue}))

    [t.start() for t in thread_list]

    logging.info('waiting for interrupts')

    while len(thread_list) > 0:
        [t.join(timeout=3) for t in thread_list if t and t.isAlive()]
