# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2017
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

"""
OS injector is a daemon to inject OS files for deletion
"""

from __future__ import division

import datetime
import dateutil.parser
import hashlib
import logging
import os
import pytz
import random
import socket
import sys
import threading
import time
import traceback

from rucio.common.config import config_get
from rucio.core import rse as rse_core
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.temporary_did import (add_temporary_dids, get_count_of_expired_temporary_dids)
from rucio.rse import rsemanager as rsemgr
from rucio.daemons.reaper.reaper import __check_rse_usage


logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()


def inject(rse, older_than):
    logging.info('Starting to inject objects for RSE: %s' % rse)
    num_of_queued_dids = get_count_of_expired_temporary_dids(rse)
    rse_id = rse_core.get_rse_id(rse)
    if num_of_queued_dids < 1000:
        max_being_deleted_files, needed_free_space, used, free = __check_rse_usage(rse=rse, rse_id=rse_id)
        logging.info("needed_free_space: %s" % needed_free_space)
        if needed_free_space is None or needed_free_space > 0:
            rse_info = rsemgr.get_rse_info(rse)
            for protocol in rse_info['protocols']:
                protocol['impl'] = 'rucio.rse.protocols.s3boto.Default'

            prot = rsemgr.create_protocol(rse_info, 'delete')
            try:
                prot.connect()
                dids = []
                older_than_time = datetime.datetime.utcnow() - datetime.timedelta(days=older_than)
                older_than_time = older_than_time.replace(tzinfo=pytz.utc)
                for key in prot.list():
                    d = dateutil.parser.parse(key.last_modified)
                    if d < older_than_time:
                        did = {'scope': 'transient',
                               'name': key.name.encode('utf-8'),
                               'rse': rse,
                               'rse_id': rse_id,
                               'bytes': key.size,
                               'created_at': d}
                        dids.append(did)
                        if len(dids) == 1000:
                            add_temporary_dids(dids=dids, account='root')
                            logging.info('Adding 1000 dids to temp dids.')
                            dids = []
                    else:
                        pass
                        logging.info('Found objects newer than %s days, quit to list(normally objects in os are returned with order by time)' % older_than)
                        break
                    if GRACEFUL_STOP.is_set():
                        logging.info('GRACEFUL_STOP is set. quit')
                        break
            except:
                logging.critical(traceback.format_exc())
    else:
        logging.info("Number of queued deletion for %s is %s, which is bigger than 1000. quit." % (rse, num_of_queued_dids))


def injector(rses=[], once=False, scheme=None, worker_number=0, total_workers=1, older_than=30, sleep_time=1):
    """
    Main loop to select and delete files.

    :param rses: List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param once: If True, only runs one iteration of the main loop.
    :param scheme: Force the reaper to use a particular protocol, e.g., mock.
    :param older_than: List control: older objects more than this value of days to list.
    :param sleep_time: Days to sleep.
    """
    logging.info('Starting Light Injector %s-%s: Will work on RSEs: %s', worker_number, total_workers, str(rses))

    pid = os.getpid()
    thread = threading.current_thread()
    hostname = socket.gethostname()
    executable = ' '.join(sys.argv)
    hash_executable = hashlib.sha256(sys.argv[0] + ''.join(rses)).hexdigest()
    sanity_check(executable=None, hostname=hostname)

    injecting_time = time.time()
    while not GRACEFUL_STOP.is_set():
        try:
            # heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=thread, hash_executable=hash_executable)
            logging.info('Light Injector({0[worker_number]}/{0[total_workers]}): Live gives {0[heartbeat]}'.format(locals()))
            nothing_to_do = True

            random.shuffle(rses)
            for rse in rses:
                inject(rse, older_than)

            if once:
                break

            next_inject_time = injecting_time + 3600 * 24 * sleep_time
            logging.info('Will sleep %s seconds(about %s days)' % (next_inject_time - time.time(), (next_inject_time - time.time()) * 1.0 / 86400))
            while not GRACEFUL_STOP.is_set() and time.time() < next_inject_time:
                time.sleep(1)
        except:
            logging.critical(traceback.format_exc())

    die(executable=executable, hostname=hostname, pid=pid, thread=thread, hash_executable=hash_executable)
    logging.info('Graceful stop requested')
    logging.info('Graceful stop done')
    return


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def run(one_worker_per_rse=False, once=False, rses=[], scheme=None, all_os_rses=False, older_than=30, sleep_time=1):
    """
    Starts up the injector threads.

    :param one_worker_per_rse: If True, one worker per RSE; Otherwise, one worker for all RSEs.
    :param once: If True, only runs one iteration of the main loop.
    :param rses: List of RSEs the reaper should work against. If empty, it considers all RSEs.
    :param scheme: Force the reaper to use a particular protocol/scheme, e.g., mock.
    :param all_os_rses: All Objectstore RSEs.
    :param older_than: List control: older objects more than this value of days to list.
    :param sleep_time: Days to sleep.
    """

    logging.info('main: starting processes')

    if all_os_rses:
        rses = []
        for rse in rse_core.list_rses():
            if rse['rse'].endswith('_ES'):
                rses.append(rse['rse'])

    threads = []
    if one_worker_per_rse:
        worker = 0
        for rse in rses:
            kwargs = {'once': once, 'rses': [rse], 'scheme': scheme, 'worker_number': worker, 'total_workers': len(rses),
                      'older_than': older_than, 'sleep_time': sleep_time}
            threads.append(threading.Thread(target=injector, kwargs=kwargs, name='Worker: %s, Total_Workers: %s' % (worker, len(rses))))
            worker += 1
    else:
        kwargs = {'once': once, 'rses': rses, 'scheme': scheme, 'older_than': older_than, 'sleep_time': sleep_time}
        threads.append(threading.Thread(target=injector, kwargs=kwargs, name='Worker: %s, Total_Workers: %s' % (0, 1)))

    [t.start() for t in threads]
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
