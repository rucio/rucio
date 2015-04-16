# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 20125

"""
Conveyor is a daemon to manage file transfers.
"""

import logging
import sys
import threading
import time

from rucio.common.config import config_get
from rucio.daemons.conveyor.submitter_utils import get_transfer_requests_and_source_replicas, get_stagein_requests_and_source_replicas


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def submitter(once=False, process=0, total_processes=1, thread=0, total_threads=1):
    # print '%(thread)s/%(total_threads)s: Submitter ' % locals()
    s = time.time()
    requests, reqs_no_source, reqs_scheme_mismatch = get_transfer_requests_and_source_replicas(process=process, total_processes=total_processes, thread=thread, total_threads=total_threads)
    duration = time.time() - s
    nb_requests = len(requests)
    print '%(thread)s/%(total_threads)s: %(nb_requests)s xfers in %(duration)s seconds' % locals()
    for id in requests:
        print requests[id]
        break
    print reqs_no_source
    print reqs_scheme_mismatch

    s = time.time()
    requests, reqs_no_source = get_stagein_requests_and_source_replicas(process=process, total_processes=total_processes, thread=thread, total_threads=total_threads)
    duration = time.time() - s
    nb_requests = len(requests)
    print '%(thread)s/%(total_threads)s: %(nb_requests)s xfers in %(duration)s seconds' % locals()
    # Grouping per rule_id, dest_rse_id
    # Order by activity
    # jobs = requests_to_jobs(requests)
    jobs = requests

    # Then submit to FTS
    # for job in jobs:
    #   print jobs[job]
    #   fts_submit(job)
    #   update_request(job)

    # print '%(thread)s/%(total_threads)s: Stop ' % locals()
    return


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, total_threads=1):
    """
    Starts up the conveyer submitter threads.
    """
    print 'Starts up the conveyer submitter threads.'

    threads = []
    for i in xrange(total_threads):
        threads.append(threading.Thread(target=submitter, kwargs={'thread': i,
                                                                  'total_threads': total_threads,
                                                                  'once': once}))

    [t.start() for t in threads]

    logging.info('waiting for interrupts')
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
