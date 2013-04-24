# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

"""
Conveyor is a daemon to manage file transfers.
"""

import threading
import time
import traceback

from rucio.core import did, request, rse
from rucio.rse import rsemanager

graceful_stop = threading.Event()


def submitter(once=False):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    print 'submitter: starting'

    rsemgr = rsemanager.RSEMgr(server_mode=True)

    print 'submitter: started'

    while not graceful_stop.is_set():

        print 'submitter: submitting transfer request'

        try:

            req = request.get_next(req_type='TRANSFER', state='QUEUED')
            if req is None:
                continue

            sources = sum([[str(pfn) for pfn in source['pfns']] for source in did.list_replicas(scope=req['scope'], name=req['name'])], [])
            rse_name = rse.get_rse_by_id(req['dest_rse_id'])['rse']
            destinations = [str(d) for d in rsemgr.lfn2pfn(rse_id=rse_name, lfns=[{'scope': req['scope'], 'filename': req['name']}])]
            request.submit_transfer(req['request_id'], sources, destinations, 'fts3-mock', {'issuer': 'rucio-conveyor'})

        except:
            print traceback.format_exc()

        if once:
            return

        time.sleep(1)

    print 'submitter: graceful stop requested'

    print 'submitter: graceful stop done'


def poller(once=False):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    print 'poller: starting'

    print 'poller: started'

    while not graceful_stop.is_set():

        try:
            print 'poller: retrieving external state of request'

            req_id = request.get_next(req_type='TRANSFER', state='SUBMITTED')['request_id']
            if req_id is None:
                continue

            request.query_request(req_id)

        except:
            print traceback.format_exc()

        if once:
            return

        time.sleep(1)

    print 'poller: graceful stop requested'

    print 'poller: graceful stop done'


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False):
    """
    Starts up the conveyer threads.
    """

    if once:
        print 'main: executing one iteration only'
        submitter(once)
        poller(once)

    else:

        print 'main: starting threads'

        threads = [threading.Thread(target=submitter),
                   threading.Thread(target=poller)]

        [t.start() for t in threads]

        print 'main: waiting for interrupts'

        # Interruptible joins require a timeout.
        while threads[0].is_alive() and threads[1].is_alive():
            [t.join(timeout=3.14) for t in threads]
