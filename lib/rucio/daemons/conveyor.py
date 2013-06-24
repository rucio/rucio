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
from rucio.core.monitor import record_counter, record_timer
from rucio.db.constants import RequestType, RequestState
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

        try:

            ts = time.time()
            req = request.get_next(req_type=RequestType.TRANSFER, state=RequestState.QUEUED)
            record_timer('daemons.conveyor.submitter.000-get_next', time.time()-ts)

            if req is None:
                if once:
                    break
                print 'submitter: idling'
                time.sleep(1)  # Only sleep if there is nothing to do
                continue

            ts = time.time()
            sources = sum([[str(pfn) for pfn in source['pfns']] for source in did.list_replicas(scope=req['scope'], name=req['name'])], [])
            record_timer('daemons.conveyor.submitter.001-list_replicas', time.time()-ts)

            ts = time.time()
            rse_name = rse.get_rse_by_id(req['dest_rse_id'])['rse']
            record_timer('daemons.conveyor.submitter.002-get_rse', time.time()-ts)

            ts = time.time()
            pfn = rsemgr.lfn2pfn(rse_id=rse_name, lfns=[{'scope': req['scope'], 'filename': req['name']}])
            record_timer('daemons.conveyor.submitter.003-lfn2pfn', time.time()-ts)

            if isinstance(pfn, list):
                destinations = [str(d) for d in pfn]
            else:
                destinations = [str(pfn)]

            ts = time.time()
            request.submit_transfer(req['request_id'], sources, destinations, 'fts3-mock', {'issuer': 'rucio-conveyor'})
            record_timer('daemons.conveyor.submitter.004-submit_transfer', time.time()-ts)

            record_counter('daemons.conveyor.submitter.submit_request')

        except:
            print traceback.format_exc()

        if once:
            return

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
            ts = time.time()
            req = request.get_next(req_type=RequestType.TRANSFER, state=RequestState.SUBMITTED)
            record_timer('daemons.conveyor.poller.000-get_next', time.time()-ts)

            if req is [] or req is None:
                print 'poller: idling'
                time.sleep(1)  # Only sleep if there is nothing to do
                continue

            ts = time.time()
            request.query_request(req['request_id'])
            record_timer('daemons.conveyor.poller.001-query_request', time.time()-ts)

            record_counter('daemons.conveyor.poller.query_request')

        except:
            print traceback.format_exc()

        if once:
            return

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
