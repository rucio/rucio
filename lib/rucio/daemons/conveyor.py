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

from rucio.common.exception import DataIdentifierNotFound
from rucio.core import did, request, rse, lock
from rucio.core.monitor import record_counter, record_timer
from rucio.db.constants import RequestType, RequestState, ReplicaState
from rucio.db.session import get_session
from rucio.rse import rsemanager

graceful_stop = threading.Event()


def submitter(once=False, process=1, total_processes=1, thread=1, total_threads=1):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    print 'submitter: starting'

    rsemgr = rsemanager.RSEMgr(server_mode=True)
    session = get_session()

    print 'submitter: started'

    while not graceful_stop.is_set():

        try:

            ts = time.time()
            reqs = request.get_next(req_type=RequestType.TRANSFER, state=RequestState.QUEUED, limit=100, process=process, total_processes=total_processes, thread=thread, total_threads=total_threads, session=session)

            record_timer('daemons.conveyor.submitter.000-get_next', (time.time()-ts)*1000)

            if reqs is None or reqs == []:
                if once:
                    break
                session.commit()
                time.sleep(1)  # Only sleep if there is nothing to do
                continue

            for req in reqs:
                ts = time.time()
                tmpsrc = []
                try:
                    for source in did.list_replicas([{'scope': req['scope'], 'name': req['name']}], session=session):
                        for pfn in source['rses'].keys():
                            tmpsrc.append(str(source['rses'][pfn]))
                except DataIdentifierNotFound:
                    print 'lost did'
                    request.set_request_state(req['request_id'], RequestState.LOST, session=session)  # if the DID does not exist anymore
                    request.archive_request(req['request_id'], session=session)
                    session.commit()
                    continue

                #  dummy replacement: list_replicas does not yet set the PFN
                sources = []
                for tmp in tmpsrc:
                    if tmp == '[]':
                        sources.append('mock://dummyhost/dummyfile.root')
                    else:
                        sources.append(tmp)

                record_timer('daemons.conveyor.submitter.001-list_replicas', (time.time()-ts)*1000)

                ts = time.time()
                rse_name = rse.get_rse_by_id(req['dest_rse_id'], session=session)['rse']
                record_timer('daemons.conveyor.submitter.002-get_rse', (time.time()-ts)*1000)

                ts = time.time()
                pfn = rsemgr.lfn2pfn(rse_id=rse_name, lfns=[{'scope': req['scope'], 'filename': req['name']}], session=session)
                record_timer('daemons.conveyor.submitter.003-lfn2pfn', (time.time()-ts)*1000)

                if isinstance(pfn, list):
                    destinations = [str(d) for d in pfn]
                else:
                    destinations = [str(pfn)]

                ts = time.time()

                request.submit_transfers(transfers=[{'request_id': req['request_id'],
                                                     'src_urls': sources,
                                                     'dest_urls': destinations,
                                                     'filesize': 12345L,
                                                     'checksum': 'ad:123456',
                                                     'src_spacetoken': None,
                                                     'dest_spacetoken': None}],
                                         transfertool='fts3',
                                         job_metadata={'issuer': 'rucio-conveyor'},
                                         session=session)
                record_timer('daemons.conveyor.submitter.004-submit_transfer', (time.time()-ts)*1000)

                ts = time.time()
                rse.update_replicas_states([{'rse': rse_name,
                                             'scope': req['scope'],
                                             'name': req['name'],
                                             'state': ReplicaState.COPYING}],
                                           session=session)
                record_timer('daemons.conveyor.submitter.005-replica-set_copying', (time.time()-ts)*1000)

                record_counter('daemons.conveyor.submitter.submit_request')

                session.commit()

        except:
            session.rollback()
            print traceback.format_exc()

        if once:
            return

    print 'submitter: graceful stop requested'

    print 'submitter: graceful stop done'


def poller(once=False, process=1, total_processes=1, thread=1, total_threads=1):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    print 'poller: starting'

    session = get_session()

    print 'poller: started'

    while not graceful_stop.is_set():

        try:
            ts = time.time()
            reqs = request.get_next(req_type=RequestType.TRANSFER, state=RequestState.SUBMITTED, limit=100, process=process, total_processes=total_processes, thread=thread, total_threads=total_threads, session=session)
            record_timer('daemons.conveyor.poller.000-get_next', (time.time()-ts)*1000)

            if reqs is None or reqs == []:
                if once:
                    break
                session.commit()
                time.sleep(1)  # Only sleep if there is nothing to do
                continue

            for req in reqs:
                ts = time.time()

                response = request.query_request(req['request_id'], 'fts3', session=session)

                if response['new_state'] is not None:
                    request.set_request_state(req['request_id'], response['new_state'], session=session)
                    if response['new_state'] == RequestState.DONE:
                        tss = time.time()
                        lock.successful_transfer(req['scope'], req['name'], req['dest_rse_id'], session=session)
                        record_timer('daemons.conveyor.poller.002-lock-successful_transfer', (time.time()-tss)*1000)

                        tss = time.time()
                        rse_name = rse.get_rse_by_id(req['dest_rse_id'], session=session)['rse']
                        record_timer('daemons.conveyor.poller.003-replica-get_rse', (time.time()-ts)*1000)

                        tss = time.time()
                        rse.update_replicas_states([{'rse': rse_name,
                                                     'scope': req['scope'],
                                                     'name': req['name'],
                                                     'state': ReplicaState.AVAILABLE}],
                                                   session=session)
                        record_timer('daemons.conveyor.poller.004-replica-set_available', (time.time()-tss)*1000)

                        tss = time.time()
                        request.archive_request(req['request_id'], session=session)
                        record_timer('daemons.conveyor.poller.005-request-archive_successful', (time.time()-tss)*1000)

                    elif response['new_state'] == RequestState.FAILED or response['new_state'] == RequestState.LOST:  # TODO: resubmit does not set failed_transfer
                        tss = time.time()
                        lock.failed_transfer(req['scope'], req['name'], req['dest_rse_id'], session=session)
                        record_timer('daemons.conveyor.poller.002-lock-failed_transfer', (time.time()-tss)*1000)

                        tss = time.time()
                        request.archive_request(req['request_id'], session=session)
                        record_timer('daemons.conveyor.poller.003-request-archive_failed', (time.time()-tss)*1000)

                record_timer('daemons.conveyor.poller.001-query_request', (time.time()-ts)*1000)

                record_counter('daemons.conveyor.poller.query_request')

                session.commit()

        except:
            session.rollback()
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


def run(once=False, process=1, total_processes=1, total_threads=1):
    """
    Starts up the conveyer threads.
    """

    if once:
        print 'main: executing one iteration only'
        submitter(once)
        poller(once)

    else:

        print 'main: starting threads'
        threads = [[threading.Thread(target=submitter, kwargs={'process': process, 'total_processes': total_processes, 'thread': i, 'total_threads': total_threads}) for i in xrange(1, total_threads+1)],
                   [threading.Thread(target=poller, kwargs={'process': process, 'total_processes': total_processes, 'thread': j, 'total_threads': total_threads}) for j in xrange(1, total_threads+1)]]

        threads = [tsub for lsub in threads for tsub in lsub]

        [t.start() for t in threads]

        print 'main: waiting for interrupts'

        # Interruptible joins require a timeout.
        while threads[0].is_alive() and threads[1].is_alive():
            [t.join(timeout=3.14) for t in threads]
