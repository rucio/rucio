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
from rucio.core import did, request, rse
from rucio.core.monitor import record_counter, record_timer
from rucio.db.constants import RequestType, RequestState, ReplicaState
from rucio.db.session import get_session
from rucio.rse import rsemanager

graceful_stop = threading.Event()


def submitter(once=False, process=0, total_processes=1, thread=0, total_threads=1):
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


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1):
    """
    Starts up the conveyer threads.
    """

    if once:
        print 'main: executing one iteration only'
        submitter(once)

    else:

        print 'main: starting threads'
        threads = [threading.Thread(target=submitter, kwargs={'process': process, 'total_processes': total_processes, 'thread': i, 'total_threads': total_threads}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        print 'main: waiting for interrupts'

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t is not None and t.isAlive()]
