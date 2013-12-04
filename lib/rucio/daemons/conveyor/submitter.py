# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

"""
Conveyor is a daemon to manage file transfers.
"""

import logging
import sys
import threading
import time
import traceback

from rucio.common.config import config_get
from rucio.common.exception import DataIdentifierNotFound
from rucio.core import replica, request, rse
from rucio.core.monitor import record_counter, record_timer
from rucio.db.constants import RequestType, RequestState, ReplicaState
from rucio.db.session import get_session
from rucio.rse import rsemanager

logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


graceful_stop = threading.Event()


def submitter(once=False, process=0, total_processes=1, thread=0, total_threads=1, mock=False):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    logging.info('submitter starting')

    rsemgr = rsemanager.RSEMgr(server_mode=True)
    session = get_session()

    logging.info('submitter started')

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
                logging.info('nothing to do')
                continue

            logging.debug('working on %s requests' % len(reqs))

            for req in reqs:
                ts = time.time()
                tmpsrc = []
                filesize = 12345L
                checksum = 'adler32:123456'
                src_spacetoken = None

                try:
                    for source in replica.list_replicas([{'scope': req['scope'], 'name': req['name']}], session=session):
                        for endpoint in source['rses']:
                            for pfn in source['rses'][endpoint]:
                                tmpsrc.append(str(pfn))
                        filesize = long(source['bytes'])
                        checksum = 'adler32:%s' % (source['adler32'])
                        src_spacetoken = source['space_token'] if 'space_token' in source.keys() else None
                except DataIdentifierNotFound:
                    record_counter('daemons.conveyor.submitter.lost_did')
                    logging.warn('DID %s:%s does not exist anymore - marking request %s as LOST' % (req['scope'],
                                                                                                    req['name'],
                                                                                                    req['request_id']))
                    request.set_request_state(req['request_id'], RequestState.LOST, session=session)  # if the DID does not exist anymore
                    request.archive_request(req['request_id'], session=session)
                    session.commit()
                    continue
                except:
                    record_counter('daemons.conveyor.submitter.unexpected')
                    logging.critical('Something unexpected happened: %s' % traceback.format_exc())
                    continue
                finally:
                    session.commit()

                sources = []

                if tmpsrc == []:
                    if mock:
                        sources.append('mock://dummy/source')
                    else:
                        record_counter('daemons.conveyor.submitter.nosource')
                        logging.warn('No source replicas found for DID %s:%s - deep check for unavailable replicas' % (req['scope'], req['name']))

                        i = 0
                        for tmp in replica.list_replicas([{'scope': req['scope'], 'name': req['name']}], unavailable=True, session=session):
                            i += 1  # sadly, we have to iterate over results

                        if not i:
                            logging.warn('DID %s:%s lost' % (req['scope'], req['name']))
                            # TODO: wipe DID

                        session.commit()
                        continue
                else:
                    for tmp in tmpsrc:
                        sources.append(tmp)

                record_timer('daemons.conveyor.submitter.001-list_replicas', (time.time()-ts)*1000)

                ts = time.time()
                rse_name = rse.get_rse_by_id(req['dest_rse_id'], session=session)['rse']
                record_timer('daemons.conveyor.submitter.002-get_rse', (time.time()-ts)*1000)

                ts = time.time()
                pfn = rsemgr.lfn2pfn(rse_id=rse_name, lfns=[{'scope': req['scope'], 'name': req['name']}], session=session)
                record_timer('daemons.conveyor.submitter.003-lfn2pfn', (time.time()-ts)*1000)

                if isinstance(pfn, list):
                    destinations = [str(d) for d in pfn]
                else:
                    destinations = [str(pfn)]

                protocols = rsemgr.list_protocols(rse_id=rse_name, session=session)
                dest_spacetoken = None
                try:
                    dest_spacetoken = protocols[0]['extended_attributes']['space_token']
                except:
                    logging.warn('No spacetoken defined for %s' % rse_name)

                ts = time.time()
                request.submit_transfers(transfers=[{'request_id': req['request_id'],
                                                     'src_urls': sources,
                                                     'dest_urls': destinations,
                                                     'filesize': filesize,
                                                     'checksum': checksum,
                                                     'src_spacetoken': src_spacetoken,
                                                     'dest_spacetoken': dest_spacetoken}],
                                         transfertool='fts3',
                                         job_metadata={'issuer': 'rucio-conveyor',
                                                       'scope': req['scope'],
                                                       'name': req['name'],
                                                       'sources': sources,
                                                       'destinations': destinations},
                                         session=session)
                record_timer('daemons.conveyor.submitter.004-submit_transfer', (time.time()-ts)*1000)

                ts = time.time()
                replica.update_replicas_states([{'rse': rse_name,
                                               'scope': req['scope'],
                                               'name': req['name'],
                                               'state': ReplicaState.COPYING}],
                                               session=session)
                record_timer('daemons.conveyor.submitter.005-replica-set_copying', (time.time()-ts)*1000)

                logging.info('COPYING %s:%s from %s to %s' % (req['scope'], req['name'], sources, destinations))
                record_counter('daemons.conveyor.submitter.submit_request')

                session.commit()

        except:
            session.rollback()
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.info('graceful stop requested')

    logging.info('graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1, mock=False):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one submitter iteration only')
        submitter(once)

    else:

        logging.info('starting submitter threads')
        threads = [threading.Thread(target=submitter, kwargs={'process': process, 'total_processes': total_processes, 'thread': i, 'total_threads': total_threads, 'mock': mock}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t is not None and t.isAlive()]
