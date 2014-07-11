# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014

"""
Conveyor is a daemon to manage file transfers.
"""

import logging
import sys
import threading
import time
import traceback

from ConfigParser import NoOptionError

from rucio.common.config import config_get
from rucio.common.exception import DataIdentifierNotFound, RSEProtocolNotSupported, UnsupportedOperation
from rucio.common.utils import construct_surl_DQ2
from rucio.core import did, replica, request, rse
from rucio.core.monitor import record_counter, record_timer
from rucio.db.constants import DIDType, RequestType, RequestState, ReplicaState
from rucio.rse import rsemanager as rsemgr

logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("dogpile").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def submitter(once=False, process=0, total_processes=1, thread=0, total_threads=1, mock=False):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    logging.info('submitter starting')

    try:
        scheme = config_get('conveyor', 'scheme')
    except NoOptionError:
        scheme = 'srm'

    logging.info('submitter started')

    while not graceful_stop.is_set():

        try:

            ts = time.time()

            reqs = request.get_next(request_type=[RequestType.TRANSFER,
                                                  RequestType.STAGEIN,
                                                  RequestType.STAGEOUT],
                                    state=RequestState.QUEUED,
                                    limit=100,
                                    process=process,
                                    total_processes=total_processes,
                                    thread=thread,
                                    total_threads=total_threads)

            if reqs:
                logging.debug('getting %s requests to submit' % (str(len(reqs))))
            record_timer('daemons.conveyor.submitter.get_next', (time.time() - ts) * 1000)

            if not reqs:
                if once:
                    break
                time.sleep(1)  # Only sleep if there is nothing to do
                continue

            for req in reqs:
                ts = time.time()
                tmpsrc = []
                filesize = None
                md5 = None
                adler32 = None
                src_spacetoken = None
                logging.debug(req)
                dest_rse = rse.get_rse_by_id(req['dest_rse_id'])
                allowed_rses = []
                if req['request_type'] == RequestType.STAGEIN:
                    rses = rse.list_rses(filters={'staging_buffer': dest_rse['rse']})
                    allowed_rses = [x['rse'] for x in rses]

                try:
                    for source in replica.list_replicas(dids=[{'scope': req['scope'],
                                                               'name': req['name'],
                                                               'type': DIDType.FILE}],
                                                        schemes=[scheme, 'gsiftp']):

                        filesize = long(source['bytes'])
                        md5 = source['md5']
                        adler32 = source['adler32']
                        # TODO: Source protection

                        for source_rse in source['rses']:
                            if req['request_type'] == RequestType.STAGEIN:
                                if source_rse in allowed_rses:
                                    for pfn in source['rses'][source_rse]:
                                        # In case of staging request, we only use one source
                                        tmpsrc = [(str(source_rse), str(pfn)), ]
                            else:
                                filtered_sources = [x for x in source['rses'][source_rse] if x.startswith('gsiftp')]
                                if not filtered_sources:
                                    filtered_sources = source['rses'][source_rse]
                                for pfn in filtered_sources:
                                    tmpsrc.append((str(source_rse), str(pfn)))

                except DataIdentifierNotFound:
                    record_counter('daemons.conveyor.submitter.lost_did')
                    logging.warn('DID %s:%s does not exist anymore - marking request %s as LOST' % (req['scope'],
                                                                                                    req['name'],
                                                                                                    req['request_id']))
                    # TODO: Merge these two calls
                    request.set_request_state(req['request_id'],
                                              RequestState.LOST)  # if the DID does not exist anymore
                    request.archive_request(req['request_id'])
                    continue
                except:
                    record_counter('daemons.conveyor.submitter.unexpected')
                    logging.critical('Something unexpected happened: %s' % traceback.format_exc())
                    continue

                sources = []

                if tmpsrc == []:
                    record_counter('daemons.conveyor.submitter.nosource')
                    logging.warn('No source replicas found for DID %s:%s - deep check for unavailable replicas' % (req['scope'],
                                                                                                                   req['name']))

                    if sum(1 for tmp in replica.list_replicas([{'scope': req['scope'],
                                                                'name': req['name'],
                                                                'type': DIDType.FILE}],
                                                              schemes=[scheme],
                                                              unavailable=True)):
                        logging.critical('DID %s:%s lost! This should not happen!' % (req['scope'], req['name']))

                    continue
                else:
                    for tmp in tmpsrc:
                        sources.append(tmp)

                record_timer('daemons.conveyor.submitter.list_replicas', (time.time() - ts) * 1000)

                ts = time.time()
                rse_info = rsemgr.get_rse_info(dest_rse['rse'])
                record_timer('daemons.conveyor.submitter.get_rse', (time.time() - ts) * 1000)

                dsn = 'other'
                pfn = {}
                paths = {}
                if not rse_info['deterministic']:
                    ts = time.time()

                    # select a containing dataset
                    for parent in did.list_parent_dids(req['scope'], req['name']):
                        if parent['type'] == DIDType.DATASET:
                            dsn = parent['name']
                            break
                    record_timer('daemons.conveyor.submitter.list_parent_dids', (time.time() - ts) * 1000)

                    # always use SRM
                    ts = time.time()
                    nondet = rsemgr.create_protocol(rse_info, 'write', scheme='srm')
                    record_timer('daemons.conveyor.submitter.create_protocol', (time.time() - ts) * 1000)

                    # if there exists a prefix for SRM, use it
                    prefix = ''
                    for s in rse_info['protocols']:
                        if s['scheme'] == 'srm':
                            prefix = s['prefix']

                    # DQ2 path always starts with /, but prefix might not end with /
                    path = construct_surl_DQ2(dsn, req['name'])

                    tmp_path = '%s%s' % (prefix[:-1], path)
                    if prefix[-1] != '/':
                        tmp_path = '%s%s' % (prefix, path)
                    paths[req['scope'], req['name']] = path

                    # add the hostname
                    pfn['%s:%s' % (req['scope'], req['name'])] = nondet.path2pfn(tmp_path)
                    if req['request_type'] == RequestType.STAGEIN:
                        if len(sources) == 1:
                            pfn['%s:%s' % (req['scope'], req['name'])] = sources[0][1]
                        else:
                            raise

                else:
                    ts = time.time()
                    pfn = rsemgr.lfns2pfns(rse_info,
                                           lfns=[{'scope': req['scope'],
                                                  'name': req['name']}],
                                           scheme=scheme)
                    record_timer('daemons.conveyor.submitter.lfns2pfns', (time.time() - ts) * 1000)

                destinations = []
                for k in pfn:
                    if isinstance(pfn[k], (str, unicode)):
                        destinations.append(pfn[k])
                    elif isinstance(pfn[k], (tuple, list)):
                        for url in pfn[k]:
                            destinations.append(pfn[k][url])

                protocols = None
                try:
                    protocols = rsemgr.select_protocol(rse_info, 'write', scheme=scheme)
                except RSEProtocolNotSupported:
                    logging.warn('%s not supported by %s' % (scheme, rse_info['rse']))

                # we need to set the spacetoken if we use SRM
                dest_spacetoken = None
                if scheme == 'srm':
                    dest_spacetoken = protocols['extended_attributes']['space_token']

                # Come up with mock sources if necessary
                if mock:
                    tmp_sources = []
                    for s in sources:
                        tmp_sources.append((s[0], ':'.join(['mock']+s[1].split(':')[1:])))
                    sources = tmp_sources

                ts = time.time()

                tmp_metadata = {'request_id': req['request_id'],
                                'scope': req['scope'],
                                'name': req['name'],
                                'src_rse': sources[0][0],
                                'dst_rse': rse_info['rse'],
                                'dest_rse_id': req['dest_rse_id']}
                if 'previous_attempt_id' in req and req['previous_attempt_id']:
                    tmp_metadata['previous_attempt_id'] = req['previous_attempt_id']

                # Extend the metadata dictionary with request attributes
                copy_pin_lifetime, overwrite, bring_online = -1, True, None
                if req['request_type'] == RequestType.STAGEIN:
                    if req['attributes']:
                        attr = eval(req['attributes'])
                        copy_pin_lifetime = attr.get('lifetime')
                    overwrite = False
                    bring_online = 3600

                eid = request.submit_transfers(transfers=[{'request_id': req['request_id'],
                                                           'src_urls': [s[1] for s in sources],
                                                           'dest_urls': destinations,
                                                           'filesize': filesize,
                                                           'md5': md5,
                                                           'adler32': adler32,
                                                           'src_spacetoken': src_spacetoken,
                                                           'dest_spacetoken': dest_spacetoken,
                                                           'overwrite': overwrite,
                                                           'bring_online': bring_online,
                                                           'copy_pin_lifetime': copy_pin_lifetime}, ],
                                               transfertool='fts3',
                                               job_metadata=tmp_metadata)

                record_timer('daemons.conveyor.submitter.submit_transfer', (time.time() - ts) * 1000)

                ts = time.time()
                try:
                    logging.debug('UPDATE REPLICA STATE DID %s:%s RSE %s' % (req['scope'], req['name'], req['dest_rse_id']))
                    if not rse_info['deterministic']:
                        # No update for COPYING state needed anymore!
                        replica.update_replicas_states(replicas=[{'rse_id': req['dest_rse_id'],
                                                                  'scope': req['scope'],
                                                                  'name': req['name'],
                                                                  'path': paths[req['scope'], req['name']],
                                                                  'state': ReplicaState.COPYING}])
                    record_timer('daemons.conveyor.submitter.replica-set_copying', (time.time() - ts) * 1000)

                    if req['previous_attempt_id']:
                        logging.info('COPYING RETRY %s REQUEST %s PREVIOUS %s DID %s:%s FROM %s TO %s ' % (req['retry_count'],
                                                                                                           eid,
                                                                                                           req['previous_attempt_id'],
                                                                                                           req['scope'],
                                                                                                           req['name'],
                                                                                                           sources,
                                                                                                           destinations))
                    else:
                        logging.info('COPYING REQUEST %s DID %s:%s FROM %s TO %s ' % (eid,
                                                                                      req['scope'],
                                                                                      req['name'],
                                                                                      sources,
                                                                                      destinations))
                    record_counter('daemons.conveyor.submitter.submit_request')
                except UnsupportedOperation, e:
                    # The replica doesn't exist
                    # Need to cancel the request
                    logging.warning(e)
                    logging.info('Cancelling transfer request %s' % req['request_id'])
                    try:
                        request.cancel_request(eid[req['request_id']], transfertool='fts3')
                        request.purge_request(req['request_id'])
                    except Exception, e:
                        logging.warning('Cannot cancel FTS job : %s' % str(e))
        except:
            logging.critical(traceback.format_exc())
            logging.info('Cancelling transfer request %s' % req['request_id'])
            try:
                request.cancel_request(eid[req['request_id']], transfertool='fts3')
            except Exception, e:
                logging.warning('Cannot cancel FTS job : %s' % str(e))

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
        submitter(once, mock=mock)

    else:
        logging.info('starting submitter threads')
        threads = [threading.Thread(target=submitter, kwargs={'process': process,
                                                              'total_processes': total_processes,
                                                              'thread': i,
                                                              'total_threads': total_threads,
                                                              'mock': mock}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
