# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014
# - Wen Guan, <wen.guan@cern.ch>, 2014

"""
Conveyor is a daemon to manage file transfers.
"""

import json
import logging
import sys
import threading
import time
import traceback

from ConfigParser import NoOptionError

from rucio.common.config import config_get
from rucio.common.exception import DataIdentifierNotFound, RSEProtocolNotSupported, UnsupportedOperation, InvalidRSEExpression
from rucio.common.utils import construct_surl_DQ2
from rucio.core import did, replica, request, rse
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse_expression_parser import parse_expression
from rucio.daemons.conveyor import common
from rucio.db.constants import DIDType, RequestType, RequestState
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

    logging.info('submitter starting - process (%i/%i) thread (%i/%i)' % (process, total_processes, thread, total_threads))

    try:
        scheme = config_get('conveyor', 'scheme')
    except NoOptionError:
        scheme = 'srm'

    logging.info('submitter started - process (%i/%i) thread (%i/%i)' % (process, total_processes, thread, total_threads))

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
            record_timer('daemons.conveyor.submitter.get_next', (time.time() - ts) * 1000)

            if reqs:
                logging.debug('%i:%i - submitting %i requests' % (process, thread, len(reqs)))

            if not reqs or reqs == []:
                if once:
                    break
                time.sleep(60)  # Only sleep if there is nothing to do
                continue

            for req in reqs:
                ts = time.time()
                tmpsrc = []
                filesize = None
                md5 = None
                adler32 = None
                src_spacetoken = None
                dest_rse = rse.get_rse(rse=None, rse_id=req['dest_rse_id'])
                allowed_rses = []
                if req['request_type'] == RequestType.STAGEIN:
                    rses = rse.list_rses(filters={'staging_buffer': dest_rse['rse']})
                    allowed_rses = [x['rse'] for x in rses]
                allowed_source_rses = None
                activity = 'default'
                if req['attributes']:
                    if type(req['attributes']) is dict:
                        req_attributes = json.loads(json.dumps(req['attributes']))
                    else:
                        req_attributes = json.loads(str(req['attributes']))
                    activity = req_attributes['activity'] if req_attributes['activity'] else 'default'
                    source_replica_expression = req_attributes["source_replica_expression"]
                    if source_replica_expression:
                        try:
                            parsed_rses = parse_expression(source_replica_expression, session=None)
                        except InvalidRSEExpression, e:
                            logging.warn("Invalid RSE exception(%s) for request(%s)" % (source_replica_expression, req['request_id']))
                            allowed_source_rses = None
                        else:
                            allowed_source_rses = [x['rse'] for x in parsed_rses]

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
                                if allowed_source_rses and not (source_rse in allowed_source_rses):
                                    logging.debug("Skip source(%s) in request(%s) because of source_replica_expression(%s)" % (source_rse, req['request_id'], req['attributes']))
                                    continue
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
                    common.update_bad_request(req, dest_rse['rse'], RequestState.FAILED, 'No source replicas found')
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

                    # we must set the destination path for nondeterministic replicas explicitly
                    replica.update_replicas_paths([{'scope': req['scope'],
                                                    'name': req['name'],
                                                    'rse_id': req['dest_rse_id'],
                                                    'path': path}])

                else:
                    ts = time.time()
                    try:
                        pfn = rsemgr.lfns2pfns(rse_info,
                                               lfns=[{'scope': req['scope'],
                                                      'name': req['name']}],
                                               scheme=scheme)
                    except RSEProtocolNotSupported:
                        logging.warn('%s not supported by %s' % (scheme, rse_info['rse']))
                        common.update_bad_request(req, dest_rse['rse'], RequestState.FAILED, 'No supported protocols with destination')
                        logging.warn("Request %s set to failed because of not supported protocols" % req['request_id'])
                        continue

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
                    common.update_bad_request(req, dest_rse['rse'], RequestState.FAILED, 'No supported protocols with destination')
                    logging.warn("Request %s set to failed because of not supported protocols" % req['request_id'])
                    continue

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
                                'activity': activity,
                                'src_rse': sources[0][0],
                                'dst_rse': rse_info['rse'],
                                'dest_rse_id': req['dest_rse_id'],
                                'filesize': filesize,
                                'md5': md5,
                                'adler32': adler32}
                if 'previous_attempt_id' in req and req['previous_attempt_id']:
                    tmp_metadata['previous_attempt_id'] = req['previous_attempt_id']

                # Extend the metadata dictionary with request attributes
                copy_pin_lifetime, overwrite, bring_online = -1, True, None
                if req['request_type'] == RequestType.STAGEIN:
                    if req['attributes']:
                        if type(req['attributes']) is dict:
                            attr = json.loads(json.dumps(req['attributes']))
                        else:
                            attr = json.loads(str(req['attributes']))
                        copy_pin_lifetime = attr.get('lifetime')
                    overwrite = False
                    bring_online = 3600

                eid, transfer_host = request.submit_transfers(transfers=[{'request_id': req['request_id'],
                                                                          'src_urls': [s[1] for s in sources],
                                                                          'dest_urls': destinations,
                                                                          'filesize': filesize,
                                                                          'md5': md5,
                                                                          'adler32': adler32,
                                                                          'src_spacetoken': src_spacetoken,
                                                                          'dest_spacetoken': dest_spacetoken,
                                                                          'activity': activity,
                                                                          'overwrite': overwrite,
                                                                          'bring_online': bring_online,
                                                                          'copy_pin_lifetime': copy_pin_lifetime}, ],
                                                              transfertool='fts3',
                                                              job_metadata=tmp_metadata)

                record_timer('daemons.conveyor.submitter.submit_transfer', (time.time() - ts) * 1000)

                ts = time.time()
                try:
                    if req['previous_attempt_id']:
                        logging.info('COPYING RETRY %s REQUEST %s PREVIOUS %s DID %s:%s FROM %s TO %s USING %s' % (req['retry_count'],
                                                                                                                   eid,
                                                                                                                   req['previous_attempt_id'],
                                                                                                                   req['scope'],
                                                                                                                   req['name'],
                                                                                                                   sources,
                                                                                                                   destinations,
                                                                                                                   transfer_host))
                    else:
                        logging.info('COPYING REQUEST %s DID %s:%s FROM %s TO %s USING %s' % (eid,
                                                                                              req['scope'],
                                                                                              req['name'],
                                                                                              sources,
                                                                                              destinations,
                                                                                              transfer_host))
                    record_counter('daemons.conveyor.submitter.submit_request')
                except UnsupportedOperation, e:
                    # The replica doesn't exist, need to cancel the request
                    logging.warning(e)
                    logging.info('Cancelling transfer request %s' % req['request_id'])
                    try:
                        # TODO: for now, there is only ever one destination
                        request.cancel_request_did(req['scope'], req['name'], destinations[0])
                    except Exception, e:
                        logging.warning('Cannot cancel request: %s' % str(e))
        except:
            logging.critical(traceback.format_exc())
            logging.info('Cancelling transfer request %s' % req['request_id'])
            try:
                # TODO: for now, there is only ever one destination
                request.cancel_request_did(req['scope'], req['name'], destinations[0])
            except Exception, e:
                logging.warning('Cannot cancel request: %s' % str(e))

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
