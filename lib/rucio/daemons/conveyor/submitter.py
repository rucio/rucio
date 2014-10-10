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
from rucio.core import did, replica, request, rse as rse_core
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.constants import DIDType, RequestType, RequestState
from rucio.rse import rsemanager as rsemgr

logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("dogpile").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def get_rses(rses=None, include_rses=None, exclude_rses=None):
    working_rses = []
    rses_list = rse_core.list_rses()
    if rses:
        working_rses = [rse for rse in rses_list if rse['rse'] in rses]

    if include_rses:
        try:
            parsed_rses = parse_expression(include_rses, session=None)
        except InvalidRSEExpression, e:
            logging.critical("Invalid RSE exception(%s) to include RSEs" % (include_rses))
        else:
            for rse in parsed_rses:
                if rse not in working_rses:
                    working_rses.append(rse)

    if not (rses or include_rses):
        working_rses = rses_list

    if exclude_rses:
        try:
            parsed_rses = parse_expression(exclude_rses, session=None)
        except InvalidRSEExpression, e:
            logging.critical("Invalid RSE exception(%s) to include RSEs: %s" % (exclude_rses, e))
        else:
            working_rses = [rse for rse in working_rses if rse not in parsed_rses]

    working_rses = [rsemgr.get_rse_info(rse['rse']) for rse in working_rses]
    return working_rses


def get_requests(rse_id=None, process=0, total_processes=1, thread=0, total_threads=1, mock=False, requests_bulk=100):
    ts = time.time()
    reqs = request.get_next(request_type=[RequestType.TRANSFER,
                                          RequestType.STAGEIN,
                                          RequestType.STAGEOUT],
                            state=RequestState.QUEUED,
                            limit=requests_bulk,
                            rse=rse_id,
                            process=process,
                            total_processes=total_processes,
                            thread=thread,
                            total_threads=total_threads)
    record_timer('daemons.conveyor.submitter.get_next', (time.time() - ts) * 1000)
    return reqs


def get_sources(dest_rse, scheme, req):
    allowed_rses = []
    if req['request_type'] == RequestType.STAGEIN:
        rses = rse_core.list_rses(filters={'staging_buffer': dest_rse['rse']})
        allowed_rses = [x['rse'] for x in rses]

    allowed_source_rses = None
    if req['attributes']:
        if type(req['attributes']) is dict:
            req_attributes = json.loads(json.dumps(req['attributes']))
        else:
            req_attributes = json.loads(str(req['attributes']))
        source_replica_expression = req_attributes["source_replica_expression"]
        if source_replica_expression:
            try:
                parsed_rses = parse_expression(source_replica_expression, session=None)
            except InvalidRSEExpression, e:
                logging.warn("Invalid RSE exception(%s) for request(%s): %s" % (source_replica_expression, req['request_id'], e))
                allowed_source_rses = None
            else:
                allowed_source_rses = [x['rse'] for x in parsed_rses]

    tmpsrc = []
    metadata = {}
    try:
        ts = time.time()
        replications = replica.list_replicas(dids=[{'scope': req['scope'],
                                                    'name': req['name'],
                                                    'type': DIDType.FILE}],
                                             schemes=[scheme, 'gsiftp'])
        record_timer('daemons.conveyor.submitter.list_replicas', (time.time() - ts) * 1000)

        for source in replications:

            metadata['filesize'] = long(source['bytes'])
            metadata['md5'] = source['md5']
            metadata['adler32'] = source['adler32']
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
        return None, None
    except:
        record_counter('daemons.conveyor.submitter.unexpected')
        logging.critical('Something unexpected happened: %s' % traceback.format_exc())
        return None, None

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
        return None, None
    else:
        for tmp in tmpsrc:
            sources.append(tmp)

    return sources, metadata


def get_destinations(rse_info, scheme, req, sources):
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
                # TODO: need to check
                return None, None

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
            return None, None

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
        return None, None

    # we need to set the spacetoken if we use SRM
    dest_spacetoken = None
    if scheme == 'srm':
        dest_spacetoken = protocols['extended_attributes']['space_token']

    return destinations, dest_spacetoken


def get_transfer(rse, req, scheme, mock):
    src_spacetoken = None
    activity = 'default'
    if req['attributes']:
        if type(req['attributes']) is dict:
            req_attributes = json.loads(json.dumps(req['attributes']))
        else:
            req_attributes = json.loads(str(req['attributes']))
        activity = req_attributes['activity'] if req_attributes['activity'] else 'default'

    ts = time.time()
    sources, metadata = get_sources(rse, scheme, req)
    record_timer('daemons.conveyor.submitter.get_sources', (time.time() - ts) * 1000)
    logging.debug('Get sources for request(%s): %s' % (req['request_id'], sources))
    if sources is None:
        logging.warn("Request %s(%s:%s) to %s failed to get sources." % (req['request_id'], req['scope'], req['name'], rse['rse']))
        return None
    filesize = metadata['filesize']
    md5 = metadata['md5']
    adler32 = metadata['adler32']

    ts = time.time()
    destinations, dest_spacetoken = get_destinations(rse, scheme, req, sources)
    record_timer('daemons.conveyor.submitter.get_destinations', (time.time() - ts) * 1000)
    logging.debug('Get destinations for request(%s): %s' % (req['request_id'], destinations))
    if destinations is None:
        logging.warn("Request %s(%s:%s) to %s failed to get destinations." % (req['request_id'], req['scope'], req['name'], rse['rse']))
        return None

    # Come up with mock sources if necessary
    if mock:
        tmp_sources = []
        for s in sources:
            tmp_sources.append((s[0], ':'.join(['mock']+s[1].split(':')[1:])))
        sources = tmp_sources

    tmp_metadata = {'request_id': req['request_id'],
                    'scope': req['scope'],
                    'name': req['name'],
                    'activity': activity,
                    'src_rse': sources[0][0],
                    'dst_rse': rse['rse'],
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

    # exclude destination replica from source

    source_surls = [s[1] for s in sources]
    if source_surls == destinations and copy_pin_lifetime:
        logging.debug('STAGING REQUEST %s - Will not try to ignore equivalent sources' % req['request_id'])
    else:
        new_sources = source_surls
        for source_surl in source_surls:
            if source_surl in destinations:
                logging.info('EXCLUDING SOURCE %s FOR REQUEST %s' % (source_surl, req['request_id']))
                new_sources.remove(source_surl)
        source_surls = new_sources

    if not source_surls:
        logging.warn('ALL SOURCES EXCLUDED - SKIP REQUEST %s' % req['request_id'])
        return

    transfer = {'request_id': req['request_id'],
                'src_urls': source_surls,
                'dest_urls': destinations,
                'filesize': filesize,
                'md5': md5,
                'adler32': adler32,
                'src_spacetoken': src_spacetoken,
                'dest_spacetoken': dest_spacetoken,
                'activity': activity,
                'overwrite': overwrite,
                'bring_online': bring_online,
                'copy_pin_lifetime': copy_pin_lifetime,
                'file_metadata': tmp_metadata}
    return transfer


def submitter(once=False, rses=[], process=0, total_processes=1, thread=0, total_threads=1, mock=False, requests_bulk=100):
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

            if rses is None:
                rses = [None]

            for rse in rses:
                if rse:
                    # run in rse list mode
                    rse_info = rsemgr.get_rse_info(rse['rse'])
                    logging.info("Working on RSE: %s" % rse['rse'])
                    ts = time.time()
                    reqs = get_requests(rse_id=rse['id'], process=process, total_processes=total_processes, thread=thread, total_threads=total_threads, mock=mock, requests_bulk=requests_bulk)
                    record_timer('daemons.conveyor.submitter.get_requests', (time.time() - ts) * 1000)
                else:
                    # no rse list, run FIFO mode
                    rse_info = None
                    ts = time.time()
                    reqs = get_requests(process=process, total_processes=total_processes, thread=thread, total_threads=total_threads, mock=mock, requests_bulk=requests_bulk)
                    record_timer('daemons.conveyor.submitter.get_requests', (time.time() - ts) * 1000)

                if reqs:
                    logging.debug('%i:%i - submitting %i requests' % (process, thread, len(reqs)))

                if not reqs or reqs == []:
                    continue

                for req in reqs:
                    try:
                        if not rse:
                            # no rse list, in FIFO mode
                            dest_rse = rse_core.get_rse(rse=None, rse_id=req['dest_rse_id'])
                            rse_info = rsemgr.get_rse_info(dest_rse['rse'])

                        ts = time.time()
                        transfer = get_transfer(rse_info, req, scheme, mock)
                        record_timer('daemons.conveyor.submitter.get_transfer', (time.time() - ts) * 1000)
                        logging.debug('Get transfer for request(%s): %s' % (req['request_id'], transfer))

                        if transfer is None:
                            logging.warn("Request %s(%s:%s) to %s failed to get transfer." % (req['request_id'], req['scope'], req['name'], rse_info['rse']))
                            # TODO: Merge these two calls
                            request.set_request_state(req['request_id'],
                                                      RequestState.LOST)  # if the DID does not exist anymore
                            request.archive_request(req['request_id'])
                            continue

                        ts = time.time()
                        tmp_metadata = transfer['file_metadata']
                        eid, transfer_host = request.submit_transfers(transfers=[transfer, ], transfertool='fts3', job_metadata=tmp_metadata)

                        record_timer('daemons.conveyor.submitter.submit_transfer', (time.time() - ts) * 1000)

                        ts = time.time()
                        if req['previous_attempt_id']:
                            logging.info('COPYING RETRY %s REQUEST %s PREVIOUS %s DID %s:%s FROM %s TO %s USING %s' % (req['retry_count'],
                                                                                                                       eid,
                                                                                                                       req['previous_attempt_id'],
                                                                                                                       req['scope'],
                                                                                                                       req['name'],
                                                                                                                       transfer['src_urls'],
                                                                                                                       transfer['dest_urls'],
                                                                                                                       transfer_host))
                        else:
                            logging.info('COPYING REQUEST %s DID %s:%s FROM %s TO %s USING %s' % (eid,
                                                                                                  req['scope'],
                                                                                                  req['name'],
                                                                                                  transfer['src_urls'],
                                                                                                  transfer['dest_urls'],
                                                                                                  transfer_host))
                        record_counter('daemons.conveyor.submitter.submit_request')
                    except UnsupportedOperation, e:
                        # The replica doesn't exist, need to cancel the request
                        logging.warning(e)
                        logging.info('Cancelling transfer request %s' % req['request_id'])
                        try:
                            # TODO: for now, there is only ever one destination
                            request.cancel_request_did(req['scope'], req['name'], transfer['dest_urls'][0])
                        except Exception, e:
                            logging.warning('Cannot cancel request: %s' % str(e))
        except:
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


def run(once=False, process=0, total_processes=1, total_threads=1, mock=False, rses=[], include_rses=None, exclude_rses=None, requests_bulk=100):
    """
    Starts up the conveyer threads.
    """

    logging.info("submitter will work on special RSES mode(rses: %s, include_rses: %s, exclude_rses: %s)" % (rses, include_rses, exclude_rses))
    working_rses = None
    if rses or include_rses or exclude_rses:
        working_rses = get_rses(rses, include_rses, exclude_rses)
        logging.info("RSE list is specified, Run in RSE order mode")
    else:
        logging.info("RSE is not specified, Run in FIFO mode")

    if once:
        logging.info('executing one submitter iteration only')
        submitter(once, rses=working_rses, mock=mock, requests_bulk=requests_bulk)

    else:
        logging.info('starting submitter threads')
        threads = [threading.Thread(target=submitter, kwargs={'process': process,
                                                              'total_processes': total_processes,
                                                              'thread': i,
                                                              'total_threads': total_threads,
                                                              'rses': working_rses,
                                                              'requests_bulk': requests_bulk,
                                                              'mock': mock}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
