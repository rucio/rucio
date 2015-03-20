# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015
# - Wen Guan, <wen.guan@cern.ch>, 2014-2015

"""
Conveyor is a daemon to manage file transfers.
"""

import json
import logging
import os
import socket
import sys
import threading
import time
import traceback

from ConfigParser import NoOptionError

from rucio.common.closeness_sorter import sort_sources
from rucio.common.config import config_get
from rucio.common.exception import DataIdentifierNotFound, RSEProtocolNotSupported, InvalidRSEExpression, InvalidRequest
from rucio.common.utils import construct_surl, chunks
from rucio.core import did, heartbeat, replica, request, rse as rse_core
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.constants import DIDType, RequestType, RequestState, RSEType
from rucio.rse import rsemanager as rsemgr


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
            logging.error("Invalid RSE exception %s to include RSEs" % (include_rses))
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
            logging.error("Invalid RSE exception %s to exclude RSEs: %s" % (exclude_rses, e))
        else:
            working_rses = [rse for rse in working_rses if rse not in parsed_rses]

    working_rses = [rsemgr.get_rse_info(rse['rse']) for rse in working_rses]
    return working_rses


def get_requests(rse_id=None,
                 process=0, total_processes=1, thread=0, total_threads=1,
                 mock=False, bulk=100, activity=None, activity_shares=None):
    ts = time.time()
    reqs = request.get_next(request_type=[RequestType.TRANSFER,
                                          RequestType.STAGEIN,
                                          RequestType.STAGEOUT],
                            state=RequestState.QUEUED,
                            limit=bulk,
                            rse=rse_id,
                            activity=activity,
                            process=process,
                            total_processes=total_processes,
                            thread=thread,
                            total_threads=total_threads,
                            activity_shares=activity_shares)
    record_timer('daemons.conveyor.submitter.get_next', (time.time() - ts) * 1000)
    return reqs


def get_sources(dest_rse, schemes, req):
    allowed_rses = []
    if req['request_type'] == RequestType.STAGEIN:
        rses = rse_core.list_rses(filters={'staging_buffer': dest_rse['rse']})
        allowed_rses = [x['rse'] for x in rses]

    allowed_source_rses = []
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
                logging.error("Invalid RSE exception %s for request %s: %s" % (source_replica_expression,
                                                                               req['request_id'],
                                                                               e))
                allowed_source_rses = []
            else:
                allowed_source_rses = [x['rse'] for x in parsed_rses]

    tmpsrc = []
    metadata = {}
    try:
        ts = time.time()
        replications = replica.list_replicas(dids=[{'scope': req['scope'],
                                                    'name': req['name'],
                                                    'type': DIDType.FILE}],
                                             schemes=schemes)
        record_timer('daemons.conveyor.submitter.list_replicas', (time.time() - ts) * 1000)

        # return gracefully if there are no replicas for a DID
        if not replications:
            return None, None

        for source in replications:

            try:
                metadata['filesize'] = long(source['bytes'])
            except KeyError, e:
                logging.error('source for %s:%s has no filesize set - skipping' % (source['scope'], source['name']))
                continue

            metadata['md5'] = source['md5']
            metadata['adler32'] = source['adler32']
            # TODO: Source protection

            # we need to know upfront if we are mixed DISK/TAPE source
            mixed_source = []
            for source_rse in source['rses']:
                mixed_source.append(rse_core.get_rse(source_rse).rse_type)
            mixed_source = True if len(set(mixed_source)) > 1 else False

            for source_rse in source['rses']:
                if req['request_type'] == RequestType.STAGEIN:
                    if source_rse in allowed_rses:
                        for pfn in source['rses'][source_rse]:
                            # In case of staging request, we only use one source
                            tmpsrc = [(str(source_rse), str(pfn)), ]

                elif req['request_type'] == RequestType.TRANSFER:

                    if source_rse == dest_rse['rse']:
                        logging.debug('Skip source %s for request %s because it is the destination' % (source_rse,
                                                                                                       req['request_id']))
                        continue

                    if allowed_source_rses and not (source_rse in allowed_source_rses):
                        logging.debug('Skip source %s for request %s because of source_replica_expression %s' % (source_rse,
                                                                                                                 req['request_id'],
                                                                                                                 req['attributes']))
                        continue

                    # do not allow mixed source jobs, either all DISK or all TAPE
                    # do not use TAPE on the first try
                    if mixed_source:
                        if not req['previous_attempt_id'] and rse_core.get_rse(source_rse).rse_type == RSEType.TAPE and source_rse not in allowed_source_rses:
                            logging.debug('Skip tape source %s for request %s' % (source_rse,
                                                                                  req['request_id']))
                            continue
                        elif req['previous_attempt_id'] and rse_core.get_rse(source_rse).rse_type == RSEType.DISK and source_rse not in allowed_source_rses:
                            logging.debug('Skip disk source %s for retrial request %s' % (source_rse,
                                                                                          req['request_id']))
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
                                                  schemes=schemes,
                                                  unavailable=True)):
            logging.error('DID %s:%s lost! This should not happen!' % (req['scope'], req['name']))
        return None, None
    else:
        for tmp in tmpsrc:
            sources.append(tmp)

    if len(sources) > 1:
        sources = sort_sources(sources, dest_rse['rse'])
    return sources, metadata


def get_destinations(rse_info, scheme, req, naming_convention):
    dsn = 'other'
    pfn = {}
    if not rse_info['deterministic']:
        ts = time.time()

        # get rule scope and name
        if req['attributes']:
            if type(req['attributes']) is dict:
                req_attributes = json.loads(json.dumps(req['attributes']))
            else:
                req_attributes = json.loads(str(req['attributes']))
            if 'ds_name' in req_attributes:
                dsn = req_attributes["ds_name"]
        if dsn == 'other':
            # select a containing dataset
            for parent in did.list_parent_dids(req['scope'], req['name']):
                if parent['type'] == DIDType.DATASET:
                    dsn = parent['name']
                    break
        record_timer('daemons.conveyor.submitter.list_parent_dids', (time.time() - ts) * 1000)

        # DQ2 path always starts with /, but prefix might not end with /
        path = construct_surl(dsn, req['name'], naming_convention)

        # retrial transfers to tape need a new filename - add timestamp
        if req['request_type'] == RequestType.TRANSFER and rse_info['rse_type'] == 'TAPE':
            if 'previous_attempt_id' in req and req['previous_attempt_id']:
                path = '%s_%i' % (path, int(time.time()))
                logging.debug('Retrial transfer request %s DID %s:%s to tape %s renamed to %s' % (req['request_id'],
                                                                                                  req['scope'],
                                                                                                  req['name'],
                                                                                                  rse_info['rse'],
                                                                                                  path))
            elif req['activity'] and req['activity'] == 'Recovery':
                path = '%s_%i' % (path, int(time.time()))
                logging.debug('Recovery transfer request %s DID %s:%s to tape %s renamed to %s' % (req['request_id'],
                                                                                                   req['scope'],
                                                                                                   req['name'],
                                                                                                   rse_info['rse'],
                                                                                                   path))
        # we must set the destination path for nondeterministic replicas explicitly
        replica.update_replicas_paths([{'scope': req['scope'],
                                        'name': req['name'],
                                        'rse_id': req['dest_rse_id'],
                                        'path': path}])
        lfn = [{'scope': req['scope'], 'name': req['name'], 'path': path}]
    else:
        lfn = [{'scope': req['scope'], 'name': req['name']}]

    ts = time.time()
    try:
        pfn = rsemgr.lfns2pfns(rse_info, lfns=lfn, operation='write', scheme=scheme)
    except RSEProtocolNotSupported:
        logging.error('Operation "write" not supported by %s' % (rse_info['rse']))
        return None, None
    record_timer('daemons.conveyor.submitter.lfns2pfns', (time.time() - ts) * 1000)

    destinations = []
    for k in pfn:
        if isinstance(pfn[k], (str, unicode)):
            destinations.append(pfn[k])
        elif isinstance(pfn[k], (tuple, list)):
            for url in pfn[k]:
                destinations.append(pfn[k][url])

    protocol = None
    try:
        protocol = rsemgr.select_protocol(rse_info, 'write', scheme=scheme)
    except RSEProtocolNotSupported:
        logging.error('Operation "write" not supported by %s' % (rse_info['rse']))
        return None, None

    # we need to set the spacetoken if we use SRM
    dest_spacetoken = None
    if protocol['extended_attributes'] and 'space_token' in protocol['extended_attributes']:
        dest_spacetoken = protocol['extended_attributes']['space_token']

    return destinations, dest_spacetoken


def get_transfer(rse, req, scheme, mock):
    src_spacetoken = None

    if req['request_type'] == RequestType.STAGEIN:
        # for staging in, get the sources at first, then use the sources as destination
        if not (rse['staging_area'] or rse['rse'].endswith("STAGING")):
            raise InvalidRequest('Not a STAGING RSE for STAGE-IN request')

        ts = time.time()
        if scheme is None:
            sources, metadata = get_sources(rse, None, req)
        else:
            sources, metadata = get_sources(rse, [scheme], req)
        record_timer('daemons.conveyor.submitter.get_sources', (time.time() - ts) * 1000)
        logging.debug('Sources for request %s: %s' % (req['request_id'], sources))
        if sources is None:
            logging.error("Request %s DID %s:%s RSE %s failed to get sources" % (req['request_id'],
                                                                                 req['scope'],
                                                                                 req['name'],
                                                                                 rse['rse']))
            return None

        filesize = metadata['filesize']
        md5 = metadata['md5']
        adler32 = metadata['adler32']
        # Sources are properly set, so now we can finally force the source RSE to the destination RSE for STAGEIN
        dest_rse = sources[0][0]

        rse_attr = rse_core.list_rse_attributes(sources[0][0])
        fts_hosts = rse_attr.get('fts', None)
        naming_convention = rse_attr.get('naming_convention', None)

        if len(sources) == 1:
            destinations = [sources[0][1]]
        else:
            # TODO: need to check
            return None

        protocol = None
        try:
            # for stagin, dest_space_token should be the source space token
            source_rse_info = rsemgr.get_rse_info(sources[0][0])
            protocol = rsemgr.select_protocol(source_rse_info, 'write')
        except RSEProtocolNotSupported:
            logging.error('Operation "write" not supported by %s' % (source_rse_info['rse']))
            return None

        # we need to set the spacetoken if we use SRM
        dest_spacetoken = None
        if 'space_token' in protocol['extended_attributes']:
            dest_spacetoken = protocol['extended_attributes']['space_token']

        # Extend the metadata dictionary with request attributes
        copy_pin_lifetime, overwrite, bring_online = -1, True, None
        if req['attributes']:
            if type(req['attributes']) is dict:
                attr = json.loads(json.dumps(req['attributes']))
            else:
                attr = json.loads(str(req['attributes']))
            copy_pin_lifetime = attr.get('lifetime')
        overwrite = False
        bring_online = 21000
    else:
        # for normal transfer, get the destination at first, then use the destination scheme to get sources

        rse_attr = rse_core.list_rse_attributes(rse['rse'], rse['id'])
        fts_hosts = rse_attr.get('fts', None)
        naming_convention = rse_attr.get('naming_convention', None)

        ts = time.time()
        destinations, dest_spacetoken = get_destinations(rse, scheme, req, naming_convention)
        record_timer('daemons.conveyor.submitter.get_destinations', (time.time() - ts) * 1000)
        logging.debug('Destinations for request %s: %s' % (req['request_id'], destinations))
        if destinations is None:
            logging.error("Request %s DID %s:%s RSE %s failed to get destinations" % (req['request_id'],
                                                                                      req['scope'],
                                                                                      req['name'],
                                                                                      rse['rse']))
            return None

        schemes = []
        for destination in destinations:
            schemes.append(destination.split("://")[0])
        if 'srm' in schemes and 'gsiftp' not in schemes:
            schemes.append('gsiftp')
        if 'gsiftp' in schemes and 'srm' not in schemes:
            schemes.append('srm')
        logging.debug('Schemes will be allowed for sources: %s' % (schemes))

        ts = time.time()
        sources, metadata = get_sources(rse, schemes, req)
        record_timer('daemons.conveyor.submitter.get_sources', (time.time() - ts) * 1000)
        logging.debug('Sources for request %s: %s' % (req['request_id'], sources))

        if not sources:
            logging.error("Request %s DID %s:%s RSE %s failed to get sources" % (req['request_id'],
                                                                                 req['scope'],
                                                                                 req['name'],
                                                                                 rse['rse']))
            return None

        dest_rse = rse['rse']
        # exclude destination replica from source
        new_sources = sources
        for source in sources:
            if source[0] == dest_rse:
                logging.info('Excluding source %s for request %s: source is destination' % (source[0],
                                                                                            req['request_id']))
                new_sources.remove(source)
        sources = new_sources

        filesize = metadata['filesize']
        md5 = metadata['md5']
        adler32 = metadata['adler32']

        # Extend the metadata dictionary with request attributes
        copy_pin_lifetime, overwrite, bring_online = -1, True, None
        if rse_core.get_rse(sources[0][0]).rse_type == RSEType.TAPE:
            bring_online = 21000
        if rse_core.get_rse(None, rse_id=req['dest_rse_id']).rse_type == RSEType.TAPE:
            overwrite = False
        # make sure we only use one source when bring_online is needed
        if bring_online and len(sources) > 1:
            sources = [sources[0]]
            logging.info('Only using first source %s for bring_online request %s' % (sources,
                                                                                     req['request_id']))

    # Come up with mock sources if necessary
    if mock:
        tmp_sources = []
        for s in sources:
            tmp_sources.append((s[0], ':'.join(['mock']+s[1].split(':')[1:])))
        sources = tmp_sources

    source_surls = [s[1] for s in sources]
    if not source_surls:
        logging.error('All sources excluded - SKIP REQUEST %s' % req['request_id'])
        return

    tmp_metadata = {'request_id': req['request_id'],
                    'scope': req['scope'],
                    'name': req['name'],
                    'activity': req['activity'],
                    'src_rse': sources[0][0],
                    'dst_rse': dest_rse,
                    'dest_rse_id': req['dest_rse_id'],
                    'filesize': filesize,
                    'md5': md5,
                    'adler32': adler32}
    if 'previous_attempt_id' in req and req['previous_attempt_id']:
        tmp_metadata['previous_attempt_id'] = req['previous_attempt_id']

    retry_count = req['retry_count']
    if not retry_count:
        retry_count = 0
    if not fts_hosts:
        logging.error('Destination RSE %s FTS attribute not defined - SKIP REQUEST %s' % (rse['rse'], req['request_id']))
        return

    fts_list = fts_hosts.split(",")
    external_host = fts_list[retry_count % len(fts_list)]

    transfer = {'request_id': req['request_id'],
                'src_urls': source_surls,
                'dest_urls': destinations,
                'filesize': filesize,
                'md5': md5,
                'adler32': adler32,
                'src_spacetoken': src_spacetoken,
                'dest_spacetoken': dest_spacetoken,
                'activity': req['activity'],
                'overwrite': overwrite,
                'bring_online': bring_online,
                'copy_pin_lifetime': copy_pin_lifetime,
                'external_host': external_host,
                'file_metadata': tmp_metadata,
                'rule_id': req['rule_id']}
    return transfer


def bulk_group_transfer(transfers, policy='rule'):
    grouped_transfers = {}
    for transfer in transfers:
        external_host = transfer['external_host']
        if external_host not in grouped_transfers:
            grouped_transfers[external_host] = {}

        file = {'sources': transfer['src_urls'],
                'destinations': transfer['dest_urls'],
                'metadata': transfer['file_metadata'],
                'filesize': int(transfer['filesize']),
                'checksum': None,
                'activity': str(transfer['activity'])}
        if 'md5' in file['metadata'].keys() and file['metadata']['md5']:
            file['checksum'] = 'MD5:%s' % str(file['metadata']['md5'])
        if 'adler32' in file['metadata'].keys() and file['metadata']['adler32']:
            file['checksum'] = 'ADLER32:%s' % str(transfer['adler32'])

        job_params = {'verify_checksum': True if file['checksum'] else False,
                      'spacetoken': transfer['dest_spacetoken'] if transfer['dest_spacetoken'] else 'null',
                      'copy_pin_lifetime': transfer['copy_pin_lifetime'] if transfer['copy_pin_lifetime'] else -1,
                      'bring_online': transfer['bring_online'] if transfer['bring_online'] else None,
                      'job_metadata': {'issuer': 'rucio'},  # finaly job_meta will like this. currently job_meta will equal file_meta to include request_id and etc.
                      'source_spacetoken': transfer['src_spacetoken'] if transfer['src_spacetoken'] else None,
                      'overwrite': transfer['overwrite'],
                      'priority': 3}

        # for multiple source replicas, no bulk submission
        if len(transfer['src_urls']) > 1:
            job_params['job_metadata']['multi_sources'] = True
            grouped_transfers[external_host][transfer['request_id']] = {'files': [file], 'job_params': job_params}
        else:
            job_params['job_metadata']['multi_sources'] = False
            key = '%s,%s,%s,%s,%s,%s,%s,%s' % (job_params['verify_checksum'], job_params['spacetoken'], job_params['copy_pin_lifetime'],
                                               job_params['bring_online'], job_params['job_metadata'], job_params['source_spacetoken'],
                                               job_params['overwrite'], job_params['priority'])
            if policy == 'rule':
                key = '%s,%s' % (transfer['rule_id'], key)
            if policy == 'dest':
                key = '%s,%s' % (file['metadata']['dst_rse'], key)
            if policy == 'src_dest':
                key = '%s,%s,%s' % (file['metadata']['src_rse'], file['metadata']['dst_rse'], key)
            # maybe here we need to hash the key if it's too long

            if key not in grouped_transfers[external_host]:
                grouped_transfers[external_host][key] = {'files': [file], 'job_params': job_params}
            else:
                grouped_transfers[external_host][key]['files'].append(file)
    return grouped_transfers


def submitter(once=False, rses=[],
              process=0, total_processes=1, thread=0, total_threads=1,
              mock=False, bulk=100, group_bulk=1, group_policy='rule',
              activities=None, activity_shares=None):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    logging.info('submitter starting - process (%i/%i) thread (%i/%i)' % (process,
                                                                          total_processes,
                                                                          thread,
                                                                          total_threads))
    try:
        scheme = config_get('conveyor', 'scheme')
    except NoOptionError:
        scheme = None

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()

    logging.info('submitter started - process (%i/%i) thread (%i/%i)' % (process,
                                                                         total_processes,
                                                                         thread,
                                                                         total_threads))

    while not graceful_stop.is_set():

        heartbeat.live(executable, hostname, pid, hb_thread)

        try:

            if activities is None:
                activities = [None]
            for activity in activities:
                if rses is None:
                    rses = [None]

                for rse in rses:
                    if rse:
                        # run in rse list mode
                        rse_info = rsemgr.get_rse_info(rse['rse'])
                        logging.info("Working on RSE: %s" % rse['rse'])
                        ts = time.time()
                        reqs = get_requests(rse_id=rse['id'],
                                            process=process,
                                            total_processes=total_processes,
                                            thread=thread,
                                            total_threads=total_threads,
                                            mock=mock,
                                            bulk=bulk,
                                            activity=activity,
                                            activity_shares=activity_shares)
                        record_timer('daemons.conveyor.submitter.get_requests', (time.time() - ts) * 1000)
                    else:
                        # no rse list, run FIFO mode
                        rse_info = None
                        ts = time.time()
                        reqs = get_requests(process=process,
                                            total_processes=total_processes,
                                            thread=thread,
                                            total_threads=total_threads,
                                            mock=mock,
                                            bulk=bulk,
                                            activity=activity,
                                            activity_shares=activity_shares)
                        record_timer('daemons.conveyor.submitter.get_requests', (time.time() - ts) * 1000)

                    if reqs:
                        logging.debug('%i:%i - submitting %i requests' % (process, thread, len(reqs)))

                    if not reqs or reqs == []:
                        time.sleep(60)
                        continue

                    # get transfers
                    transfers = []
                    for req in reqs:
                        try:
                            if not rse:
                                # no rse list, in FIFO mode
                                dest_rse = rse_core.get_rse(rse=None, rse_id=req['dest_rse_id'])
                                rse_info = rsemgr.get_rse_info(dest_rse['rse'])

                            ts = time.time()
                            transfer = get_transfer(rse_info, req, scheme, mock)
                            record_timer('daemons.conveyor.submitter.get_transfer', (time.time() - ts) * 1000)
                            logging.debug('Transfer for request %s: %s' % (req['request_id'], transfer))

                            if transfer is None:
                                logging.error("Request %s DID %s:%s RSE %s failed to get transfer" % (req['request_id'],
                                                                                                      req['scope'],
                                                                                                      req['name'],
                                                                                                      rse_info['rse']))
                                request.set_request_state(req['request_id'],
                                                          RequestState.LOST)  # if the DID does not exist anymore
                                continue

                            transfers.append(transfer)
                        except Exception, e:
                            logging.error("Failed to get transfer for request(%s): %s " % (req['request_id'], str(e)))

                    # group transfers
                    grouped_transfers = bulk_group_transfer(transfers, group_policy)

                    # submit transfers
                    for external_host in grouped_transfers:
                        for key in grouped_transfers[external_host]:
                            job_params = grouped_transfers[external_host][key]['job_params']
                            for xfers_files in chunks(grouped_transfers[external_host][key]['files'], group_bulk):
                                # submit transfers
                                eid = None
                                try:
                                    ts = time.time()
                                    eid = request.submit_bulk_transfers(external_host, files=xfers_files, transfertool='fts3', job_params=job_params)
                                    logging.debug("Submit job %s to %s" % (eid, external_host))
                                    record_timer('daemons.conveyor.submitter.submit_bulk_transfer', (time.time() - ts) * 1000/len(xfers_files))
                                except Exception, ex:
                                    logging.error("Failed to submit a job with error %s: %s" % (str(ex), traceback.format_exc()))

                                # register transfer returns
                                try:
                                    xfers_ret = {}
                                    for file in xfers_files:
                                        file_metadata = file['metadata']
                                        request_id = file_metadata['request_id']
                                        log_str = 'COPYING REQUEST %s DID %s:%s PREVIOUS %s FROM %s TO %s USING %s ' % (file_metadata['request_id'],
                                                                                                                        file_metadata['scope'],
                                                                                                                        file_metadata['name'],
                                                                                                                        file_metadata['previous_attempt_id'] if 'previous_attempt_id' in file_metadata else None,
                                                                                                                        file['sources'],
                                                                                                                        file['destinations'],
                                                                                                                        external_host)
                                        if eid:
                                            xfers_ret[request_id] = {'state': RequestState.SUBMITTED, 'external_host': external_host, 'external_id': eid, 'dest_url':  file['destinations'][0]}
                                            log_str += 'with state(%s) with eid(%s)' % (RequestState.SUBMITTED, eid)
                                            logging.info(log_str)
                                        else:
                                            xfers_ret[request_id] = {'state': RequestState.LOST, 'external_host': external_host, 'external_id': None, 'dest_url': None}
                                            log_str += 'with state(%s) with eid(%s)' % (RequestState.LOST, None)
                                            logging.warn(log_str)
                                    request.set_request_transfers(xfers_ret)
                                except Exception, ex:
                                    logging.error("Failed to register transfer state with error %s: %s" % (str(ex), traceback.format_exc()))
                                record_counter('daemons.conveyor.submitter.submit_request', len(xfers_files))
        except:
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.info('graceful stop requested')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False,
        process=0, total_processes=1, total_threads=1, group_bulk=1, group_policy='rule',
        mock=False, rses=[], include_rses=None, exclude_rses=None, bulk=100,
        activities=[], activity_shares=None):
    """
    Starts up the conveyer threads.
    """

    if mock:
        logging.info('mock source replicas: enabled')

    working_rses = None
    if rses or include_rses or exclude_rses:
        working_rses = get_rses(rses, include_rses, exclude_rses)
        logging.info("RSE selection: RSEs: %s, Include: %s, Exclude: %s" % (rses,
                                                                            include_rses,
                                                                            exclude_rses))
    else:
        logging.info("RSE selection: automatic")

    if activity_shares:

        try:
            activity_shares = json.loads(activity_shares)
        except:
            logging.critical('activity share is not a valid JSON dictionary')
            return

        try:
            if round(sum(activity_shares.values()), 2) != 1:
                logging.critical('activity shares do not sum up to 1, got %s - aborting' % round(sum(activity_shares.values()), 2))
                return
        except:
            logging.critical('activity shares are not numbers? - aborting')
            return

        activity_shares.update((share, int(percentage*bulk)) for share, percentage in activity_shares.items())
        logging.info('activity shares enabled: %s' % activity_shares)

    if once:
        logging.info('executing one submitter iteration only')
        submitter(once,
                  rses=working_rses,
                  mock=mock,
                  bulk=bulk,
                  group_bulk=group_bulk,
                  group_policy=group_policy,
                  activities=activities,
                  activity_shares=activity_shares)

    else:
        logging.info('starting submitter threads')
        threads = [threading.Thread(target=submitter, kwargs={'process': process,
                                                              'total_processes': total_processes,
                                                              'thread': i,
                                                              'total_threads': total_threads,
                                                              'rses': working_rses,
                                                              'bulk': bulk,
                                                              'group_bulk': group_bulk,
                                                              'group_policy': group_policy,
                                                              'activities': activities,
                                                              'mock': mock,
                                                              'activity_shares': activity_shares}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
