# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015
# - Wen Guan, <wen.guan@cern.ch>, 2014-2015

"""
Methods common to different conveyor submitter daemons.
"""

import json
import logging
import random
import time
import traceback

from rucio.common.closeness_sorter import sort_sources
from rucio.common.exception import DataIdentifierNotFound, RSEProtocolNotSupported, InvalidRSEExpression, InvalidRequest
from rucio.common.rse_attributes import get_rse_attributes
from rucio.common.utils import construct_surl, chunks
from rucio.core import did, replica, request, rse as rse_core
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.constants import DIDType, RequestType, RequestState, RSEType
from rucio.db.session import read_session
from rucio.rse import rsemanager as rsemgr


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


def get_sources(dest_rse, schemes, req, max_sources=4):
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
        used_sources = request.get_sources(req['request_id'])
        for tmp in tmpsrc:
            source_rse_info = rsemgr.get_rse_info(tmp[0])
            rank = None
            if used_sources:
                for used_source in used_sources:
                    if used_source['rse_id'] == source_rse_info['id']:
                        # file already used
                        rank = used_source['ranking']
                        break
            sources.append((tmp[0], tmp[1], source_rse_info['id'], rank))

    if len(sources) > 1:
        sources = sort_sources(sources, dest_rse['rse'])
    if len(sources) > max_sources:
        sources = sources[:max_sources]
        random.shuffle(sources)
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


def get_transfer(rse, req, scheme, mock, max_sources=4):
    src_spacetoken = None

    if req['request_type'] == RequestType.STAGEIN:
        # for staging in, get the sources at first, then use the sources as destination
        if not (rse['staging_area'] or rse['rse'].endswith("STAGING")):
            raise InvalidRequest('Not a STAGING RSE for STAGE-IN request')

        ts = time.time()
        if scheme is None:
            sources, metadata = get_sources(rse, None, req, max_sources=max_sources)
        else:
            sources, metadata = get_sources(rse, [scheme], req, max_sources=max_sources)
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
        bring_online = 172800
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
        sources, metadata = get_sources(rse, schemes, req, max_sources=max_sources)
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
            bring_online = 172800
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
            tmp_sources.append((s[0], ':'.join(['mock']+s[1].split(':')[1:]), s[2], s[3]))
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
                'sources': sources,
                # 'src_urls': source_surls,
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


def get_transfers_from_requests(process=0, total_processes=1, thread=0, total_threads=1, rse_ids=None,
                                mock=False, bulk=100, activity=None, activity_shares=None, scheme=None, max_sources=4):
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
        logging.debug('%i:%i - Getting %i requests' % (process, thread, len(reqs)))

    if not reqs or reqs == []:
        return {}

    # get transfers
    transfers = {}
    for req in reqs:
        try:
            if rse_ids and req['dest_rse_id'] not in rse_ids:
                # logging.info("Request dest %s is not in RSEs list, skip")
                continue
            else:
                dest_rse = rse_core.get_rse(rse=None, rse_id=req['dest_rse_id'])
                rse_info = rsemgr.get_rse_info(dest_rse['rse'])

                ts = time.time()
                transfer = get_transfer(rse_info, req, scheme, mock, max_sources=max_sources)
                record_timer('daemons.conveyor.submitter.get_transfer', (time.time() - ts) * 1000)
                logging.debug('Transfer for request %s: %s' % (req['request_id'], transfer))

                if transfer is None:
                    logging.error("Request %s DID %s:%s RSE %s failed to get transfer" % (req['request_id'],
                                                                                          req['scope'],
                                                                                          req['name'],
                                                                                          rse_info['rse']))
                    request.set_request_state(req['request_id'], RequestState.LOST)
                    continue

                transfers[req['request_id']] = transfer
        except Exception, e:
            logging.error("Failed to get transfer for request(%s): %s " % (req['request_id'], str(e)))
    return transfers


def bulk_group_transfer(transfers, policy='rule', group_bulk=200, fts_source_strategy='auto'):
    grouped_transfers = {}
    grouped_jobs = {}
    for request_id in transfers:
        transfer = transfers[request_id]
        external_host = transfer['external_host']
        if external_host not in grouped_transfers:
            grouped_transfers[external_host] = {}
            grouped_jobs[external_host] = []

        file = {'sources': transfer['sources'],
                'destinations': transfer['dest_urls'],
                'metadata': transfer['file_metadata'],
                'filesize': int(transfer['file_metadata']['filesize']),
                'checksum': None,
                'selection_strategy': fts_source_strategy,
                'activity': str(transfer['file_metadata']['activity'])}
        if 'md5' in file['metadata'].keys() and file['metadata']['md5']:
            file['checksum'] = 'MD5:%s' % str(file['metadata']['md5'])
        if 'adler32' in file['metadata'].keys() and file['metadata']['adler32']:
            file['checksum'] = 'ADLER32:%s' % str(file['metadata']['adler32'])

        job_params = {'verify_checksum': True if file['checksum'] else False,
                      'spacetoken': transfer['dest_spacetoken'] if transfer['dest_spacetoken'] else 'null',
                      'copy_pin_lifetime': transfer['copy_pin_lifetime'] if transfer['copy_pin_lifetime'] else -1,
                      'bring_online': transfer['bring_online'] if transfer['bring_online'] else None,
                      'job_metadata': {'issuer': 'rucio'},  # finaly job_meta will like this. currently job_meta will equal file_meta to include request_id and etc.
                      'source_spacetoken': transfer['src_spacetoken'] if transfer['src_spacetoken'] else None,
                      'overwrite': transfer['overwrite'],
                      'priority': 3}

        # for multiple source replicas, no bulk submission
        if len(transfer['sources']) > 1:
            job_params['job_metadata']['multi_sources'] = True
            grouped_jobs[external_host].append({'files': [file], 'job_params': job_params})
        else:
            job_params['job_metadata']['multi_sources'] = False
            job_key = '%s,%s,%s,%s,%s,%s,%s,%s' % (job_params['verify_checksum'], job_params['spacetoken'], job_params['copy_pin_lifetime'],
                                                   job_params['bring_online'], job_params['job_metadata'], job_params['source_spacetoken'],
                                                   job_params['overwrite'], job_params['priority'])
            if job_key not in grouped_transfers[external_host]:
                grouped_transfers[external_host][job_key] = {}

            if policy == 'rule':
                policy_key = '%s' % (transfer['rule_id'])
            if policy == 'dest':
                policy_key = '%s' % (file['metadata']['dst_rse'])
            if policy == 'src_dest':
                policy_key = '%s,%s' % (file['metadata']['src_rse'], file['metadata']['dst_rse'])
            # maybe here we need to hash the key if it's too long

            if policy_key not in grouped_transfers[external_host][job_key]:
                grouped_transfers[external_host][job_key][policy_key] = {'files': [file], 'job_params': job_params}
            else:
                grouped_transfers[external_host][job_key][policy_key]['files'].append(file)

    # for jobs with different job_key, we cannot put in one job.
    # but for jobs with the same job_key, we can put them in one job if there are not many 'files' in one policy_key(rule, dest or scr_dest)
    for external_host in grouped_transfers:
        for job_key in grouped_transfers[external_host]:
            # for all policy groups in job_key, the job_params is the same.
            current_job = {'files': []}
            for policy_key in grouped_transfers[external_host][job_key]:
                job_params = grouped_transfers[external_host][job_key][policy_key]['job_params']
                if len(grouped_transfers[external_host][job_key][policy_key]['files']) > group_bulk:
                    for xfers_files in chunks(grouped_transfers[external_host][job_key][policy_key]['files'], group_bulk):
                        # for the last small piece, just submit it.
                        grouped_jobs[external_host].append({'files': xfers_files, 'job_params': job_params})
                else:
                    if len(current_job['files']) + len(grouped_transfers[external_host][job_key][policy_key]['files']) < group_bulk:
                        current_job['files'] += grouped_transfers[external_host][job_key][policy_key]['files']
                    else:
                        if len(current_job['files']) > group_bulk / 2:
                            grouped_jobs[external_host].append({'files': current_job['files'], 'job_params': job_params})
                            current_job['files'] = grouped_transfers[external_host][job_key][policy_key]['files']
                        else:
                            grouped_jobs[external_host].append({'files': grouped_transfers[external_host][job_key][policy_key]['files'], 'job_params': job_params})
            if len(current_job['files']) > 0:
                grouped_jobs[external_host].append({'files': current_job['files'], 'job_params': job_params})

    return grouped_jobs


@read_session
def get_transfer_requests_and_source_replicas(process=None, total_processes=None, thread=None, total_threads=None,
                                              activity=None, older_than=None, rses=None, schemes=None, session=None):
    req_sources = request.list_transfer_requests_and_source_replicas(process=process, total_processes=total_processes, thread=thread, total_threads=total_threads,
                                                                     activity=activity, older_than=older_than, rses=rses, session=session)

    transfers, rses_info, protocols, rse_attrs, reqs_no_source, reqs_scheme_mismatch = {}, {}, {}, {}, [], []
    for id, rule_id, scope, name, md5, adler32, bytes, activity, attributes, previous_attempt_id, dest_rse_id, source_rse_id, rse, deterministic, rse_type, path, retry_count, src_url, ranking in req_sources:
        try:
            if rses and dest_rse_id not in rses:
                continue

            if id not in transfers:
                if id not in reqs_no_source:
                    reqs_no_source.append(id)

                # source_rse_id will be None if no source replicas
                # rse will be None if rse is staging area
                if source_rse_id is None or rse is None:
                    continue

                # Get destination rse information and protocol
                if dest_rse_id not in rses_info:
                    dest_rse = rse_core.get_rse_name(rse_id=dest_rse_id, session=session)
                    rses_info[dest_rse_id] = rsemgr.get_rse_info(dest_rse, session=session)
                if dest_rse_id not in rse_attrs:
                    rse_attrs[dest_rse_id] = get_rse_attributes(dest_rse_id, session=session)

                attr = None
                if attributes:
                    if type(attributes) is dict:
                        attr = json.loads(json.dumps(attributes))
                    else:
                        attr = json.loads(str(attributes))

                # parse source expression
                source_replica_expression = attr["source_replica_expression"] if "source_replica_expression" in attr else None
                if source_replica_expression:
                    try:
                        parsed_rses = parse_expression(source_replica_expression, session=session)
                    except InvalidRSEExpression, e:
                        logging.error("Invalid RSE exception %s: %s" % (source_replica_expression, e))
                        continue
                    else:
                        allowed_rses = [x['rse'] for x in parsed_rses]
                        if rse not in allowed_rses:
                            continue

                # Get protocol
                if dest_rse_id not in protocols:
                    try:
                        protocols[dest_rse_id] = rsemgr.create_protocol(rses_info[dest_rse_id], 'write', schemes)
                    except RSEProtocolNotSupported:
                        logging.error('Operation "write" not supported by %s with schemes %s' % (rses_info[dest_rse_id]['rse'], schemes))
                        if id in reqs_no_source:
                            reqs_no_source.remove(id)
                        if id not in reqs_scheme_mismatch:
                            reqs_scheme_mismatch.append(id)
                        continue

                # get dest space token
                dest_spacetoken = None
                if protocols[dest_rse_id].attributes and \
                   'extended_attributes' in protocols[dest_rse_id].attributes and \
                   protocols[dest_rse_id].attributes['extended_attributes'] and \
                   'space_token' in protocols[dest_rse_id].attributes['extended_attributes']:
                    dest_spacetoken = protocols[dest_rse_id].attributes['extended_attributes']['space_token']

                # Compute the destination url
                if rses_info[dest_rse_id]['deterministic']:
                    dest_url = protocols[dest_rse_id].lfns2pfns(lfns={'scope': scope, 'name': name}).values()[0]
                else:
                    # compute dest url in case of non deterministic
                    # naming convention, etc.
                    dsn = 'other'
                    if attr and 'ds_name' in attr:
                        dsn = attr["ds_name"]

                    else:
                        # select a containing dataset
                        for parent in did.list_parent_dids(scope, name):
                            if parent['type'] == DIDType.DATASET:
                                dsn = parent['name']
                                break
                    # DQ2 path always starts with /, but prefix might not end with /
                    naming_convention = rse_attrs[dest_rse_id].get('naming_convention', None)
                    dest_path = construct_surl(dsn, name, naming_convention)
                    if rses_info[dest_rse_id]['rse_type'] == RSEType.TAPE:
                        if previous_attempt_id or activity == 'Recovery':
                            dest_path = '%s_%i' % (dest_path, int(time.time()))

                    # replica cannot be imported. finisher will do it
                    # update_replicas_paths([{'scope': req['scope'],
                    #                                     'name': req['name'],
                    #                                     'rse_id': req['dest_rse_id'],
                    #                                     'path': dest_path}])
                    dest_url = protocols[dest_rse_id].lfns2pfns(lfns={'scope': scope, 'name': name, 'path': dest_path}).values()[0]

                # get allowed source scheme
                src_schemes = []
                dest_scheme = dest_url.split("://")[0]
                if dest_scheme in ['srm', 'gsiftp']:
                    src_schemes = ['srm', 'gsiftp']
                else:
                    src_schemes = [dest_scheme]

                # Compute the sources: urls, etc
                if source_rse_id not in rses_info:
                    # source_rse = rse_core.get_rse_name(rse_id=source_rse_id, session=session)
                    source_rse = rse
                    rses_info[source_rse_id] = rsemgr.get_rse_info(source_rse, session=session)

                # Get protocol
                source_rse_id_key = '%s_%s' % (source_rse_id, '_'.join(src_schemes))
                if source_rse_id_key not in protocols:
                    try:
                        protocols[source_rse_id_key] = rsemgr.create_protocol(rses_info[source_rse_id], 'read', src_schemes)
                    except RSEProtocolNotSupported:
                        logging.error('Operation "read" not supported by %s with schemes %s' % (rses_info[source_rse_id]['rse'], src_schemes))
                        if id in reqs_no_source:
                            reqs_no_source.remove(id)
                        if id not in reqs_scheme_mismatch:
                            reqs_scheme_mismatch.append(id)
                        continue

                source_url = protocols[source_rse_id_key].lfns2pfns(lfns={'scope': scope, 'name': name, 'path': path}).values()[0]

                # Extend the metadata dictionary with request attributes
                overwrite, bring_online = True, None
                if rses_info[source_rse_id]['rse_type'] == RSEType.TAPE:
                    bring_online = 172800  # 48 hours
                if rses_info[dest_rse_id]['rse_type'] == RSEType.TAPE:
                    overwrite = False

                # get external_host
                fts_hosts = rse_attrs[dest_rse_id].get('fts', None)
                if not fts_hosts:
                    logging.error('Source RSE %s FTS attribute not defined - SKIP REQUEST %s' % (rse, id))
                    continue
                if retry_count is None:
                    retry_count = 0
                fts_list = fts_hosts.split(",")
                external_host = fts_list[retry_count % len(fts_list)]

                if id in reqs_no_source:
                    reqs_no_source.remove(id)

                file_metadata = {'request_id': id,
                                 'scope': scope,
                                 'name': name,
                                 'activity': activity,
                                 'src_rse': rse,
                                 'dst_rse': rses_info[dest_rse_id]['rse'],
                                 'dest_rse_id': dest_rse_id,
                                 'filesize': bytes,
                                 'md5': md5,
                                 'adler32': adler32}

                if previous_attempt_id:
                    file_metadata['previous_attempt_id'] = previous_attempt_id

                transfers[id] = {'request_id': id,
                                 'schemes': src_schemes,
                                 # 'src_urls': [source_url],
                                 'sources': [(rse, source_url, source_rse_id, ranking)],
                                 'dest_urls': [dest_url],
                                 'src_spacetoken': None,
                                 'dest_spacetoken': dest_spacetoken,
                                 'overwrite': overwrite,
                                 'bring_online': bring_online,
                                 'copy_pin_lifetime': attr.get('lifetime', -1),
                                 'external_host': external_host,
                                 'selection_strategy': 'auto',
                                 'rule_id': rule_id,
                                 'file_metadata': file_metadata}
            else:
                schemes = transfers[id]['schemes']

                # source_rse_id will be None if no source replicas
                # rse will be None if rse is staging area
                if source_rse_id is None or rse is None:
                    continue

                # Compute the sources: urls, etc
                if source_rse_id not in rses_info:
                    # source_rse = rse_core.get_rse_name(rse_id=source_rse_id, session=session)
                    source_rse = rse
                    rses_info[source_rse_id] = rsemgr.get_rse_info(source_rse, session=session)

                # TAPE should not mixed with Disk and should not use as first try
                # If there is a source whose ranking is more than 0, Tape will not be used.
                if rses_info[source_rse_id]['rse_type'] == RSEType.TAPE:
                    # current src_rse is Tape
                    if not transfers[id]['bring_online']:
                        # the founded sources are disks.
                        avail_disks = False
                        founded_sources = transfers[id]['sources']
                        for founded_source in founded_sources:
                            if founded_source[3] is None or founded_source[3] >= 0:
                                avail_disks = True
                                break
                        if avail_disks:
                            continue
                        else:
                            # no available Disks with ranking more than 0, remove all founded sources to use this tape
                            transfers[id]['sources'] = []
                            transfers[id]['bring_online'] = 172800
                else:
                    # current src_rse is Disk
                    if transfers[id]['bring_online']:
                        # the founded sources are Tape
                        if ranking is None or ranking >= 0:
                            # remove founded Tape sources
                            transfers[id]['sources'] = []
                            transfers[id]['bring_online'] = None
                        else:
                            # will not use current src_rse
                            continue

                # Get protocol
                source_rse_id_key = '%s_%s' % (source_rse_id, '_'.join(schemes))
                if source_rse_id_key not in protocols:
                    try:
                        protocols[source_rse_id_key] = rsemgr.create_protocol(rses_info[source_rse_id], 'read', schemes)
                    except RSEProtocolNotSupported:
                        logging.error('Operation "read" not supported by %s with schemes %s' % (rses_info[source_rse_id]['rse'], schemes))
                        if id not in reqs_scheme_mismatch:
                            reqs_scheme_mismatch.append(id)
                        continue
                source_url = protocols[source_rse_id_key].lfns2pfns(lfns={'scope': scope, 'name': name, 'path': path}).values()[0]

                # transfers[id]['src_urls'].append((source_rse_id, source_url))
                transfers[id]['sources'].append((rse, source_url, source_rse_id, ranking))

        except:
            logging.error("Exception happened when trying to get transfer for request %s: %s" % (id, traceback.format_exc()))
            break

    return transfers, reqs_no_source, reqs_scheme_mismatch


@read_session
def get_stagein_requests_and_source_replicas(process=None, total_processes=None, thread=None, total_threads=None,
                                             activity=None, older_than=None, rses=None, mock=False, schemes=None, session=None):
    req_sources = request.list_stagein_requests_and_source_replicas(process=process, total_processes=total_processes, thread=thread, total_threads=total_threads,
                                                                    activity=activity, older_than=older_than, rses=rses, session=session)

    transfers, rses_info, protocols, rse_attrs, reqs_no_source = {}, {}, {}, {}, []
    for id, rule_id, scope, name, md5, adler32, bytes, activity, attributes, dest_rse_id, source_rse_id, rse, deterministic, rse_type, path, staging_buffer, retry_count, previous_attempt_id, src_url, ranking in req_sources:
        try:
            if rses and dest_rse_id not in rses:
                continue

            if id not in transfers:
                if id not in reqs_no_source:
                    reqs_no_source.append(id)

                if not src_url:
                    # source_rse_id will be None if no source replicas
                    # rse will be None if rse is staging area
                    # staging_buffer will be None if rse has no key 'staging_buffer'
                    if source_rse_id is None or rse is None or staging_buffer is None:
                        continue

                    # Get destination rse information and protocol
                    if dest_rse_id not in rses_info:
                        dest_rse = rse_core.get_rse_name(rse_id=dest_rse_id, session=session)
                        rses_info[dest_rse_id] = rsemgr.get_rse_info(dest_rse, session=session)

                    if staging_buffer != rses_info[dest_rse_id]['rse']:
                        continue

                    attr = None
                    if attributes:
                        if type(attributes) is dict:
                            attr = json.loads(json.dumps(attributes))
                        else:
                            attr = json.loads(str(attributes))

                    source_replica_expression = attr["source_replica_expression"] if "source_replica_expression" in attr else None
                    if source_replica_expression:
                        try:
                            parsed_rses = parse_expression(source_replica_expression, session=session)
                        except InvalidRSEExpression, e:
                            logging.error("Invalid RSE exception %s: %s" % (source_replica_expression, e))
                            continue
                        else:
                            allowed_rses = [x['rse'] for x in parsed_rses]
                            if rse not in allowed_rses:
                                continue

                    if source_rse_id not in rses_info:
                        # source_rse = rse_core.get_rse_name(rse_id=source_rse_id, session=session)
                        source_rse = rse
                        rses_info[source_rse_id] = rsemgr.get_rse_info(source_rse, session=session)
                    if source_rse_id not in rse_attrs:
                        rse_attrs[source_rse_id] = get_rse_attributes(source_rse_id, session=session)

                    if source_rse_id not in protocols:
                        protocols[source_rse_id] = rsemgr.create_protocol(rses_info[source_rse_id], 'write', schemes)

                    # we need to set the spacetoken if we use SRM
                    dest_spacetoken = None
                    if protocols[source_rse_id].attributes and \
                       'extended_attributes' in protocols[source_rse_id].attributes and \
                       protocols[source_rse_id].attributes['extended_attributes'] and \
                       'space_token' in protocols[source_rse_id].attributes['extended_attributes']:
                        dest_spacetoken = protocols[source_rse_id].attributes['extended_attributes']['space_token']

                    source_url = protocols[source_rse_id].lfns2pfns(lfns={'scope': scope, 'name': name, 'path': path}).values()[0]
                else:
                    # source_rse_id will be None if no source replicas
                    # rse will be None if rse is staging area
                    # staging_buffer will be None if rse has no key 'staging_buffer'
                    if source_rse_id is None or rse is None or staging_buffer is None:
                        continue

                    # to get space token and fts attribute
                    if source_rse_id not in rses_info:
                        # source_rse = rse_core.get_rse_name(rse_id=source_rse_id, session=session)
                        source_rse = rse
                        rses_info[source_rse_id] = rsemgr.get_rse_info(source_rse, session=session)
                    if source_rse_id not in rse_attrs:
                        rse_attrs[source_rse_id] = get_rse_attributes(source_rse_id, session=session)

                    if source_rse_id not in protocols:
                        protocols[source_rse_id] = rsemgr.create_protocol(rses_info[source_rse_id], 'write', schemes)

                    # we need to set the spacetoken if we use SRM
                    dest_spacetoken = None
                    if protocols[source_rse_id].attributes and \
                       'extended_attributes' in protocols[source_rse_id].attributes and \
                       protocols[source_rse_id].attributes['extended_attributes'] and \
                       'space_token' in protocols[source_rse_id].attributes['extended_attributes']:
                        dest_spacetoken = protocols[source_rse_id].attributes['extended_attributes']['space_token']
                    source_url = src_url

                fts_hosts = rse_attrs[source_rse_id].get('fts', None)
                if not fts_hosts:
                    logging.error('Source RSE %s FTS attribute not defined - SKIP REQUEST %s' % (rse, id))
                    continue
                if not retry_count:
                    retry_count = 0
                fts_list = fts_hosts.split(",")
                external_host = fts_list[retry_count % len(fts_list)]

                if id in reqs_no_source:
                    reqs_no_source.remove(id)

                file_metadata = {'request_id': id,
                                 'scope': scope,
                                 'name': name,
                                 'activity': activity,
                                 'src_rse': rse,
                                 'dst_rse': rses_info[dest_rse_id]['rse'],
                                 'dest_rse_id': dest_rse_id,
                                 'filesize': bytes,
                                 'md5': md5,
                                 'adler32': adler32}
                if previous_attempt_id:
                    file_metadata['previous_attempt_id'] = previous_attempt_id

                transfers[id] = {'request_id': id,
                                 # 'src_urls': [source_url],
                                 'sources': [(rse, source_url, source_rse_id, ranking)],
                                 'dest_urls': [source_url],
                                 'src_spacetoken': None,
                                 'dest_spacetoken': dest_spacetoken,
                                 'overwrite': False,
                                 'bring_online': 172800,  # 48 hours
                                 'copy_pin_lifetime': attr.get('lifetime', -1),
                                 'external_host': external_host,
                                 'selection_strategy': 'auto',
                                 'rule_id': rule_id,
                                 'file_metadata': file_metadata}
                logging.debug("Transfer for request(%s): %s" % (id, transfers[id]))
        except:
            logging.error("Exception happened when trying to get transfer for request %s: %s" % (id, traceback.format_exc()))
            break

    return transfers, reqs_no_source


def get_stagein_transfers(process=None, total_processes=None, thread=None, total_threads=None,
                          activity=None, older_than=None, rses=None, mock=False, schemes=None, session=None):
    transfers, reqs_no_source = get_stagein_requests_and_source_replicas(process=process, total_processes=total_processes, thread=thread, total_threads=total_threads,
                                                                         activity=activity, older_than=older_than, rses=rses, mock=mock, schemes=schemes, session=session)
    request.set_requests_state(reqs_no_source, RequestState.LOST)
    return transfers


def handle_requests_with_scheme_mismatch(transfers=None, reqs_scheme_mismatch=None):
    if not reqs_scheme_mismatch:
        return transfers
    for request_id in reqs_scheme_mismatch:
        found_avail_source = 0
        if request_id in transfers:
            for source in transfers[request_id]['sources']:
                ranking = source[3]
                if ranking >= 0:
                    # if ranking less than 0, it means it already failed at least one time.
                    found_avail_source = 1
                    break
        if not found_avail_source:
            # todo
            # try to force scheme to regenerate the dest_url and src_url
            # transfer = get_transfer_from_request_id(request_id, scheme='srm') # if rsemgr can select protocol by order, we can change
            # if transfer:
            #     transfers[request_id] = transfer
            pass
    return transfers


def mock_sources(sources):
    tmp_sources = []
    for s in sources:
        tmp_sources.append((s[0], ':'.join(['mock']+s[1].split(':')[1:]), s[2], s[3]))
    sources = tmp_sources
    return tmp_sources


def get_transfer_transfers(process=None, total_processes=None, thread=None, total_threads=None,
                           activity=None, older_than=None, rses=None, schemes=None, mock=False, max_sources=4, session=None):
    transfers, reqs_no_source, reqs_scheme_mismatch = get_transfer_requests_and_source_replicas(process=process, total_processes=total_processes, thread=thread, total_threads=total_threads,
                                                                                                activity=activity, older_than=older_than, rses=rses, schemes=schemes, session=session)
    request.set_requests_state(reqs_no_source, RequestState.LOST)
    transfers = handle_requests_with_scheme_mismatch(transfers, reqs_scheme_mismatch)

    for request_id in transfers:
        sources = transfers[request_id]['sources']
        sources = sort_sources(sources, transfers[request_id]['file_metadata']['dst_rse'])
        if len(sources) > max_sources:
            sources = sources[:max_sources]
        if not mock:
            transfers[request_id]['sources'] = sources
        else:
            transfers[request_id]['sources'] = mock_sources(sources)
        logging.debug("Transfer for request(%s): %s" % (request_id, transfers[request_id]))
    return transfers


def submit_transfer(external_host, job, submitter='submitter', process=0, thread=0):
    eid = None
    try:
        ts = time.time()
        eid = request.submit_bulk_transfers(external_host, files=job['files'], transfertool='fts3', job_params=job['job_params'])
        logging.debug("%s:%s Submit job %s to %s" % (process, thread, eid, external_host))
        record_timer('daemons.conveyor.%s.submit_bulk_transfer.per_file' % submitter, (time.time() - ts) * 1000/len(job['files']))
        record_counter('daemons.conveyor.%s.submit_bulk_transfer' % submitter, len(job['files']))
        record_timer('daemons.conveyor.%s.submit_bulk_transfer.files' % submitter, len(job['files']))
    except Exception, ex:
        logging.error("Failed to submit a job with error %s: %s" % (str(ex), traceback.format_exc()))

    # register transfer returns
    try:
        xfers_ret = {}
        for file in job['files']:
            file_metadata = file['metadata']
            request_id = file_metadata['request_id']
            log_str = '%s:%s COPYING REQUEST %s DID %s:%s PREVIOUS %s FROM %s TO %s USING %s ' % (process, thread,
                                                                                                  file_metadata['request_id'],
                                                                                                  file_metadata['scope'],
                                                                                                  file_metadata['name'],
                                                                                                  file_metadata['previous_attempt_id'] if 'previous_attempt_id' in file_metadata else None,
                                                                                                  file['sources'],
                                                                                                  file['destinations'],
                                                                                                  external_host)
            if eid:
                xfers_ret[request_id] = {'state': RequestState.SUBMITTED, 'external_host': external_host, 'external_id': eid, 'dest_url':  file['destinations'][0]}
                log_str += 'with state(%s) with eid(%s)' % (RequestState.SUBMITTED, eid)
                logging.info("%s" % (log_str))
            else:
                xfers_ret[request_id] = {'state': RequestState.SUBMITTING, 'external_host': external_host, 'external_id': None, 'dest_url': file['destinations'][0]}
                log_str += 'with state(%s) with eid(%s)' % (RequestState.SUBMITTING, None)
                logging.warn("%s" % (log_str))
            xfers_ret[request_id]['file'] = file
        request.set_request_transfers(xfers_ret)
    except Exception, ex:
        logging.error("%s:%s Failed to register transfer state with error %s: %s" % (process, thread, str(ex), traceback.format_exc()))
