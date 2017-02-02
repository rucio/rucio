# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014-2016
# - Joaquin Bogado, <jbogadog@cern.ch>, 2016
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016

import datetime
import json
import logging
import time
import traceback

from ConfigParser import NoOptionError
from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from sqlalchemy import and_, or_, func
from sqlalchemy.orm import aliased
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import asc, bindparam, text, false, true

from rucio.common.config import config_get
from rucio.common.exception import RequestNotFound, RucioException, UnsupportedOperation
from rucio.common.utils import generate_uuid, chunks
from rucio.core import config as config_core, message as message_core
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import get_rse_id, get_rse_name, get_rse_transfer_limits
from rucio.db.sqla import models
from rucio.db.sqla.constants import RequestState, RequestType, FTSState, ReplicaState, LockState
from rucio.db.sqla.session import read_session, transactional_session
from rucio.transfertool import fts3


try:
    queue_mode = config_get('conveyor', 'queue_mode')
    if queue_mode.upper() == 'STRICT':
        queue_mode = 'strict'
    else:
        queue_mode = 'default'
except NoOptionError:
    queue_mode = 'default'


try:
    config_memcache = config_get('conveyor', 'using_memcache')
    if config_memcache.upper() == 'TRUE':
        using_memcache = True
    else:
        using_memcache = False
except NoOptionError:
    using_memcache = False


try:
    cache_time = int(config_get('conveyor', 'cache_time'))
except NoOptionError:
    cache_time = 600


REGION_SHORT = make_region().configure('dogpile.cache.memory',
                                       expiration_time=cache_time)


def get_transfer_limits_default(activity, rse_id):
    """
    Get RSE transfer limits in default mode.

    :param activity: The activity.
    :param rse_id: The RSE id.

    :returns: max_transfers if exists else None.
    """
    if using_memcache:
        key = 'rse_transfer_limits'
        result = REGION_SHORT.get(key)
        if type(result) is NoValue:
            try:
                logging.debug("Refresh rse transfer limits")
                result = get_rse_transfer_limits()
                REGION_SHORT.set(key, result)
            except:
                logging.warning("Failed to retrieve rse transfer limits: %s" % (traceback.format_exc()))
                result = None
        if result and activity in result and rse_id in result[activity]:
            return result[activity][rse_id]
        return None
    else:
        result = get_rse_transfer_limits(rse_id=rse_id, activity=activity)
        if result and activity in result and rse_id in result[activity]:
            return result[activity][rse_id]
        return None


def get_config_limits():
    """
    Get config limits.

    :returns: dictionary of limits.
    """

    config_limits = {}
    items = config_core.items('throttler')
    for opt, value in items:
        try:
            activity, rsename = opt.split(',')
            if rsename == 'all_rses':
                rse_id = 'all_rses'
            else:
                rse_id = get_rse_id(rsename)
            if activity not in config_limits:
                config_limits[activity] = {}
            config_limits[activity][rse_id] = int(value)
        except:
            logging.warning("Failed to parse throttler config %s:%s, error: %s" % (opt, value, traceback.format_exc()))
    return config_limits


def get_config_limit(activity, rse_id):
    """
    Get RSE transfer limits in strict mode.

    :param activity: The activity.
    :param rse_id: The RSE id.

    :returns: max_transfers if exists else None.
    """
    key = 'config_limits'
    result = REGION_SHORT.get(key)
    if type(result) is NoValue:
        try:
            logging.debug("Refresh rse config limits")
            result = get_config_limits()
            REGION_SHORT.set(key, result)
        except:
            logging.warning("Failed to retrieve rse transfer limits: %s" % (traceback.format_exc()))
            result = None

    threshold = None
    if result:
        if activity in result.keys():
            if rse_id in result[activity].keys():
                threshold = result[activity][rse_id]
            elif 'all_rses' in result[activity].keys():
                threshold = result[activity]['all_rses']
        if not threshold and 'all_activities' in result.keys():
            if rse_id in result['all_activities'].keys():
                threshold = result['all_activities'][rse_id]
            elif 'all_rses' in result['all_activities'].keys():
                threshold = result['all_activities']['all_rses']
    return threshold


def get_transfer_limits(activity, rse_id):
    """
    Get RSE transfer limits.

    :param activity: The activity.
    :param rse_id: The RSE id.

    :returns: max_transfers if exists else None.
    """
    try:
        if queue_mode == 'strict':
            threshold = get_config_limit(activity, rse_id)
            if threshold:
                return {'max_transfers': threshold, 'transfers': 0, 'waitings': 0}
            else:
                return None
        else:
            return get_transfer_limits_default(activity, rse_id)
    except:
        logging.warning("Failed to get transfer limits: %s" % traceback.format_exc())
        return None


def should_retry_request(req):
    """
    Whether should retry this request.

    :param request: Request as a dictionary.
    :returns: True if should retry it; False if no more retry.
    """
    if req['state'] == RequestState.SUBMITTING:
        return True
    if req['state'] == RequestState.NO_SOURCES or req['state'] == RequestState.ONLY_TAPE_SOURCES:
        return False
    # hardcoded for now - only requeue a couple of times
    if req['retry_count'] is None or req['retry_count'] < 3:
        return True
    return False


@transactional_session
def requeue_and_archive(request_id, session=None):
    """
    Requeue and archive a failed request.
    TODO: Multiple requeue.

    :param request_id: Original request ID as a string.
    :param session: Database session to use.
    """

    record_counter('core.request.requeue_request')
    new_req = get_request(request_id, session=session)

    if new_req:
        new_req['sources'] = get_sources(request_id, session=session)
        archive_request(request_id, session=session)

        if should_retry_request(new_req):
            new_req['request_id'] = generate_uuid()
            new_req['previous_attempt_id'] = request_id
            if new_req['retry_count'] is None:
                new_req['retry_count'] = 1
            elif new_req['state'] != RequestState.SUBMITTING:
                new_req['retry_count'] += 1

            if new_req['sources']:
                for i in range(len(new_req['sources'])):
                    if new_req['sources'][i]['is_using']:
                        if new_req['sources'][i]['ranking'] is None:
                            new_req['sources'][i]['ranking'] = -1
                        else:
                            new_req['sources'][i]['ranking'] -= 1
                        new_req['sources'][i]['is_using'] = False
            queue_requests([new_req], session=session)
            return new_req


@transactional_session
def queue_requests(requests, session=None):
    """
    Submit transfer requests on destination RSEs for data identifiers.

    :param requests: List of dictionaries containing request metadata.
    :param session: Database session to use.
    :returns: List of Request-IDs as 32 character hex strings.
    """
    record_counter('core.request.queue_requests')

    logging.debug("queue requests")

    request_clause = []
    transfer_limits, rses = {}, {}
    for req in requests:

        if isinstance(req['attributes'], (str, unicode)):
            req['attributes'] = json.loads(req['attributes'])
            if isinstance(req['attributes'], (str, unicode)):
                req['attributes'] = json.loads(req['attributes'])

        if req['request_type'] == RequestType.TRANSFER:
            request_clause.append(and_(models.Request.scope == req['scope'],
                                       models.Request.name == req['name'],
                                       models.Request.dest_rse_id == req['dest_rse_id'],
                                       models.Request.request_type == RequestType.TRANSFER))

        if req['dest_rse_id'] not in rses:
            rses[req['dest_rse_id']] = get_rse_name(req['dest_rse_id'], session=session)

        if req['attributes']['activity'] not in transfer_limits:
            transfer_limits[req['attributes']['activity']] = {req['dest_rse_id']: get_transfer_limits(req['attributes']['activity'], req['dest_rse_id'])}
        elif req['dest_rse_id'] not in transfer_limits[req['attributes']['activity']]:
            transfer_limits[req['attributes']['activity']] = {req['dest_rse_id']: get_transfer_limits(req['attributes']['activity'], req['dest_rse_id'])}

    # Check existing requests
    if request_clause:
        existing_requests = []
        for requests_condition in chunks(request_clause, 1000):
            query_existing_requests = session.query(models.Request.scope,
                                                    models.Request.name,
                                                    models.Request.dest_rse_id).\
                with_hint(models.Request,
                          "INDEX(REQUESTS REQUESTS_SC_NA_RS_TY_UQ_IDX)",
                          'oracle').\
                filter(or_(*requests_condition))
            for request in query_existing_requests:
                existing_requests.append(request)

    new_requests, sources, messages = [], [], []
    for request in requests:

        if req['request_type'] == RequestType.TRANSFER and (request['scope'], request['name'], request['dest_rse_id']) in existing_requests:
            logging.warn('Request TYPE %s for DID %s:%s at RSE %s exists - ignoring' % (request['request_type'],
                                                                                        request['scope'],
                                                                                        request['name'],
                                                                                        rses[request['dest_rse_id']]))
            continue

        transfer_limit = transfer_limits[request['attributes']['activity']].\
            get(request['dest_rse_id'])
        request['state'] = RequestState.WAITING if transfer_limit else RequestState.QUEUED

        if 'previous_attempt_id' in request and 'retry_count' in request:
            new_requests.append({'id': request['request_id'],
                                 'request_type': request['request_type'],
                                 'scope': request['scope'],
                                 'name': request['name'],
                                 'dest_rse_id': request['dest_rse_id'],
                                 'attributes': json.dumps(request['attributes']),
                                 'state': request['state'],
                                 'rule_id': request['rule_id'],
                                 'activity': request['attributes']['activity'],
                                 'bytes': request['attributes']['bytes'],
                                 'md5': request['attributes']['md5'],
                                 'adler32': request['attributes']['adler32'],
                                 'account': request.get('account', None),
                                 'priority': request['attributes'].get('priority', None),
                                 'requested_at': request.get('requested_at', None),
                                 'retry_count': request['retry_count'],
                                 'previous_attempt_id': request['previous_attempt_id']})
        else:
            request['request_id'] = generate_uuid()
            new_requests.append({'id': request['request_id'],
                                 'request_type': request['request_type'],
                                 'scope': request['scope'],
                                 'name': request['name'],
                                 'dest_rse_id': request['dest_rse_id'],
                                 'attributes': json.dumps(request['attributes']),
                                 'state': request['state'],
                                 'rule_id': request['rule_id'],
                                 'activity': request['attributes']['activity'],
                                 'bytes': request['attributes']['bytes'],
                                 'md5': request['attributes']['md5'],
                                 'adler32': request['attributes']['adler32'],
                                 'account': request.get('account', None),
                                 'priority': request['attributes'].get('priority', None),
                                 'requested_at': request.get('requested_at', None),
                                 'retry_count': request['retry_count']})

        if 'sources' in request and request['sources']:
            for source in request['sources']:
                sources.append({'request_id': request['request_id'],
                                'scope': request['scope'],
                                'name': request['name'],
                                'rse_id': source['rse_id'],
                                'dest_rse_id': request['dest_rse_id'],
                                'ranking': source['ranking'],
                                'bytes': source['bytes'],
                                'url': source['url'],
                                'is_using': source['is_using']})

        if request['request_type']:
            transfer_status = '%s-%s' % (request['request_type'], request['state'])
        else:
            transfer_status = 'transfer-%s' % request['state']

        payload = {'request-id': request['request_id'],
                   'request-type': str(request['request_type']).lower(),
                   'scope': request['scope'],
                   'name': request['name'],
                   'dst-rse-id': request['dest_rse_id'],
                   'dst-rse': rses[request['dest_rse_id']],
                   'state': str(request['state']),
                   'retry-count': request['retry_count'],
                   'rule-id': str(request['rule_id']),
                   'activity': request['attributes']['activity'],
                   'file-size': request['attributes']['bytes'],
                   'bytes': request['attributes']['bytes'],
                   'checksum-md5': request['attributes']['md5'],
                   'checksum-adler': request['attributes']['adler32'],
                   'queued_at': str(datetime.datetime.utcnow())}

        messages.append({'event_type': transfer_status.lower(),
                         'payload': json.dumps(payload)})

    for requests_chunk in chunks(new_requests, 1000):
        session.bulk_insert_mappings(models.Request, requests_chunk)

    for sources_chunk in chunks(sources, 1000):
        session.bulk_insert_mappings(models.Source, sources_chunk)

    for messages_chunk in chunks(messages, 1000):
        session.bulk_insert_mappings(models.Message, messages_chunk)


def submit_bulk_transfers(external_host, files, transfertool='fts3', job_params={}, timeout=None):
    """
    Submit transfer request to a transfertool.

    :param external_host: External host name as string
    :param files: List of Dictionary containing request file.
    :param transfertool: Transfertool as a string.
    :param job_params: Metadata key/value pairs for all files as a dictionary.
    :returns: Transfertool external ID.
    """

    record_counter('core.request.submit_transfer')

    transfer_id = None

    if transfertool == 'fts3':
        ts = time.time()
        job_files = []
        for file in files:
            job_file = {}
            for key in file:
                if key == 'sources':
                    # convert sources from (src_rse, url, src_rse_id, rank) to url
                    job_file[key] = []
                    for source in file[key]:
                        job_file[key].append(source[1])
                else:
                    job_file[key] = file[key]
            job_files.append(job_file)
        transfer_id = fts3.submit_bulk_transfers(external_host, job_files, job_params, timeout)
        record_timer('core.request.submit_transfers_fts3', (time.time() - ts) * 1000 / len(files))
    return transfer_id


@transactional_session
def set_request_transfers(transfers, session=None):
    """
    Update the transfer info of a request.

    :param transfers: Dictionary containing request transfer info.
    :param session: Database session to use.
    """

    try:
        for request_id in transfers:
            rowcount = session.query(models.Request).filter_by(id=request_id)\
                              .update({'state': transfers[request_id]['state'],
                                       'external_id': transfers[request_id]['external_id'],
                                       'external_host': transfers[request_id]['external_host'],
                                       'dest_url': transfers[request_id]['dest_url'],
                                       'submitted_at': datetime.datetime.utcnow()},
                                      synchronize_session=False)
            if rowcount and 'file' in transfers[request_id]:
                file = transfers[request_id]['file']
                used_src_rse_ids = get_source_rse_ids(request_id, session=session)
                for src_rse, src_url, src_rse_id, rank in file['sources']:
                    if src_rse_id not in used_src_rse_ids:
                        models.Source(request_id=file['metadata']['request_id'],
                                      scope=file['metadata']['scope'],
                                      name=file['metadata']['name'],
                                      rse_id=src_rse_id,
                                      dest_rse_id=file['metadata']['dest_rse_id'],
                                      ranking=rank if rank else 0,
                                      bytes=file['metadata']['filesize'],
                                      url=src_url).\
                            save(session=session, flush=False)

    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def prepare_request_transfers(transfers, session=None):
    """
    Prepare the transfer info for requests.

    :param transfers: Dictionary containing request transfer info.
    :param session: Database session to use.
    """

    try:
        for request_id in transfers:
            rowcount = session.query(models.Request)\
                              .filter_by(id=request_id)\
                              .filter(models.Request.state == RequestState.QUEUED)\
                              .update({'state': transfers[request_id]['state'],
                                       'external_id': transfers[request_id]['external_id'],
                                       'external_host': transfers[request_id]['external_host'],
                                       'dest_url': transfers[request_id]['dest_url'],
                                       'submitted_at': datetime.datetime.utcnow()},
                                      synchronize_session=False)
            if rowcount == 0:
                raise RucioException("Failed to prepare transfer: request %s does not exist or is not in queued state" % (request_id))

            if 'file' in transfers[request_id]:
                file = transfers[request_id]['file']
                for src_rse, src_url, src_rse_id, rank in file['sources']:
                    src_rowcount = session.query(models.Source)\
                                          .filter_by(request_id=request_id)\
                                          .filter(models.Source.rse_id == src_rse_id)\
                                          .update({'is_using': True}, synchronize_session=False)
                    if src_rowcount == 0:
                        models.Source(request_id=file['metadata']['request_id'],
                                      scope=file['metadata']['scope'],
                                      name=file['metadata']['name'],
                                      rse_id=src_rse_id,
                                      dest_rse_id=file['metadata']['dest_rse_id'],
                                      ranking=rank if rank else 0,
                                      bytes=file['metadata']['filesize'],
                                      url=src_url,
                                      is_using=True).\
                            save(session=session, flush=False)

    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def set_request_transfers_state(transfers, submitted_at, session=None):
    """
    Update the transfer info of a request.

    :param transfers: Dictionary containing request transfer info.
    :param session: Database session to use.
    """

    try:
        for request_id in transfers:
            rowcount = session.query(models.Request)\
                              .filter_by(id=request_id)\
                              .filter(models.Request.state == RequestState.SUBMITTING)\
                              .update({'state': transfers[request_id]['state'],
                                       'external_id': transfers[request_id]['external_id'],
                                       'external_host': transfers[request_id]['external_host'],
                                       'source_rse_id': transfers[request_id]['src_rse_id'],
                                       'submitted_at': submitted_at},
                                      synchronize_session=False)
            if rowcount == 0:
                raise RucioException("Failed to set requests %s tansfer %s: request doesn't exist or is not in SUBMITTING state" % (request_id, transfers[request_id]))

            request_type = transfers[request_id].get('request_type', None)
            msg = {'request-id': request_id,
                   'request-type': str(request_type).lower() if request_type else request_type,
                   'scope': transfers[request_id]['scope'],
                   'name': transfers[request_id]['name'],
                   'src-rse-id': transfers[request_id]['metadata'].get('src_rse_id', None),
                   'src-rse': transfers[request_id]['metadata'].get('src_rse', None),
                   'dst-rse-id': transfers[request_id]['metadata'].get('dst_rse_id', None),
                   'dst-rse': transfers[request_id]['metadata'].get('dst_rse', None),
                   'state': str(transfers[request_id]['state']),
                   'activity': transfers[request_id]['metadata'].get('activity', None),
                   'file-size': transfers[request_id]['metadata'].get('filesize', None),
                   'bytes': transfers[request_id]['metadata'].get('filesize', None),
                   'checksum-md5': transfers[request_id]['metadata'].get('md5', None),
                   'checksum-adler': transfers[request_id]['metadata'].get('adler32', None),
                   'external-id': transfers[request_id]['external_id'],
                   'external-host': transfers[request_id]['external_host'],
                   'queued_at': str(submitted_at)}

            if msg['request-type']:
                transfer_status = '%s-%s' % (msg['request-type'], msg['state'])
            else:
                transfer_status = 'transfer-%s' % msg['state']
            transfer_status = transfer_status.lower()
            message_core.add_message(transfer_status, msg, session=session)

    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def get_next(request_type, state, limit=100, older_than=None, rse=None, activity=None,
             process=None, total_processes=None, thread=None, total_threads=None,
             activity_shares=None, session=None):
    """
    Retrieve the next requests matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param request_type: Type of the request as a string or list of strings.
    :param state: State of the request as a string or list of strings.
    :param limit: Integer of requests to retrieve.
    :param older_than: Only select requests older than this DateTime.
    :param process: Identifier of the caller process as an integer.
    :param total_processes: Maximum number of processes as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param activity_shares: Activity shares dictionary, with number of requests
    :param session: Database session to use.
    :returns: Request as a dictionary.
    """

    record_counter('core.request.get_next.%s-%s' % (request_type, state))

    if total_processes > 1 and total_processes == total_threads:
        raise RucioException("Total process %s is the same with total threads %s, will create potential same hash" % (total_processes, total_threads))

    # lists of one element are not allowed by SQLA, so just duplicate the item
    if type(request_type) is not list:
        request_type = [request_type, request_type]
    elif len(request_type) == 1:
        request_type = [request_type[0], request_type[0]]
    if type(state) is not list:
        state = [state, state]
    elif len(state) == 1:
        state = [state[0], state[0]]

    result = []
    if not activity_shares:
        activity_shares = [None]

    for share in activity_shares:

        query = session.query(models.Request).with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
                                             .filter(models.Request.state.in_(state))\
                                             .filter(models.Request.request_type.in_(request_type))\
                                             .order_by(asc(models.Request.updated_at))

        if isinstance(older_than, datetime.datetime):
            query = query.filter(models.Request.updated_at < older_than)

        if rse:
            query = query.filter(models.Request.dest_rse_id == rse)

        if share:
            query = query.filter(models.Request.activity == share)
        elif activity:
            query = query.filter(models.Request.activity == activity)

        if (total_processes - 1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('process_number', process), bindparam('total_processes', total_processes - 1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_processes) = :process_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter('mod(md5(rule_id), %s) = %s' % (total_processes - 1, process))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_processes - 1, process))

        if (total_threads - 1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads - 1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter('mod(md5(rule_id), %s) = %s' % (total_threads - 1, thread))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_threads - 1, thread))

        if share:
            query = query.limit(activity_shares[share])
        else:
            query = query.limit(limit)

        tmp = query.all()
        if tmp:
            for t in tmp:
                t2 = dict(t)
                t2.pop('_sa_instance_state')
                t2['request_id'] = t2['id']
                t2['attributes'] = json.loads(str(t2['attributes']))
                result.append(t2)
    return result


@read_session
def get_next_transfers(request_type, state, limit=100, older_than=None, rse=None, activity=None,
                       process=None, total_processes=None, thread=None, total_threads=None,
                       activity_shares=None, session=None):
    """
    Retrieve the next requests matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param request_type: Type of the request as a string or list of strings.
    :param state: State of the request as a string or list of strings.
    :param limit: Integer of requests to retrieve.
    :param older_than: Only select requests older than this DateTime.
    :param process: Identifier of the caller process as an integer.
    :param total_processes: Maximum number of processes as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param activity_shares: Activity shares dictionary, with number of requests
    :param session: Database session to use.
    :returns: List of a {external_host, external_id} dictionary.
    """

    record_counter('core.request.get_next_transfers.%s-%s' % (request_type, state))

    if total_processes > 1 and total_processes == total_threads:
        raise RucioException("Total process %s is the same with total threads %s, will create potential same hash" % (total_processes, total_threads))

    # lists of one element are not allowed by SQLA, so just duplicate the item
    if type(request_type) is not list:
        request_type = [request_type, request_type]
    elif len(request_type) == 1:
        request_type = [request_type[0], request_type[0]]
    if type(state) is not list:
        state = [state, state]
    elif len(state) == 1:
        state = [state[0], state[0]]

    result = []
    if not activity_shares:
        activity_shares = [None]

    for share in activity_shares:

        query = session.query(models.Request.external_host, models.Request.external_id).with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
                                                                                       .distinct()\
                                                                                       .filter(models.Request.state.in_(state))\
                                                                                       .filter(models.Request.request_type.in_(request_type))\
                                                                                       .order_by(asc(models.Request.updated_at))

        if isinstance(older_than, datetime.datetime):
            query = query.filter(models.Request.updated_at < older_than)

        if rse:
            query = query.filter(models.Request.dest_rse_id == rse)

        if share:
            query = query.filter(models.Request.activity == share)
        elif activity:
            query = query.filter(models.Request.activity == activity)

        if (total_processes - 1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('process_number', process), bindparam('total_processes', total_processes - 1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_processes) = :process_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter('mod(md5(rule_id), %s) = %s' % (total_processes - 1, process))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_processes - 1, process))

        if (total_threads - 1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads - 1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter('mod(md5(rule_id), %s) = %s' % (total_threads - 1, thread))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_threads - 1, thread))

        if share:
            query = query.limit(activity_shares[share])
        else:
            query = query.limit(limit)

        tmp = query.all()
        if tmp:
            for t in tmp:
                t2 = {'external_host': t[0], 'external_id': t[1]}
                result.append(t2)
    return result


@read_session
def query_request(request_id, transfertool='fts3', session=None):
    """
    Query the status of a request.

    :param request_id: Request-ID as a 32 character hex string.
    :param transfertool: Transfertool name as a string.
    :param session: Database session to use.
    :returns: Request status information as a dictionary.
    """

    record_counter('core.request.query_request')

    req = get_request(request_id, session=session)

    req_status = {'request_id': request_id,
                  'new_state': None}

    if not req:
        req_status['new_state'] = RequestState.LOST
        return req_status

    if transfertool == 'fts3':
        try:
            ts = time.time()
            response = fts3.query(req['external_id'], req['external_host'])
            record_timer('core.request.query_request_fts3', (time.time() - ts) * 1000)
            req_status['details'] = response
        except Exception:
            raise

        if response is None:
            req_status['new_state'] = RequestState.LOST
        else:
            if 'job_state' not in response:
                req_status['new_state'] = RequestState.LOST
            elif response['job_state'] in (str(FTSState.FAILED),
                                           str(FTSState.FINISHEDDIRTY),
                                           str(FTSState.CANCELED)):
                req_status['new_state'] = RequestState.FAILED
            elif response['job_state'] == str(FTSState.FINISHED):
                req_status['new_state'] = RequestState.DONE
    else:
        raise NotImplementedError

    return req_status


def query_latest(external_host, state, last_nhours=1):
    """
    Query the latest requests in last n hours with state.

    :param external_host: FTS host name as a string.
    :param state: FTS job state as a string or a dictionary.
    :param last_nhours: Latest n hours as an integer.
    :returns: Requests status information as a dictionary.
    """

    record_counter('core.request.query_latest')

    ts = time.time()
    resps = fts3.query_latest(external_host, state, last_nhours)
    record_timer('core.request.query_latest_fts3.%s.%s_hours' % (external_host, last_nhours), (time.time() - ts) * 1000)

    if not resps:
        return

    ret_resps = []
    for resp in resps:
        if 'job_metadata' not in resp or resp['job_metadata'] is None or 'issuer' not in resp['job_metadata'] or resp['job_metadata']['issuer'] != 'rucio':
            continue

        if 'request_id' not in resp['job_metadata']:
            # submitted by new submitter
            try:
                logging.debug("Transfer %s on %s is %s, decrease its updated_at." % (resp['job_id'], external_host, resp['job_state']))
                set_transfer_update_time(external_host, resp['job_id'], datetime.datetime.utcnow() - datetime.timedelta(hours=24))
            except Exception, e:
                logging.debug("Exception happened when updating transfer updatetime: %s" % str(e).replace('\n', ''))

    return ret_resps


def bulk_query_requests(request_host, request_ids, transfertool='fts3'):
    """
    Query the status of a request.

    :param request_host: Name of the external host.
    :param request_ids: List of (Request-ID as a 32 character hex string, External-ID as a 32 character hex string)
    :param transfertool: Transfertool name as a string.
    :param session: Database session to use.
    :returns: Request status information as a dictionary.
    """

    record_counter('core.request.query_request')

    transfer_ids = []
    for request_id, external_id in request_ids:
        if external_id not in transfer_ids:
            transfer_ids.append(external_id)

    if transfertool == 'fts3':
        try:
            ts = time.time()
            fts_resps = fts3.bulk_query(transfer_ids, request_host)
            record_timer('core.request.query_bulk_request_fts3', (time.time() - ts) * 1000 / len(transfer_ids))
        except Exception:
            raise

        responses = {}
        for request_id, external_id in request_ids:
            fts_resp = fts_resps[external_id]
            if fts_resp is None:
                req_status = {}
                req_status['new_state'] = RequestState.LOST
                req_status['request_id'] = request_id
            elif isinstance(fts_resp, Exception):
                req_status = fts_resp
            else:
                req_status = fts_resp
                # needed for unfinished jobs
                req_status['request_id'] = request_id

                if req_status['job_state'] in (str(FTSState.FAILED),
                                               str(FTSState.FINISHEDDIRTY),
                                               str(FTSState.CANCELED)):
                    req_status['new_state'] = RequestState.FAILED
                elif req_status['job_state'] == str(FTSState.FINISHED):
                    req_status['new_state'] = RequestState.DONE

            responses[request_id] = req_status
        return responses
    else:
        raise NotImplementedError

    return None


def bulk_query_transfers(request_host, transfer_ids, transfertool='fts3', timeout=None):
    """
    Query the status of a request.

    :param request_host: Name of the external host.
    :param transfer_ids: List of (External-ID as a 32 character hex string)
    :param transfertool: Transfertool name as a string.
    :returns: Request status information as a dictionary.
    """

    record_counter('core.request.bulk_query_transfers')

    if transfertool == 'fts3':
        try:
            ts = time.time()
            fts_resps = fts3.bulk_query(transfer_ids, request_host, timeout)
            record_timer('core.request.bulk_query_transfers', (time.time() - ts) * 1000 / len(transfer_ids))
        except Exception:
            raise

        for transfer_id in transfer_ids:
            if transfer_id not in fts_resps:
                fts_resps[transfer_id] = Exception("Transfer id %s is not returned" % transfer_id)
            if fts_resps[transfer_id] and not isinstance(fts_resps[transfer_id], Exception):
                for request_id in fts_resps[transfer_id]:
                    if fts_resps[transfer_id][request_id]['file_state'] in (str(FTSState.FAILED),
                                                                            str(FTSState.FINISHEDDIRTY),
                                                                            str(FTSState.CANCELED)):
                        fts_resps[transfer_id][request_id]['new_state'] = RequestState.FAILED
                    elif fts_resps[transfer_id][request_id]['file_state'] in str(FTSState.FINISHED):
                        fts_resps[transfer_id][request_id]['new_state'] = RequestState.DONE
        return fts_resps
    else:
        raise NotImplementedError

    return None


@read_session
def query_request_details(request_id, transfertool='fts3', session=None):
    """
    Query the detailed status of a request. Can also be done after the
    external transfer has finished.

    :param request_id: Request-ID as a 32 character hex string.
    :param transfertool: Transfertool name as a string.
    :param session: Database session to use.
    :returns: Detailed request status information as a dictionary.
    """

    record_counter('core.request.query_request_details')

    req = get_request(request_id, session=session)

    if not req:
        return

    if transfertool == 'fts3':
        ts = time.time()
        tmp = fts3.query_details(req['external_id'], req['external_host'])
        record_timer('core.request.query_details_fts3', (time.time() - ts) * 1000)
        return tmp

    raise NotImplementedError


@transactional_session
def set_requests_external(transfer_ids, submitted_at, session=None):
    """
    Update all requests with the according external id from the transfertool.

    :param transfer_ids: Transfer data as returned by transfertool.
    :param session: Database session to use.
    """

    for transfer_id in transfer_ids:
        session.query(models.Request)\
               .filter_by(id=transfer_id)\
               .update({'state': RequestState.SUBMITTED,
                        'external_id': transfer_ids[transfer_id]['external_id'],
                        'external_host': transfer_ids[transfer_id]['external_host'],
                        'dest_url': transfer_ids[transfer_id]['dest_urls'][0],
                        'submitted_at': submitted_at},
                       synchronize_session=False)


@transactional_session
def set_request_state(request_id, new_state, transfer_id=None, transferred_at=None, started_at=None, src_rse_id=None, err_msg=None, session=None):
    """
    Update the state of a request. Fails silently if the request_id does not exist.

    :param request_id: Request-ID as a 32 character hex string.
    :param new_state: New state as string.
    :param transfer_id: external transfer job id as a string.
    :param session: Database session to use.
    """

    record_counter('core.request.set_request_state')

    try:
        update_items = {'state': new_state, 'updated_at': datetime.datetime.utcnow()}
        if transferred_at:
            update_items['transferred_at'] = transferred_at
        if started_at:
            update_items['started_at'] = started_at
        if src_rse_id:
            update_items['source_rse_id'] = src_rse_id
        if err_msg:
            update_items['err_msg'] = err_msg

        if transfer_id:
            rowcount = session.query(models.Request).filter_by(id=request_id, external_id=transfer_id).update(update_items, synchronize_session=False)
        else:
            if new_state in [RequestState.FAILED, RequestState.DONE]:
                logging.error("Request %s should not be updated to 'Failed' or 'Done' without external transfer_id" % request_id)
            else:
                rowcount = session.query(models.Request).filter_by(id=request_id).update(update_items, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)

    if not rowcount:
        raise UnsupportedOperation("Request %s state cannot be updated." % request_id)


@transactional_session
def set_requests_state(request_ids, new_state, session=None):
    """
    Bulk update the state of requests. Fails silently if the request_id does not exist.

    :param request_ids: List of (Request-ID as a 32 character hex string).
    :param new_state: New state as string.
    :param session: Database session to use.
    """

    record_counter('core.request.set_requests_state')

    try:
        for request_id in request_ids:
            set_request_state(request_id, new_state, session=session)
    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def set_transfer_update_time(external_host, transfer_id, update_time=datetime.datetime.utcnow(), session=None):
    """
    Update the state of a request. Fails silently if the transfer_id does not exist.

    :param external_host: Selected external host as string in format protocol://fqdn:port
    :param transfer_id: external transfer job id as a string.
    :param update_time: time stamp.
    :param session: Database session to use.
    """

    record_counter('core.request.set_transfer_update_time')

    try:
        rowcount = session.query(models.Request).filter_by(external_id=transfer_id, state=RequestState.SUBMITTED).update({'updated_at': update_time}, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)

    if not rowcount:
        raise UnsupportedOperation("Transfer %s doesn't exist or its status is not submitted." % (transfer_id))


@transactional_session
def touch_requests_by_rule(rule_id, session=None):
    """
    Update the update time of requests in a rule. Fails silently if no requests on this rule.

    :param rule_id: Rule-ID as a 32 character hex string.
    :param session: Database session to use.
    """

    record_counter('core.request.touch_requests_by_rule')

    try:
        session.query(models.Request).with_hint(models.Request, "INDEX(REQUESTS REQUESTS_RULEID_IDX)", 'oracle')\
                                     .filter_by(rule_id=rule_id)\
                                     .filter(models.Request.state.in_([RequestState.FAILED, RequestState.DONE, RequestState.LOST, RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES]))\
                                     .filter(models.Request.updated_at < datetime.datetime.utcnow())\
                                     .update({'updated_at': datetime.datetime.utcnow() + datetime.timedelta(minutes=20)}, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def set_transfer_state(external_host, transfer_id, new_state, session=None):
    """
    Update the state of a request. Fails silently if the transfer_id does not exist.

    :param external_host: Selected external host as string in format protocol://fqdn:port
    :param transfer_id: external transfer job id as a string.
    :param new_state: New state as string.
    :param session: Database session to use.
    """

    record_counter('core.request.set_transfer_state')

    try:
        rowcount = session.query(models.Request).filter_by(external_id=transfer_id).update({'state': new_state, 'updated_at': datetime.datetime.utcnow()}, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)

    if not rowcount:
        raise UnsupportedOperation("Transfer %s on %s state %s cannot be updated." % (transfer_id, external_host, new_state))


@transactional_session
def set_external_host(request_id, external_host, session=None):
    """
    Update the state of a request. Fails silently if the request_id does not exist.

    :param request_id: Request-ID as a 32 character hex string.
    :param external_host: Selected external host as string in format protocol://fqdn:port
    :param session: Database session to use.
    """

    record_counter('core.request.set_external_host')

    try:
        session.query(models.Request).filter_by(id=request_id).update({'external_host': external_host}, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def touch_request(request_id, session=None):
    """
    Update the timestamp of a request. Fails silently if the request_id does not exist.

    :param request_id: Request-ID as a 32 character hex string.
    :param session: Database session to use.
    """

    record_counter('core.request.touch_request')

    try:
        rowcount = session.query(models.Request).filter_by(id=request_id).update({'updated_at': datetime.datetime.utcnow()}, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)
    if not rowcount:
        raise UnsupportedOperation("Request %s cannot be touched." % request_id)


@transactional_session
def touch_transfer(external_host, transfer_id, session=None):
    """
    Update the timestamp of requests in a transfer. Fails silently if the transfer_id does not exist.

    :param request_host: Name of the external host.
    :param transfer_id: external transfer job id as a string.
    :param session: Database session to use.
    """

    record_counter('core.request.touch_transfer')

    try:
        # don't touch it if it's already touched in 30 seconds
        session.query(models.Request).with_hint(models.Request, "INDEX(REQUESTS REQUESTS_EXTERNALID_UQ)", 'oracle')\
                                     .filter_by(external_id=transfer_id)\
                                     .filter(models.Request.state == RequestState.SUBMITTED)\
                                     .filter(models.Request.updated_at < datetime.datetime.utcnow() - datetime.timedelta(seconds=30))\
                                     .update({'updated_at': datetime.datetime.utcnow()}, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def get_request(request_id, session=None):
    """
    Retrieve a request by its ID.

    :param request_id: Request-ID as a 32 character hex string.
    :param session: Database session to use.
    :returns: Request as a dictionary.
    """

    try:
        tmp = session.query(models.Request).filter_by(id=request_id).first()

        if not tmp:
            return
        else:
            tmp = dict(tmp)
            tmp.pop('_sa_instance_state')
            return tmp
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def get_requests_by_transfer(external_host, transfer_id, session=None):
    """
    Retrieve requests by its transfer ID.

    :param request_host: Name of the external host.
    :param transfer_id: external transfer job id as a string.
    :param session: Database session to use.
    :returns: List of Requests.
    """

    try:
        tmp = session.query(models.Request).filter_by(external_id=transfer_id).all()

        if tmp:
            result = []
            for t in tmp:
                t2 = dict(t)
                t2.pop('_sa_instance_state')
                t2['request_id'] = t2['id']
                t2['attributes'] = json.loads(str(t2['attributes']))
                result.append(t2)
            return result
        return
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def get_request_by_did(scope, name, rse, rse_id=None, request_type=None, session=None):
    """
    Retrieve a request by its DID for a destination RSE.

    :param scope: The scope of the data identifier.
    :param name: The name of the data identifier.
    :param rse: The destination RSE of the request.
    :param rse_id: The destination RSE ID of the request. Overrides rse param!
    :param request_type: The type of request as rucio.db.sqla.constants.RequestType.
    :param session: Database session to use.
    :returns: Request as a dictionary.
    """

    record_counter('core.request.get_request_by_did')
    try:
        tmp = session.query(models.Request).filter_by(scope=scope,
                                                      name=name)

        if rse_id:
            tmp = tmp.filter_by(dest_rse_id=rse_id)
        else:
            tmp = tmp.filter_by(dest_rse_id=get_rse_id(rse))

        if request_type:
            tmp = tmp.filter_by(request_type=request_type)

        tmp = tmp.first()
        if not tmp:
            raise RequestNotFound()
        else:
            tmp = dict(tmp)
            tmp.pop('_sa_instance_state')
            return tmp
    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def archive_request(request_id, session=None):
    """
    Move a request to the history table.

    :param request_id: Request-ID as a 32 character hex string.
    :param session: Database session to use.
    """

    record_counter('core.request.archive')
    req = get_request(request_id=request_id, session=session)

    if req:
        hist_request = models.Request.__history_mapper__.class_(id=req['id'],
                                                                created_at=req['created_at'],
                                                                request_type=req['request_type'],
                                                                scope=req['scope'],
                                                                name=req['name'],
                                                                dest_rse_id=req['dest_rse_id'],
                                                                source_rse_id=req['source_rse_id'],
                                                                attributes=req['attributes'],
                                                                state=req['state'],
                                                                account=req['account'],
                                                                external_id=req['external_id'],
                                                                retry_count=req['retry_count'],
                                                                err_msg=req['err_msg'],
                                                                previous_attempt_id=req['previous_attempt_id'],
                                                                external_host=req['external_host'],
                                                                rule_id=req['rule_id'],
                                                                activity=req['activity'],
                                                                bytes=req['bytes'],
                                                                md5=req['md5'],
                                                                adler32=req['adler32'],
                                                                dest_url=req['dest_url'],
                                                                submitted_at=req['submitted_at'],
                                                                started_at=req['started_at'],
                                                                transferred_at=req['transferred_at'])
        hist_request.save(session=session)
        try:
            time_diff = req['updated_at'] - req['created_at']
            time_diff_s = time_diff.seconds + time_diff.days * 24 * 3600
            record_timer('core.request.archive_request.%s' % req['activity'].replace(' ', '_'), time_diff_s)
            session.query(models.Source).filter_by(request_id=request_id).delete()
            session.query(models.Request).filter_by(id=request_id).delete()
        except IntegrityError, e:
            raise RucioException(e.args)


@transactional_session
def cancel_request_did(scope, name, dest_rse_id, request_type=RequestType.TRANSFER, session=None):
    """
    Cancel a request based on a DID and request type.

    :param scope: Data identifier scope as a string.
    :param name: Data identifier name as a string.
    :param dest_rse_id: RSE id as a string.
    :param request_type: Type of the request.
    :param session: Database session to use.
    """

    record_counter('core.request.cancel_request_did')

    reqs = None
    try:
        reqs = session.query(models.Request.id,
                             models.Request.external_id,
                             models.Request.external_host).filter_by(scope=scope,
                                                                     name=name,
                                                                     dest_rse_id=dest_rse_id,
                                                                     request_type=request_type).all()
        if not reqs:
            logging.warn('Tried to cancel non-existant request for DID %s:%s at RSE ID %s' % (scope, name, dest_rse_id))
    except IntegrityError, e:
        raise RucioException(e.args)

    for req in reqs:
        # is there a transfer already in FTS3? if so, try to cancel it
        if req[1] is not None:
            try:
                fts3.cancel(req[1], req[2])
            except Exception, e:
                logging.warn('Could not cancel FTS3 transfer %s on %s: %s' % (req[1], req[2], str(e)))
        archive_request(request_id=req[0], session=session)


def cancel_request_external_id(transfer_id, transfer_host):
    """
    Cancel a request based on external transfer id.

    :param transfer_id: External-ID as a 32 character hex string.
    :param transfer_host: Name of the external host.
    """

    record_counter('core.request.cancel_request_external_id')
    try:
        fts3.cancel(transfer_id, transfer_host)
    except:
        raise RucioException('Could not cancel FTS3 transfer %s on %s: %s' % (transfer_id, transfer_host, traceback.format_exc()))


@read_session
def list_transfer_requests_and_source_replicas(process=None, total_processes=None, thread=None, total_threads=None,
                                               limit=None, activity=None, older_than=None, rses=None, session=None):
    """
    List requests with source replicas

    :param process: Identifier of the caller process as an integer.
    :param total_processes: Maximum number of processes as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param limit: Integer of requests to retrieve.
    :param activity: Activity to be selected.
    :param older_than: Only select requests older than this DateTime.
    :param rses: List of rse_id to select requests.
    :param session: Database session to use.
    :returns: List.
    """
    if total_processes > 1 and total_processes == total_threads:
        raise RucioException("Total process %s is the same with total threads %s, will create potential same hash" % (total_processes, total_threads))

    sub_requests = session.query(models.Request.id,
                                 models.Request.rule_id,
                                 models.Request.scope,
                                 models.Request.name,
                                 models.Request.md5,
                                 models.Request.adler32,
                                 models.Request.bytes,
                                 models.Request.activity,
                                 models.Request.attributes,
                                 models.Request.previous_attempt_id,
                                 models.Request.dest_rse_id,
                                 models.Request.retry_count)\
        .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
        .filter(models.Request.state == RequestState.QUEUED)\
        .filter(models.Request.request_type == RequestType.TRANSFER)

    if isinstance(older_than, datetime.datetime):
        sub_requests = sub_requests.filter(models.Request.requested_at < older_than)

    if activity:
        sub_requests = sub_requests.filter(models.Request.activity == activity)

    if (total_processes - 1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('process_number', process), bindparam('total_processes', total_processes - 1)]
            sub_requests = sub_requests.filter(text('ORA_HASH(rule_id, :total_processes) = :process_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            sub_requests = sub_requests.filter('mod(md5(rule_id), %s) = %s' % (total_processes - 1, process))
        elif session.bind.dialect.name == 'postgresql':
            sub_requests = sub_requests.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_processes - 1, process))

    if (total_threads - 1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads - 1)]
            sub_requests = sub_requests.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            sub_requests = sub_requests.filter('mod(md5(rule_id), %s) = %s' % (total_threads - 1, thread))
        elif session.bind.dialect.name == 'postgresql':
            sub_requests = sub_requests.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_threads - 1, thread))

    if limit:
        sub_requests = sub_requests.limit(limit)

    sub_requests = sub_requests.subquery()

    query = session.query(sub_requests.c.id,
                          sub_requests.c.rule_id,
                          sub_requests.c.scope,
                          sub_requests.c.name,
                          sub_requests.c.md5,
                          sub_requests.c.adler32,
                          sub_requests.c.bytes,
                          sub_requests.c.activity,
                          sub_requests.c.attributes,
                          sub_requests.c.previous_attempt_id,
                          sub_requests.c.dest_rse_id,
                          models.RSEFileAssociation.rse_id,
                          models.RSE.rse,
                          models.RSE.deterministic,
                          models.RSE.rse_type,
                          models.RSEFileAssociation.path,
                          sub_requests.c.retry_count,
                          models.Source.url,
                          models.Source.ranking,
                          models.Distance.ranking)\
        .outerjoin(models.RSEFileAssociation, and_(sub_requests.c.scope == models.RSEFileAssociation.scope,
                                                   sub_requests.c.name == models.RSEFileAssociation.name,
                                                   models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                                                   sub_requests.c.dest_rse_id != models.RSEFileAssociation.rse_id))\
        .with_hint(models.RSEFileAssociation, "+ index(replicas REPLICAS_PK)", 'oracle')\
        .outerjoin(models.RSE, and_(models.RSE.id == models.RSEFileAssociation.rse_id,
                                    models.RSE.staging_area == false(),
                                    models.RSE.deleted == false()))\
        .outerjoin(models.Source, and_(sub_requests.c.id == models.Source.request_id,
                                       models.RSE.id == models.Source.rse_id))\
        .with_hint(models.Source, "+ index(sources SOURCES_PK)", 'oracle')\
        .outerjoin(models.Distance, and_(sub_requests.c.dest_rse_id == models.Distance.dest_rse_id,
                                         models.RSEFileAssociation.rse_id == models.Distance.src_rse_id))\
        .with_hint(models.Distance, "+ index(distances DISTANCES_PK)", 'oracle')

    if rses:
        result = []
        for item in query.all():
            dest_rse_id = item[9]
            if dest_rse_id in rses:
                result.append(item)
        return result
    else:
        return query.all()


@read_session
def list_stagein_requests_and_source_replicas(process=None, total_processes=None, thread=None, total_threads=None,
                                              limit=None, activity=None, older_than=None, rses=None, session=None):
    """
    List stagein requests with source replicas

    :param process: Identifier of the caller process as an integer.
    :param total_processes: Maximum number of processes as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param limit: Integer of requests to retrieve.
    :param activity: Activity to be selected.
    :param older_than: Only select requests older than this DateTime.
    :param rses: List of rse_id to select requests.
    :param session: Database session to use.
    :returns: List.
    """
    sub_requests = session.query(models.Request.id,
                                 models.Request.rule_id,
                                 models.Request.scope,
                                 models.Request.name,
                                 models.Request.md5,
                                 models.Request.adler32,
                                 models.Request.bytes,
                                 models.Request.activity,
                                 models.Request.attributes,
                                 models.Request.previous_attempt_id,
                                 models.Request.dest_rse_id,
                                 models.Request.retry_count)\
        .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
        .filter(models.Request.state == RequestState.QUEUED)\
        .filter(models.Request.request_type == RequestType.STAGEIN)

    if isinstance(older_than, datetime.datetime):
        sub_requests = sub_requests.filter(models.Request.requested_at < older_than)

    if activity:
        sub_requests = sub_requests.filter(models.Request.activity == activity)

    if (total_processes - 1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('process_number', process), bindparam('total_processes', total_processes - 1)]
            sub_requests = sub_requests.filter(text('ORA_HASH(rule_id, :total_processes) = :process_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            sub_requests = sub_requests.filter('mod(md5(rule_id), %s) = %s' % (total_processes - 1, process))
        elif session.bind.dialect.name == 'postgresql':
            sub_requests = sub_requests.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_processes - 1, process))

    if (total_threads - 1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads - 1)]
            sub_requests = sub_requests.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            sub_requests = sub_requests.filter('mod(md5(rule_id), %s) = %s' % (total_threads - 1, thread))
        elif session.bind.dialect.name == 'postgresql':
            sub_requests = sub_requests.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_threads - 1, thread))

    if limit:
        sub_requests = sub_requests.limit(limit)

    sub_requests = sub_requests.subquery()

    query = session.query(sub_requests.c.id,
                          sub_requests.c.rule_id,
                          sub_requests.c.scope,
                          sub_requests.c.name,
                          sub_requests.c.md5,
                          sub_requests.c.adler32,
                          sub_requests.c.bytes,
                          sub_requests.c.activity,
                          sub_requests.c.attributes,
                          sub_requests.c.dest_rse_id,
                          models.RSEFileAssociation.rse_id,
                          models.RSE.rse,
                          models.RSE.deterministic,
                          models.RSE.rse_type,
                          models.RSEFileAssociation.path,
                          models.RSEAttrAssociation.value,
                          sub_requests.c.retry_count,
                          sub_requests.c.previous_attempt_id,
                          models.Source.url,
                          models.Source.ranking)\
        .outerjoin(models.RSEFileAssociation, and_(sub_requests.c.scope == models.RSEFileAssociation.scope,
                                                   sub_requests.c.name == models.RSEFileAssociation.name,
                                                   models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                                                   sub_requests.c.dest_rse_id != models.RSEFileAssociation.rse_id))\
        .with_hint(models.RSEFileAssociation, "+ index(replicas REPLICAS_PK)", 'oracle')\
        .outerjoin(models.RSE, and_(models.RSE.id == models.RSEFileAssociation.rse_id,
                                    models.RSE.staging_area == false(),
                                    models.RSE.deleted == false()))\
        .outerjoin(models.RSEAttrAssociation, and_(models.RSEAttrAssociation.rse_id == models.RSE.id,
                                                   models.RSEAttrAssociation.key == 'staging_buffer'))\
        .outerjoin(models.Source, and_(sub_requests.c.id == models.Source.request_id,
                                       models.RSE.id == models.Source.rse_id))\
        .with_hint(models.Source, "+ index(sources SOURCES_PK)", 'oracle')

    if rses:
        result = []
        for item in query.all():
            dest_rse_id = item[9]
            if dest_rse_id in rses:
                result.append(item)
        return result
    else:
        return query.all()


@read_session
def get_sources(request_id, rse_id=None, session=None):
    """
    Retrieve sources by its ID.

    :param request_id: Request-ID as a 32 character hex string.
    :param rse_id: RSE ID as a 32 character hex string.
    :param session: Database session to use.
    :returns: Sources as a dictionary.
    """

    try:
        if rse_id:
            tmp = session.query(models.Source).filter_by(request_id=request_id, rse_id=rse_id).all()
        else:
            tmp = session.query(models.Source).filter_by(request_id=request_id).all()

        if not tmp:
            return
        else:
            result = []
            for t in tmp:
                t2 = dict(t)
                t2.pop('_sa_instance_state')
                result.append(t2)

            return result
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def get_source_rse_ids(request_id, session=None):
    """
    Retrieve source RSE ids by its ID.

    :param request_id: Request-ID as a 32 character hex string.
    :param session: Database session to use.
    :returns: Source RSE ids as a list.
    """

    try:
        tmp = session.query(models.Source.rse_id).filter_by(request_id=request_id).all()
        result = [t[0] for t in tmp]
        return result
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def get_heavy_load_rses(threshold, session=None):
    """
    Retrieve heavy load rses.

    :param threshold: threshold as an int.
    :param session: Database session to use.
    :returns: .
    """
    try:
        results = session.query(models.Source.rse_id, func.count(models.Source.rse_id).label('load'))\
                         .filter(models.Source.is_using == true())\
                         .group_by(models.Source.rse_id)\
                         .all()

        if not results:
            return

        result = []
        for t in results:
            if t[1] >= threshold:
                t2 = {'rse_id': t[0], 'load': t[1]}
                result.append(t2)

        return result
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def stats(session=None):
    """
    Retrieve statistics about src-destination traffic

    :returns: A list of dictionaries.
        [{'files': .., 'source': .., 'destination': .., 'bytes': ...},]
    """
    source, destination = aliased(models.RSE), aliased(models.RSE)
    query = session.query(source.rse.label('source'),
                          destination.rse.label('destination'),
                          func.count(1).label('files'),
                          func.sum(models.Source.bytes).label('bytes')).\
        filter(models.Source.rse_id == source.id).\
        filter(models.Source.dest_rse_id == destination.id).\
        group_by(source.rse, destination.rse)

    return [row._asdict() for row in query]


@read_session
def get_stats_by_activity_dest_state(state, session=None):
    """
    Retrieve statistics about per destination by activity and state.

    :param session: Database session to use.
    :returns List of (activity, dest_rse_id, state, counter).
    """

    if type(state) is not list:
        state = [state, state]

    try:
        subquery = session.query(models.Request.activity, models.Request.dest_rse_id,
                                 models.Request.account, models.Request.state,
                                 func.count(1).label('counter'))\
            .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
            .filter(models.Request.state.in_(state))\
            .group_by(models.Request.activity,
                      models.Request.dest_rse_id,
                      models.Request.account,
                      models.Request.state).subquery()

        return session.query(subquery.c.activity,
                             subquery.c.dest_rse_id,
                             subquery.c.account,
                             subquery.c.state,
                             models.RSE.rse,
                             subquery.c.counter)\
            .with_hint(models.RSE, "INDEX(RSES RSES_PK)", 'oracle')\
            .filter(models.RSE.id == subquery.c.dest_rse_id).all()

    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def release_waiting_requests(rse, activity=None, rse_id=None, count=None, account=None, session=None):
    """
    Release waiting requests.

    :param rse: The RSE name.
    :param activity: The activity.
    :param rse_id: The RSE id.
    :param count: The count to be released. If None, release all waiting requests.
    """
    try:
        if not rse_id:
            rse_id = get_rse_id(rse=rse, session=session)
        rowcount = 0

        if count is None:
            query = session.query(models.Request).\
                filter_by(dest_rse_id=rse_id, state=RequestState.WAITING)
            if activity:
                query = query.filter_by(activity=activity)
            if account:
                query = query.filter_by(account=account)
            rowcount = query.update({'state': RequestState.QUEUED}, synchronize_session=False)
        elif count > 0:
            subquery = session.query(models.Request.id)\
                              .filter(models.Request.dest_rse_id == rse_id)\
                              .filter(models.Request.state == RequestState.WAITING)\
                              .order_by(asc(models.Request.requested_at))
            if activity:
                subquery = subquery.filter(models.Request.activity == activity)
            if account:
                subquery = subquery.filter(models.Request.account == account)
            subquery = subquery.limit(count).with_for_update()

            rowcount = session.query(models.Request)\
                              .filter(models.Request.id.in_(subquery))\
                              .update({'state': RequestState.QUEUED},
                                      synchronize_session=False)
        return rowcount
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def update_requests_priority(priority, filter, session=None):
    """
    Update priority of requests.

    :param priority: The priority as an integer from 1 to 5.
    :param filter: Dictionary such as {'rule_id': rule_id, 'request_id': request_id, 'older_than': time_stamp, 'activities': [activities]}.
    """
    try:
        query = session.query(models.Request.id, models.Request.external_id, models.Request.external_host)\
            .join(models.ReplicaLock, and_(models.ReplicaLock.scope == models.Request.scope,
                                           models.ReplicaLock.name == models.Request.name,
                                           models.ReplicaLock.rse_id == models.Request.dest_rse_id))\
            .filter(models.Request.state == RequestState.SUBMITTED,
                    models.ReplicaLock.state == LockState.REPLICATING)

        if 'rule_id' in filter:
            query = query.filter(models.ReplicaLock.rule_id == filter['rule_id'])
        if 'request_id' in filter:
            query = query.filter(models.Request.id == filter['request_id'])
        if 'older_than' in filter:
            query = query.filter(models.Request.created_at < filter['older_than'])
        if 'activities' in filter:
            if type(filter['activities']) is not list:
                filter['activities'] = filter['activities'].split(',')
            query = query.filter(models.Request.activity.in_(filter['activities']))

        for item in query.all():
            try:
                res = fts3.update_priority(item[1], item[2], priority)
            except:
                logging.debug("Failed to boost request %s priority: %s" % (item[0], traceback.format_exc()))
            else:
                logging.debug("Update request %s priority to %s: %s" % (item[0], priority, res['http_message']))
    except IntegrityError, e:
        raise RucioException(e.args)
