# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014-2015

import datetime
import json
import logging
import time
import traceback

from sqlalchemy import and_, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import asc, bindparam, text

from rucio.common.exception import RequestNotFound, RucioException, UnsupportedOperation
from rucio.common.utils import generate_uuid
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import get_rse_id, get_rse_name
from rucio.db import models
from rucio.db.constants import RequestState, RequestType, FTSState, ReplicaState
from rucio.db.session import read_session, transactional_session
from rucio.transfertool import fts3


def should_retry_request(req):
    """
    Whether should retry this request.

    :param request: Request as a dictionary.
    :returns: True if should retry it; False if no more retry.
    """
    if req['state'] == RequestState.SUBMITTING:
        return True
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
                    if new_req['sources'][i]['ranking'] is None:
                        new_req['sources'][i]['ranking'] = -1
                    else:
                        new_req['sources'][i]['ranking'] -= 1
            queue_requests([new_req], session=session)
            return new_req


@transactional_session
def queue_requests(requests, session=None):
    """
    Submit transfer or deletion requests on destination RSEs for data identifiers.

    :param requests: List of dictionaries containing request metadata.
    :param session: Database session to use.
    :returns: List of Request-IDs as 32 character hex strings.
    """

    record_counter('core.request.queue_requests')

    try:
        for req in requests:
            if isinstance(req['attributes'], (str, unicode)):
                req['attributes'] = json.loads(req['attributes'])
                if isinstance(req['attributes'], (str, unicode)):
                    req['attributes'] = json.loads(req['attributes'])

            # do not insert duplicate transfer requests
            if req['request_type'] == RequestType.TRANSFER:
                try:
                    get_request_by_did(req['scope'],
                                       req['name'],
                                       None,
                                       rse_id=req['dest_rse_id'],
                                       request_type=RequestType.TRANSFER,
                                       session=session)
                    continue
                except:
                    pass

            new_request = models.Request(request_type=req['request_type'],
                                         scope=req['scope'],
                                         name=req['name'],
                                         dest_rse_id=req['dest_rse_id'],
                                         attributes=json.dumps(req['attributes']),
                                         state=RequestState.QUEUED,
                                         rule_id=req['rule_id'],
                                         activity=req['attributes']['activity'],
                                         bytes=req['attributes']['bytes'],
                                         md5=req['attributes']['md5'],
                                         adler32=req['attributes']['adler32'])
            if 'previous_attempt_id' in req and 'retry_count' in req:
                new_request = models.Request(id=req['request_id'],
                                             request_type=req['request_type'],
                                             scope=req['scope'],
                                             name=req['name'],
                                             dest_rse_id=req['dest_rse_id'],
                                             attributes=json.dumps(req['attributes']),
                                             state=RequestState.QUEUED,
                                             previous_attempt_id=req['previous_attempt_id'],
                                             retry_count=req['retry_count'],
                                             rule_id=req['rule_id'],
                                             activity=req['attributes']['activity'],
                                             bytes=req['attributes']['bytes'],
                                             md5=req['attributes']['md5'],
                                             adler32=req['attributes']['adler32'])

            new_request.save(session=session)

            if 'sources' in req and req['sources']:
                for source in req['sources']:
                    models.Source(request_id=new_request['id'],
                                  scope=req['scope'],
                                  name=req['name'],
                                  rse_id=source['rse_id'],
                                  dest_rse_id=req['dest_rse_id'],
                                  ranking=source['ranking'],
                                  bytes=source['bytes'],
                                  url=source['url']).\
                        save(session=session, flush=False)

        session.flush()
    except IntegrityError:
        logging.warn('Request TYPE %s for DID %s:%s at RSE %s exists - ignoring' % (req['request_type'],
                                                                                    req['scope'],
                                                                                    req['name'],
                                                                                    get_rse_name(req['dest_rse_id'])))
        raise


def submit_bulk_transfers(external_host, files, transfertool='fts3', job_params={}):
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
        transfer_id = fts3.submit_bulk_transfers(external_host, job_files, job_params)
        record_timer('core.request.submit_transfers_fts3', (time.time() - ts) * 1000/len(files))
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

        if (total_processes-1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('process_number', process), bindparam('total_processes', total_processes-1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_processes) = :process_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter('mod(md5(rule_id), %s) = %s' % (total_processes-1, process))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_processes-1, process))

        if (total_threads-1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads-1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter('mod(md5(rule_id), %s) = %s' % (total_threads-1, thread))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_threads-1, thread))

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

        if (total_processes-1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('process_number', process), bindparam('total_processes', total_processes-1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_processes) = :process_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter('mod(md5(rule_id), %s) = %s' % (total_processes-1, process))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_processes-1, process))

        if (total_threads-1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads-1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter('mod(md5(rule_id), %s) = %s' % (total_threads-1, thread))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_threads-1, thread))

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

        if not response:
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


@read_session
def query_latest(external_host, state, last_nhours=1, session=None):
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
                logging.info("Transfer %s on %s is %s, decrease its updated_at." % (resp['job_id'], external_host, resp['job_state']))
                set_transfer_update_time(external_host, resp['job_id'], datetime.datetime.utcnow() - datetime.timedelta(hours=24))
            except Exception, e:
                logging.warn("Exception happened when updating transfer updatetime: %s" % str(e).replace('\n', ''))
            continue

        request_id = resp['job_metadata']['request_id']
        try:
            req = get_request(request_id, session=session)
        except:
            logging.warning(traceback.format_exc())
            continue

        if req:
            if resp['job_state'] in (str(FTSState.FAILED),
                                     str(FTSState.FINISHEDDIRTY),
                                     str(FTSState.CANCELED)):
                new_state = RequestState.FAILED
            elif resp['job_state'] == str(FTSState.FINISHED):
                new_state = RequestState.DONE

            if 'finish_time' in resp and resp['finish_time'] and 'submit_time' in resp and resp['submit_time']:
                duration = (datetime.datetime.strptime(resp['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                            datetime.datetime.strptime(resp['submit_time'], '%Y-%m-%dT%H:%M:%S')).seconds
            else:
                duration = 0

            response = {'new_state': new_state,
                        'transfer_id': resp.get('job_id', None),
                        'job_state': resp.get('job_state', None),
                        # Todo, "source_se" is just a short se path, for example "srm://srm-atlas.cern.ch". It's not full surl.
                        # for multiple source replicas, it will be None
                        'src_url': resp.get('source_se', None),
                        'dst_url': req['dest_url'],
                        'transferred_at': datetime.datetime.strptime(resp['finish_time'], '%Y-%m-%dT%H:%M:%S') if resp['finish_time'] else None,
                        # Todo, should be file start_time, not job start_time
                        'duration': duration,
                        'reason': resp.get('reason', None),
                        'scope': resp['job_metadata'].get('scope', None),
                        'name': resp['job_metadata'].get('name', None),
                        'src_rse': resp['job_metadata'].get('src_rse', None),  # Todo for multiple source replicas
                        'dst_rse': resp['job_metadata'].get('dst_rse', None),
                        'request_id': resp['job_metadata'].get('request_id', None),
                        'activity': resp['job_metadata'].get('activity', None),
                        'dest_rse_id': resp['job_metadata'].get('dest_rse_id', None),
                        'previous_attempt_id': resp['job_metadata'].get('previous_attempt_id', None),
                        'adler32': resp['job_metadata'].get('adler32', None),
                        'md5': resp['job_metadata'].get('md5', None),
                        'filesize': resp['job_metadata'].get('filesize', None),
                        'external_host': external_host,
                        'job_m_replica': None,   # Todo, do we need to set it true? If it's true, common.get_source_rse will not called to correct the src_url and src_rse
                        'details': {'files': resp['job_metadata']}}
            ret_resps.append(response)
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
            if not fts_resp:
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


def bulk_query_transfers(request_host, transfer_ids, transfertool='fts3'):
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
            fts_resps = fts3.bulk_query(transfer_ids, request_host)
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
def set_requests_external(transfer_ids, session=None):
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
                        'submitted_at': datetime.datetime.utcnow()},
                       synchronize_session=False)


@transactional_session
def set_request_state(request_id, new_state, transfer_id=None, transferred_at=None, session=None):
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
        rowcount = session.query(models.Request).filter_by(external_id=transfer_id).update({'updated_at': update_time}, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)

    if not rowcount:
        raise UnsupportedOperation("Transfer %s on %s cannot be updated." % (transfer_id, external_host))


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
                                     .update({'updated_at': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, synchronize_session=False)
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
    :param request_type: The type of request as rucio.db.constants.RequestType.
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
                                                                attributes=req['attributes'],
                                                                state=req['state'],
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


@read_session
def list_transfer_requests_and_source_replicas(process=None, total_processes=None, thread=None, total_threads=None,
                                               activity=None, older_than=None, rses=None, session=None):
    """
    List requests with source replicas

    :param process: Identifier of the caller process as an integer.
    :param total_processes: Maximum number of processes as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param activity: Activity to be selected.
    :param older_than: Only select requests older than this DateTime.
    :param rses: List of rse_id to select requests.
    :param session: Database session to use.
    :returns: List.
    """
    is_false = False  # For PEP8
    query = session.query(models.Request.id,
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
                          models.RSEFileAssociation.rse_id,
                          models.RSE.rse,
                          models.RSE.deterministic,
                          models.RSE.rse_type,
                          models.RSEFileAssociation.path,
                          models.Request.retry_count,
                          models.Source.url,
                          models.Source.ranking)\
        .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
        .filter(models.Request.state == RequestState.QUEUED)\
        .filter(models.Request.request_type == RequestType.TRANSFER)\
        .outerjoin(models.RSEFileAssociation, and_(models.Request.scope == models.RSEFileAssociation.scope,
                                                   models.Request.name == models.RSEFileAssociation.name,
                                                   models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                                                   models.Request.dest_rse_id != models.RSEFileAssociation.rse_id))\
        .outerjoin(models.RSE, and_(models.RSE.id == models.RSEFileAssociation.rse_id,
                                    models.RSE.staging_area == is_false))\
        .outerjoin(models.Source, and_(models.Request.id == models.Source.request_id,
                                       models.RSE.id == models.Source.rse_id))

    if isinstance(older_than, datetime.datetime):
        query = query.filter(models.Request.updated_at < older_than)

    if activity:
        query = query.filter(models.Request.activity == activity)

    if (total_processes-1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('process_number', process), bindparam('total_processes', total_processes-1)]
            query = query.filter(text('ORA_HASH(rule_id, :total_processes) = :process_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(rule_id), %s) = %s' % (total_processes-1, process))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_processes-1, process))

    if (total_threads-1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads-1)]
            query = query.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(rule_id), %s) = %s' % (total_threads-1, thread))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_threads-1, thread))

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
                                              activity=None, older_than=None, rses=None, session=None):
    """
    List stagein requests with source replicas

    :param process: Identifier of the caller process as an integer.
    :param total_processes: Maximum number of processes as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param activity: Activity to be selected.
    :param older_than: Only select requests older than this DateTime.
    :param rses: List of rse_id to select requests.
    :param session: Database session to use.
    :returns: List.
    """
    is_false = False  # For PEP8
    query = session.query(models.Request.id,
                          models.Request.rule_id,
                          models.Request.scope,
                          models.Request.name,
                          models.Request.md5,
                          models.Request.adler32,
                          models.Request.bytes,
                          models.Request.activity,
                          models.Request.attributes,
                          models.Request.dest_rse_id,
                          models.RSEFileAssociation.rse_id,
                          models.RSE.rse,
                          models.RSE.deterministic,
                          models.RSE.rse_type,
                          models.RSEFileAssociation.path,
                          models.RSEAttrAssociation.value,
                          models.Request.retry_count,
                          models.Request.previous_attempt_id,
                          models.Source.url,
                          models.Source.ranking)\
        .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
        .filter(models.Request.state == RequestState.QUEUED)\
        .filter(models.Request.request_type == RequestType.STAGEIN)\
        .outerjoin(models.RSEFileAssociation, and_(models.Request.scope == models.RSEFileAssociation.scope,
                                                   models.Request.name == models.RSEFileAssociation.name,
                                                   models.RSEFileAssociation.state == ReplicaState.AVAILABLE,
                                                   models.Request.dest_rse_id != models.RSEFileAssociation.rse_id))\
        .outerjoin(models.RSE, and_(models.RSE.id == models.RSEFileAssociation.rse_id,
                                    models.RSE.staging_area == is_false))\
        .outerjoin(models.RSEAttrAssociation, and_(models.RSEAttrAssociation.rse_id == models.RSE.id,
                                                   models.RSEAttrAssociation.key == 'staging_buffer'))\
        .outerjoin(models.Source, and_(models.Request.id == models.Source.request_id,
                                       models.RSE.id == models.Source.rse_id))

    if isinstance(older_than, datetime.datetime):
        query = query.filter(models.Request.updated_at < older_than)

    if activity:
        query = query.filter(models.Request.activity == activity)

    if (total_processes-1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('process_number', process), bindparam('total_processes', total_processes-1)]
            query = query.filter(text('ORA_HASH(rule_id, :total_processes) = :process_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(rule_id), %s) = %s' % (total_processes-1, process))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_processes-1, process))

    if (total_threads-1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads-1)]
            query = query.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(rule_id), %s) = %s' % (total_threads-1, thread))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(rule_id))::bit(32)::int), %s) = %s' % (total_threads-1, thread))

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
def get_sources(request_id, session=None):
    """
    Retrieve sources by its ID.

    :param request_id: Request-ID as a 32 character hex string.
    :param session: Database session to use.
    :returns: Sources as a dictionary.
    """

    try:
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
        results = session.query(models.Source.rse_id, func.count(models.Source.rse_id).label('load')).group_by(models.Source.rse_id).all()

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
