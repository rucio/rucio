# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014

import datetime
import json
import logging
import random
import re
import time

from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import asc, bindparam, text

from rucio.common.config import config_get
from rucio.common.exception import RucioException
from rucio.common.utils import generate_uuid
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import get_rse_name
from rucio.db import models
from rucio.db.constants import RequestState, RequestType, FTSState
from rucio.db.session import read_session, transactional_session
from rucio.transfertool import fts3

__HOSTS = [b.strip() for b in config_get('conveyor', 'ftshosts').split(',')]


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
        archive_request(request_id, session=session)
        new_req['request_id'] = generate_uuid()
        new_req['previous_attempt_id'] = request_id
        if new_req['retry_count'] is None:
            new_req['retry_count'] = 1
        else:
            new_req['retry_count'] += 1

        # hardcoded for now - only requeue a couple of times
        if new_req['retry_count'] < 4:
            queue_requests([new_req], session=session)
            return new_req


@transactional_session
def queue_requests(requests, session=None):
    """
    Submit transfer or deletion requests on destination RSEs for data identifiers.

    :param requests: List of dictionaries containing 'scope', 'name', 'dest_rse_id', 'request_type', 'attributes'
    :param session: Database session to use.
    :returns: List of Request-IDs as 32 character hex strings
    """

    record_counter('core.request.queue_requests')

    try:
        for req in requests:
            new_request = models.Request(request_type=req['request_type'],
                                         scope=req['scope'],
                                         name=req['name'],
                                         dest_rse_id=req['dest_rse_id'],
                                         attributes=json.dumps(req['attributes']),
                                         state=RequestState.QUEUED,
                                         rule_id=req['rule_id'])
            if 'previous_attempt_id' in req and 'retry_count' in req:
                new_request = models.Request(id=req['request_id'],
                                             request_type=req['request_type'],
                                             scope=req['scope'],
                                             name=req['name'],
                                             dest_rse_id=req['dest_rse_id'],
                                             attributes=req['attributes'],
                                             state=RequestState.QUEUED,
                                             previous_attempt_id=req['previous_attempt_id'],
                                             retry_count=req['retry_count'],
                                             rule_id=req['rule_id'])
            new_request.save(session=session, flush=False)
        session.flush()
    except IntegrityError, e:
        if e.args[0] == "(IntegrityError) columns scope, name are not unique" \
           or re.match('.*IntegrityError.*ORA-00001: unique constraint.*DIDS_PK.*violated.*', e.args[0]) \
           or re.match('.*IntegrityError.*ORA-00001: unique constraint.*REQUESTS_PK.*violated.*', e.args[0]) \
           or re.match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', e.args[0]):
            logging.warn('Transfer request for DID %s:%s at RSE %s exists - ignoring' % (req['scope'],
                                                                                         req['name'],
                                                                                         get_rse_name(req['dest_rse_id'])))
        else:
            raise RucioException(e.args)


@transactional_session
def submit_deletion(url, session=None):
    """
    Submit a deletion request to a deletiontool.

    :param url: URL acceptable to deletiontool as a string.
    :param session: Database sesssion to use.
    :returns: Deletiontool external ID.
    """

    record_counter('core.request.submit_deletion')


@transactional_session
def submit_transfers(transfers, transfertool='fts3', job_metadata={}, session=None):
    """
    Submit transfer request to a transfertool.

    :param transfers: Dictionary containing 'request_id', 'src_urls', 'dest_urls', 'bytes', 'md5', 'adler32'
    :param transfertool: Transfertool as a string.
    :param job_metadata: Metadata key/value pairs for all files as a dictionary.
    :param session: Database session to use.
    :returns: Transfertool external ID.
    """

    record_counter('core.request.submit_transfer')

    transfer_id = None
    external_host = random.sample(__HOSTS, 1)[0]

    if transfertool == 'fts3':
        ts = time.time()
        transfer_ids = fts3.submit_transfers(transfers, job_metadata, external_host)
        record_timer('core.request.submit_transfers_fts3', (time.time() - ts) * 1000)

    for transfer_id in transfer_ids:
        session.query(models.Request)\
               .filter_by(id=transfer_id)\
               .update({'state': RequestState.SUBMITTED,
                        'external_id': transfer_ids[transfer_id],
                        'external_host': external_host},
                       synchronize_session=False)

    return (transfer_ids, external_host)


@transactional_session
def submit_transfer(request_id, src_urls, dest_urls, transfertool, filesize, md5=None, adler32=None, metadata={}, session=None):
    """
    Submit a transfer request to a transfertool.

    :param request_id: Associated request identifier as a string.
    :param src_urls: Source URLs acceptable to transfertool as a list of strings.
    :param dest_urls: Destination URLs acceptable to transfertool as a list of strings.
    :param transfertool: Transfertool as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :param session: Database session to use.
    :returns: Transfertool external ID.
    """

    record_counter('core.request.submit_transfer')

    return submit_transfers(transfers=[{'request_id': request_id,
                                        'src_urls': src_urls,
                                        'dest_urls': dest_urls,
                                        'filesize': filesize,
                                        'md5': md5,
                                        'adler32': adler32,
                                        'metadata': metadata}],
                            transfertool=transfertool,
                            session=session)


@read_session
def get_next(request_type, state, limit=100, older_than=None, process=None, total_processes=None, thread=None, total_threads=None, session=None):
    """
    Retrieve the next requests matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param request_type: Type of the request as a string or list of strings.
    :param state: State of the request as a string.
    :param limit: Integer of requests to retrieve.
    :param older_than: Only select requests older than this DateTime.
    :param process: Identifier of the caller process as an integer.
    :param total_processes: Maximum number of processes as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :param session: Database session to use.
    :returns: Request as a dictionary.
    """

    record_counter('core.request.get_next.%s-%s' % (request_type, state))

    # lists of one element are not allowed by SQLA, so just duplicate the item
    if type(request_type) == str:
        request_type = [request_type, request_type]
    elif len(request_type) == 1:
        request_type = [request_type[0], request_type[0]]

    query = session.query(models.Request).with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
                                         .filter_by(state=state)\
                                         .filter(models.Request.request_type.in_(request_type))\
                                         .order_by(asc(models.Request.updated_at))

    if isinstance(older_than, datetime.datetime):
        query = query.filter(models.Request.updated_at < older_than)

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

    tmp = query.limit(limit).all()

    if not tmp:
        return
    else:
        result = []
        for t in tmp:
            t2 = dict(t)
            t2.pop('_sa_instance_state')
            t2['request_id'] = t2['id']
            t2['attributes'] = json.loads(str(t2['attributes']))
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
def bulk_query_requests(request_host, request_ids, transfertool='fts3', session=None):
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
            req_status = {'request_id': request_id,
                          'transfer_id': external_id,
                          'job_state': None,
                          'new_state': None}
            fts_resp = fts_resps[external_id]
            req_status['details'] = fts_resp
            if not fts_resp:
                req_status['new_state'] = RequestState.LOST
            elif not isinstance(fts_resp, Exception):
                if 'job_state' not in fts_resp:
                    req_status['new_state'] = RequestState.LOST
                else:
                    req_status['job_state'] = fts_resp['job_state']
                    if fts_resp['job_state'] in (str(FTSState.FAILED),
                                                 str(FTSState.FINISHEDDIRTY),
                                                 str(FTSState.CANCELED)):
                        req_status['new_state'] = RequestState.FAILED
                    elif fts_resp['job_state'] == str(FTSState.FINISHED):
                        req_status['new_state'] = RequestState.DONE

            responses[request_id] = req_status
        return responses
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
def set_request_state(request_id, new_state, session=None):
    """
    Update the state of a request. Fails silently if the request_id does not exist.

    :param request_id: Request-ID as a 32 character hex string.
    :param new_state: New state as string.
    :param session: Database session to use.
    """

    record_counter('core.request.set_request_state')

    try:
        session.query(models.Request).filter_by(id=request_id).update({'state': new_state}, synchronize_session=False)
    except IntegrityError, e:
        raise RucioException(e.args)


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
        session.query(models.Request).filter_by(id=request_id).update({'updated_at': datetime.datetime.utcnow()}, synchronize_session=False)
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
                                                                external_host=req['external_host'])
        hist_request.save(session=session)
        try:
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
