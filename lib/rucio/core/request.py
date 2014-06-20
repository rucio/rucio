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

import datetime
import json
import logging
import re

from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import asc, bindparam, text

from rucio.common.exception import RucioException
from rucio.common.utils import generate_uuid
from rucio.core.monitor import record_counter
from rucio.core.rse import get_rse_by_id
from rucio.db import models
from rucio.db.constants import RequestState, FTSState
from rucio.db.session import read_session, transactional_session
from rucio.transfertool import fts3


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
                                         state=RequestState.QUEUED)
            if 'previous_attempt_id' in req and 'retry_count' in req:
                new_request = models.Request(id=req['request_id'],
                                             request_type=req['request_type'],
                                             scope=req['scope'],
                                             name=req['name'],
                                             dest_rse_id=req['dest_rse_id'],
                                             attributes=req['attributes'],
                                             state=RequestState.QUEUED,
                                             previous_attempt_id=req['previous_attempt_id'],
                                             retry_count=req['retry_count'])
            new_request.save(session=session, flush=False)
        session.flush()
    except IntegrityError, e:
        if e.args[0] == "(IntegrityError) columns scope, name are not unique" \
           or re.match('.*IntegrityError.*ORA-00001: unique constraint.*DIDS_PK.*violated.*', e.args[0]) \
           or re.match('.*IntegrityError.*ORA-00001: unique constraint.*REQUESTS_PK.*violated.*', e.args[0]) \
           or re.match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', e.args[0]):
            logging.warn('Transfer request for DID %s:%s at RSE %s exists - ignoring' % (req['scope'],
                                                                                         req['name'],
                                                                                         get_rse_by_id(req['dest_rse_id'])['rse']))
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

    if transfertool == 'fts3':
        transfer_ids = fts3.submit_transfers(transfers=transfers, job_metadata=job_metadata)

    for transfer_id in transfer_ids:
        session.query(models.Request)\
               .filter_by(id=transfer_id)\
               .update({'state': RequestState.SUBMITTED, 'external_id': transfer_ids[transfer_id]}, synchronize_session=False)

    return transfer_ids


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
            bindparams = [bindparam('worker_number', process), bindparam('total_workers', total_processes-1)]
            query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_processes-1, process))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_processes-1, process))

    if (total_threads-1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('worker_number', thread), bindparam('total_workers', total_threads-1)]
            query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_threads-1, thread))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_threads-1, thread))

    tmp = query.limit(limit).all()

    if not tmp:
        return
    else:
        result = []
        for t in tmp:
            t2 = dict(t)
            t2.pop('_sa_instance_state')
            t2['request_id'] = t2['id']
            result.append(t2)
        return result


@read_session
def __get_external_id(request_id, session=None):
    """
    Retrieve the ID used by the external tool.

    :param request_id: Request-ID as a 32 character hex string.
    :param session: Database session to use.
    :returns: External ID as a string.
    """

    try:
        return session.query(models.Request.external_id).filter_by(id=request_id).first()[0]
    except IntegrityError, e:
        raise RucioException(e.args)


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

    external_id = __get_external_id(request_id, session=session)

    req_status = {'request_id': request_id,
                  'new_state': None}

    if external_id is None:
        req_status['new_state'] = RequestState.LOST
        return req_status

    if transfertool == 'fts3':
        response = fts3.query(external_id)

        if response is None:
            req_status['new_state'] = RequestState.LOST
        else:
            if 'job_state' not in response:
                req_status['new_state'] = RequestState.LOST
            elif response['job_state'] == str(FTSState.FAILED) or response['job_state'] == str(FTSState.FINISHEDDIRTY):
                req_status['new_state'] = RequestState.FAILED
            elif response['job_state'] == str(FTSState.FINISHED):
                req_status['new_state'] = RequestState.DONE

    else:
        raise NotImplementedError

    return req_status


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

    external_id = __get_external_id(request_id, session=session)

    if external_id is None:
        return

    if transfertool == 'fts3':
        return fts3.query_details(external_id)

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
        session.query(models.Request).filter_by(id=request_id).update({'state': new_state})
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def get_request(request_id, old=True, session=None):
    """
    Retrieve a request by its ID.

    :param request_id: Request-ID as a 32 character hex string.
    :param session: Database session to use.
    :returns: Request as a dictionary.
    """

    try:
        tmp = session.query(models.Request).filter_by(id=request_id).first()

        if tmp is None:
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
                                                                previous_attempt_id=req['previous_attempt_id'])
        hist_request.save(session=session)
        purge_request(request_id=request_id, session=session)


@transactional_session
def purge_request(request_id, session=None):
    """
    Purge a request.

    :param request_id: Request Identifier as a 32 character hex string.
    :param session: Database session to use.
    """

    record_counter('core.request.purge_request')

    try:
        session.query(models.Request).filter_by(id=request_id).delete()
    except IntegrityError, e:
        raise RucioException(e.args)


def cancel_request(request_id, transfertool):
    """
    Cancel a request.

    :param request_id: Request Identifier as a 32 character hex string.
    """

    record_counter('core.request.cancel_request')

    # select correct transfertool and external transfer id based on rucio transfer id entry in database
    transfer_id = request_id

    if transfertool == 'fts3':
        return fts3.cancel(transfer_id)


def cancel_request_did(scope, name, dest_rse, request_type):
    """
    Cancel a request based on a DID and request type.

    :param scope: Data identifier scope as a string.
    :param name: Data identifier name as a string.
    :param dest_rse: RSE name as a string.
    :param request_type: Type of the request as a string.
    """

    record_counter('core.request.cancel_request_did')

    # select correct transfertool and external transfer id based on request entry in database
    transfer_id = 'whatever'

    return None  # TODO: Temporary
    return fts3.cancel(transfer_id)  # hardcoded for now
