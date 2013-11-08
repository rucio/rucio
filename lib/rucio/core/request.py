# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from re import match

from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import asc

from rucio.common.exception import RucioException
from rucio.core.monitor import record_counter
from rucio.db import models
from rucio.db.constants import RequestState, FTSState
from rucio.db.session import read_session, transactional_session
from rucio.transfertool import fts3


@transactional_session
def queue_requests(requests, session=None):
    """
    Submit transfer or deletion requests on a destination RSE for a data identifier.

    :param requests: Dictionary containing 'scope', 'name', 'dest_rse_id', 'req_type', 'metadata'
    :returns: List of Request-IDs as 32 character hex strings
    """

    record_counter('core.request.queue_requests')

    try:
        for req in requests:
            new_request = models.Request(request_type=req['req_type'],
                                         scope=req['scope'],
                                         name=req['name'],
                                         dest_rse_id=req['dest_rse_id'],
                                         attributes=str(req['metadata']),
                                         state=RequestState.QUEUED)

            new_request.save(session=session, flush=False)
        session.flush()
    except IntegrityError, e:
        if e.args[0] == "(IntegrityError) columns scope, name are not unique" \
           or match('.*IntegrityError.*ORA-00001: unique constraint.*DIDS_PK.*violated.*', e.args[0]) \
           or match('.*IntegrityError.*ORA-00001: unique constraint.*REQUESTS_PK.*violated.*', e.args[0]) \
           or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', e.args[0]):
            pass  # silently accept - we already have a transfer request for this DID@RSE
        else:
            raise RucioException(e.args)
    except:
        raise


@transactional_session
def queue_request(scope, name, dest_rse_id, req_type, metadata={}, session=None):
    """
    Submit a transfer or deletion request on a destination RSE for a data identifier.

    :param scope: Data identifier scope as a string.
    :param name: Data identifier name as a string.
    :param dest_rse: RSE identifier as a string.
    :param req_type: Type of the request as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Request-ID as a 32 character hex string.
    """

    record_counter('core.request.queue_request')

    queue_requests(requests=[{'scope': scope,
                              'name': name,
                              'dest_rse_id': dest_rse_id,
                              'req_type': req_type,
                              'metadata': metadata}],
                   session=session)


@transactional_session
def submit_deletion(url, session=None):
    """
    Submit a deletion request to a deletiontool.

    :param src_url: URL acceptable to deletiontool as a string.
    :returns: Deletiontool external ID.
    """

    record_counter('core.request.submit_deletion')


@transactional_session
def submit_transfers(transfers, transfertool, job_metadata={}, session=None):
    """
    Submit transfer request to a transfertool.

    :param transfers: Dictionary containing 'request_id', 'src_urls', 'dest_urls', 'filesize', 'checksum'
    :param transfertool: Transfertool as a string.
    :param job_metadata: Metadata key/value pairs for all files as a dictionary.
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


@transactional_session
def submit_transfer(request_id, src_urls, dest_urls, transfertool, metadata={}, session=None):
    """
    Submit a transfer request to a transfertool.

    :param request_id: Associated request identifier as a string.
    :param src_urls: Source URLs acceptable to transfertool as a list of strings.
    :param dest_urls: Destination URLs acceptable to transfertool as a list of strings.
    :param transfertool: Transfertool as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Transfertool external ID.
    """

    record_counter('core.request.submit_transfer')

    submit_transfers(transfers=[{'request_id': request_id,
                                 'src_urls': src_urls,
                                 'dest_urls': dest_urls,
                                 'filesize': 12345L,
                                 'checksum': 'ad:12345',
                                 'metadata': metadata}],
                     transfertool=transfertool,
                     session=session)


@transactional_session
def get_next(req_type, state, limit=1, process=None, total_processes=None, thread=None, total_threads=None, session=None):
    """
    Retrieve the next requests matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param account: Account identifier as a string.
    :param req_type: Type of the request as a string.
    :param state: State of the request as a string.
    :param n: Integer of requests to retrieve.
    :param process: Identifier of the caller process as an integer.
    :param total_processes: Maximum number of processes as an integer.
    :param thread: Identifier of the caller thread as an integer.
    :param total_threads: Maximum number of threads as an integer.
    :returns: Request as a dictionary.
    """

    record_counter('core.request.get_next.%s-%s' % (req_type, state))

    query = session.query(models.Request).add_columns(models.Request.id,
                                                      models.Request.scope,
                                                      models.Request.name,
                                                      models.Request.dest_rse_id)\
                                         .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_CRE_IDX)", 'oracle')\
                                         .filter_by(request_type=req_type, state=state)\
                                         .order_by(asc(models.Request.created_at))

    if (total_processes-1) > 0:
        if session.bind.dialect.name == 'oracle':
            query = query.filter('ORA_HASH(name, %s) = %s' % (total_processes-1, process))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_processes-1, process))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_processes-1, process))

    if (total_threads-1) > 0:
        if session.bind.dialect.name == 'oracle':
            query = query.filter('ORA_HASH(name, %s) = %s' % (total_threads-1, thread))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_threads-1, thread))
        elif session.bind.dialect.name == 'postgresql':
            query = query.filter('mod(abs((\'x\'||md5(name))::bit(32)::int), %s) = %s' % (total_threads-1, thread))

    tmp = query.limit(limit).all()

    if tmp == [] or tmp is None:
        return
    else:
        result = []
        for t in tmp:
            result.append({'request_id': t[1],
                           'scope': t[2],
                           'name': t[3],
                           'dest_rse_id': t[4]})
        return result


@read_session
def __get_external_id(request_id, session=None):
    """
    Retrieve the ID used by the external tool.

    :param request_id: Request-ID as a 32 character hex string.
    :returns: External ID as a string.
    """

    try:
        res = session.query(models.Request).add_columns(models.Request.external_id).filter_by(id=request_id).all()
        if res is None or res == []:
            return None
        else:
            return res[0][1]
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def query_request(request_id, transfertool, session=None):
    """
    Query the status of a request.

    :param request_id: Request-ID as a 32 character hex string.
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

            if response['job_state'] == str(FTSState.FAILED) or response['job_state'] == str(FTSState.FINISHEDDIRTY):
                req_status['new_state'] = RequestState.FAILED
            elif response['job_state'] == str(FTSState.FINISHED):
                req_status['new_state'] = RequestState.DONE

    else:
        raise NotImplementedError

    return req_status


@transactional_session
def set_request_state(request_id, new_state, session=None):
    """
    Update the state of a request. Fails silently if the request_id does not exist.

    :param request_id: Request-ID as a 32 character hex string.
    :param new_state: New state as string.
    """

    record_counter('core.request.set_request_state')

    try:
        session.query(models.Request).filter_by(id=request_id).update({'state': new_state})
    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def archive_request(request_id, session=None):
    """
    Move a request to the history table.

    :param request_id: Request-ID as a 32 character hex string.
    """

    record_counter('core.request.archive')

    try:
        session.execute('INSERT INTO atlas_rucio.requests_history SELECT * FROM atlas_rucio.requests WHERE id = hextoraw(:id)', {'id': request_id})
        purge_request(request_id=request_id, session=session)
    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def purge_request(request_id, session=None):
    """
    Purge a request.

    :param request_id: Request Identifier as a 32 character hex string.
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


def cancel_request_did(scope, name, dest_rse, req_type):
    """
    Cancel a request based on a DID and request type.

    :param scope: Data identifier scope as a string.
    :param name: Data identifier name as a string.
    :param dest_rse: RSE name as a string.
    :param req_type: Type of the request as a string.
    """

    record_counter('core.request.cancel_request_did')

    # select correct transfertool and external transfer id based on request entry in database
    transfer_id = 'whatever'

    #if transfertool == 'fts3':
    #    return fts3.cancel(transfer_id)

    return fts3.cancel(transfer_id)  # hardcoded for now
