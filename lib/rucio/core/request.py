# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import asc

from rucio.common.exception import RucioException
from rucio.core.monitor import record_counter
from rucio.db import models
from rucio.db.constants import RequestState
from rucio.db.session import read_session, transactional_session
from rucio.transfertool import fts3


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

    new_request = models.Request(request_type=req_type,
                                 scope=scope,
                                 name=name,
                                 dest_rse_id=dest_rse_id,
                                 attributes=str(metadata),
                                 state=RequestState.QUEUED)

    try:
        new_request.save(session=session)
    except IntegrityError, e:
        raise RucioException(e.args)


@transactional_session
def submit_deletion(url, session=None):
    """
    Submit a deletion request to a deletiontool.

    :param src_url: URL acceptable to deletiontool as a string.
    :returns: Deletiontool external ID.
    """

    record_counter('core.request.submit_deletion')


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

    transfer_id = None

    if transfertool == 'fts3':
        transfer_id = fts3.submit(src_urls=src_urls, dest_urls=dest_urls, filesize=None, checksum=None, overwrite=False, job_metadata=metadata)
    elif transfertool == 'fts3-mock':
        transfer_id = fts3.submit(src_urls=src_urls, dest_urls=dest_urls, filesize=None, checksum=None, overwrite=False, job_metadata=metadata, mock=True)

    session.query(models.Request).filter_by(id=request_id).update({'state': RequestState.SUBMITTED, 'external_id': transfer_id})


@transactional_session
def get_next(req_type, state, limit=1, worker_number=None, total_workers=None, session=None):
    """
    Retrieve the next requests matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param account: Account identifier as a string.
    :param req_type: Type of the request as a string.
    :param state: State of the request as a string.
    :param n: Integer of requests to retrieve.
    :param worker_number: Identifier of the caller as an integer.
    :param total_workers: Maximum number of workers as an integer.
    :returns: Request as a dictionary.
    """

    record_counter('core.request.get_next.%s-%s' % (req_type, state))

    query = session.query(models.Request).add_columns(models.Request.id,
                                                      models.Request.scope,
                                                      models.Request.name,
                                                      models.Request.dest_rse_id)\
                                         .filter_by(request_type=req_type, state=state)\
                                         .order_by(asc(models.Request.created_at))

    if worker_number and total_workers:
        if session.bind.dialect.name == 'oracle':
            query = query.filter('ORA_HASH(name, %s) = %s' % (total_workers-1, worker_number-1))
        elif session.bind.dialect.name == 'mysql':
            query = query.filter('mod(md5(name), %s) = %s' % (total_workers-1, worker_number-1))

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
        return session.query(models.Request).add_columns(models.Request.external_id).filter_by(id=request_id).one()[1]
    except IntegrityError, e:
        raise RucioException(e.args)


@read_session
def query_request(request_id, session=None):
    """
    Query the status of a request.

    :param request_id: Request-ID as a 32 character hex string.
    :returns: Request status information as a dictionary.
    """

    record_counter('core.request.query_request')

    transfertool = 'fts3-mock'

    external_id = __get_external_id(request_id, session=session)

    req_status = {'request_id': request_id}

    if transfertool == 'fts3':
        response = fts3.query(external_id)
    elif transfertool == 'fts3-mock':
        response = fts3.query(external_id, mock=True)

    if response is None:
        raise Exception('The external tool does not know about request %(external_id)s' % locals())
    else:
        req_status['state'] = response['job_state']
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


def cancel_request(request_id):
    """
    Cancel a request.

    :param request_id: Request Identifier as a 32 character hex string.
    """

    record_counter('core.request.cancel_request')

    # select correct transfertool and external transfer id based on rucio transfer id entry in database
    transfertool = 'fts3-mock'
    transfer_id = request_id

    if transfertool == 'fts3':
        return fts3.cancel(transfer_id)
    elif transfertool == 'fts3-mock':
        return fts3.cancel(transfer_id, mock=True)


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
    transfertool = 'fts3-mock'
    transfer_id = 'whatever'

    if transfertool == 'fts3':
        return fts3.cancel(transfer_id)
    elif transfertool == 'fts3-mock':
        return fts3.cancel(transfer_id, mock=True)
