# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015, 2017
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017
# - Martin Barisits, <martin.barisits@cern.ch>, 2014-2017
# - Wen Guan, <wen.guan@cern.ch>, 2014-2016
# - Joaquin Bogado, <jbogadog@cern.ch>, 2016
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2017-2020
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White, <bjwhite@fnal.gov>, 2019
#
# PY3K COMPATIBLE

import datetime
import json
import logging
import time
import traceback

from six import string_types

from sqlalchemy import and_, or_, func, update
from sqlalchemy.exc import IntegrityError
# from sqlalchemy.sql import tuple_
from sqlalchemy.sql.expression import asc, false, true

from rucio.common.exception import RequestNotFound, RucioException, UnsupportedOperation, ConfigNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, chunks, get_parsed_throttler_mode
from rucio.core.config import get
from rucio.core.message import add_message
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import get_rse_name, get_rse_transfer_limits, get_rse_vo
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import RequestState, RequestType, FTSState, ReplicaState, LockState, RequestErrMsg
from rucio.db.sqla.session import read_session, transactional_session, stream_session
from rucio.transfertool.fts3 import FTS3Transfertool

"""
The core request.py is specifically for handling requests.
Requests accessed by external_id (So called transfers), are covered in the core transfer.py
"""


def should_retry_request(req, retry_protocol_mismatches):
    """
    Whether should retry this request.

    :param request:                      Request as a dictionary.
    :param retry_protocol_mismatches:    Boolean to retry the transfer in case of protocol mismatch.
    :returns:                            True if should retry it; False if no more retry.
    """
    if req['state'] == RequestState.SUBMITTING:
        return True
    if req['state'] == RequestState.NO_SOURCES or req['state'] == RequestState.ONLY_TAPE_SOURCES:
        return False
    # hardcoded for now - only requeue a couple of times
    if req['retry_count'] is None or req['retry_count'] < 3:
        if req['state'] == RequestState.MISMATCH_SCHEME:
            return retry_protocol_mismatches
        return True
    return False


@transactional_session
def requeue_and_archive(request, retry_protocol_mismatches=False, session=None):
    """
    Requeue and archive a failed request.
    TODO: Multiple requeue.

    :param request:     Original request.
    :param session:     Database session to use.
    """

    record_counter('core.request.requeue_request')
    # Probably not needed anymore
    request_id = request['request_id']
    new_req = get_request(request_id, session=session)

    if new_req:
        new_req['sources'] = get_sources(request_id, session=session)
        archive_request(request_id, session=session)

        if should_retry_request(new_req, retry_protocol_mismatches):
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
    else:
        raise RequestNotFound
    return None


@transactional_session
def queue_requests(requests, session=None):
    """
    Submit transfer requests on destination RSEs for data identifiers.

    :param requests:  List of dictionaries containing request metadata.
    :param session:   Database session to use.
    :returns:         List of Request-IDs as 32 character hex strings.
    """
    record_counter('core.request.queue_requests')

    logging.debug("queue requests")

    request_clause = []
    transfer_limits, rses = get_rse_transfer_limits(session=session), {}
    for req in requests:

        if isinstance(req['attributes'], string_types):
            req['attributes'] = json.loads(req['attributes'])
            if isinstance(req['attributes'], string_types):
                req['attributes'] = json.loads(req['attributes'])

        if req['request_type'] == RequestType.TRANSFER:
            request_clause.append(and_(models.Request.scope == req['scope'],
                                       models.Request.name == req['name'],
                                       models.Request.dest_rse_id == req['dest_rse_id'],
                                       models.Request.request_type == RequestType.TRANSFER))

        if req['dest_rse_id'] not in rses:
            rses[req['dest_rse_id']] = get_rse_name(req['dest_rse_id'], session=session)

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

    # Temporary disabled
    source_rses = {}
    # request_scopes_names = [(request['scope'], request['name']) for request in requests]
    # for chunked_requests in chunks(request_scopes_names, 50):
    #    results = session.query(models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.rse_id, models.Distance.dest_rse_id, models.Distance.ranking)\
    #                     .filter(tuple_(models.RSEFileAssociation.scope, models.RSEFileAssociation.name).in_(chunked_requests))\
    #                     .join(models.Distance, models.Distance.src_rse_id == models.RSEFileAssociation.rse_id)\
    #                     .all()
    #    for result in results:
    #        scope = result[0]
    #        name = result[1]
    #        src_rse_id = result[2]
    #        dest_rse_id = result[3]
    #        distance = result[4]
    #        if scope not in source_rses:
    #            source_rses[scope] = {}
    #        if name not in source_rses[scope]:
    #            source_rses[scope][name] = {}
    #        if dest_rse_id not in source_rses[scope][name]:
    #            source_rses[scope][name][dest_rse_id] = {}
    #        if src_rse_id not in source_rses[scope][name][dest_rse_id]:
    #            source_rses[scope][name][dest_rse_id][src_rse_id] = distance

    try:
        throttler_mode = get('throttler', 'mode', default=None, use_cache=False, session=session)
        direction, all_activities = get_parsed_throttler_mode(throttler_mode)
    except ConfigNotFound:
        throttler_mode = None

    new_requests, sources, messages = [], [], []
    for request in requests:
        dest_rse_name = get_rse_name(rse_id=request['dest_rse_id'], session=session)
        if req['request_type'] == RequestType.TRANSFER and (request['scope'], request['name'], request['dest_rse_id']) in existing_requests:
            logging.warn('Request TYPE %s for DID %s:%s at RSE %s exists - ignoring' % (request['request_type'],
                                                                                        request['scope'],
                                                                                        request['name'],
                                                                                        dest_rse_name))
            continue

        def temp_serializer(obj):
            if isinstance(obj, (InternalAccount, InternalScope)):
                return obj.internal
            raise TypeError('Could not serialise object %r' % obj)

        source_rse_id = request.get('source_rse_id')
        if not source_rse_id:
            try:
                source_rses_of_request = source_rses[request['scope']][request['name']][request['dest_rse_id']]
                source_rse_id = min(source_rses_of_request, key=source_rses_of_request.get)
            except KeyError:
                pass
        activity_limit = transfer_limits.get(request['attributes']['activity'], {})
        all_activities_limit = transfer_limits.get('all_activities', {})
        limit_found = False
        if throttler_mode:
            if direction == 'source':
                if all_activities:
                    if all_activities_limit.get(source_rse_id):
                        limit_found = True
                else:
                    if activity_limit.get(source_rse_id):
                        limit_found = True
            elif direction == 'destination':
                if all_activities:
                    if all_activities_limit.get(request['dest_rse_id']):
                        limit_found = True
                else:
                    if activity_limit.get(request['dest_rse_id']):
                        limit_found = True
        request['state'] = RequestState.WAITING if limit_found else RequestState.QUEUED

        new_request = {'request_type': request['request_type'],
                       'scope': request['scope'],
                       'name': request['name'],
                       'dest_rse_id': request['dest_rse_id'],
                       'source_rse_id': source_rse_id,
                       'attributes': json.dumps(request['attributes'], default=temp_serializer),
                       'state': request['state'],
                       'rule_id': request['rule_id'],
                       'activity': request['attributes']['activity'],
                       'bytes': request['attributes']['bytes'],
                       'md5': request['attributes']['md5'],
                       'adler32': request['attributes']['adler32'],
                       'account': request.get('account', None),
                       'priority': request['attributes'].get('priority', None),
                       'requested_at': request.get('requested_at', None),
                       'retry_count': request['retry_count']}
        if 'previous_attempt_id' in request and 'retry_count' in request:
            new_request['previous_attempt_id'] = request['previous_attempt_id']
            new_request['id'] = request['request_id']
        else:
            new_request['id'] = generate_uuid()
        new_requests.append(new_request)

        if 'sources' in request and request['sources']:
            for source in request['sources']:
                sources.append({'request_id': new_request['id'],
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

        payload = {'request-id': new_request['id'],
                   'request-type': str(request['request_type']).lower(),
                   'scope': request['scope'].external,
                   'name': request['name'],
                   'dst-rse-id': request['dest_rse_id'],
                   'dst-rse': dest_rse_name,
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
    return new_requests


@read_session
def get_next(request_type, state, limit=100, older_than=None, rse_id=None, activity=None,
             total_workers=0, worker_number=0, mode_all=False, hash_variable='id',
             activity_shares=None, session=None):
    """
    Retrieve the next requests matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param request_type:      Type of the request as a string or list of strings.
    :param state:             State of the request as a string or list of strings.
    :param limit:             Integer of requests to retrieve.
    :param older_than:        Only select requests older than this DateTime.
    :param rse_id:            The RSE to filter on.
    :param activity:          The activity to filter on.
    :param total_workers:     Number of total workers.
    :param worker_number:     Id of the executing worker.
    :param mode_all:          If set to True the function returns everything, if set to False returns list of dictionaries  {'request_id': x, 'external_host': y, 'external_id': z}.
    :param hash_variable:     The variable to use to perform the partitioning. By default it uses the request id.
    :param activity_shares:   Activity shares dictionary, with number of requests
    :param session:           Database session to use.
    :returns:                 Request as a dictionary.
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

        if rse_id:
            query = query.filter(models.Request.dest_rse_id == rse_id)

        if share:
            query = query.filter(models.Request.activity == share)
        elif activity:
            query = query.filter(models.Request.activity == activity)

        query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable=hash_variable)

        if share:
            query = query.limit(activity_shares[share])
        else:
            query = query.limit(limit)

        query_result = query.all()
        if query_result:
            if mode_all:
                for res in query_result:
                    res_dict = dict(res)
                    res_dict.pop('_sa_instance_state')
                    res_dict['request_id'] = res_dict['id']
                    res_dict['attributes'] = json.loads(str(res_dict['attributes']))

                    dst_id = res_dict['dest_rse_id']
                    src_id = res_dict['source_rse_id']
                    res_dict['dest_rse'] = get_rse_name(rse_id=dst_id, session=session) if dst_id is not None else None
                    res_dict['source_rse'] = get_rse_name(rse_id=src_id, session=session) if src_id is not None else None

                    result.append(res_dict)
            else:
                for res in query_result:
                    result.append({'request_id': res.id, 'external_host': res.external_host, 'external_id': res.external_id})

    return result


@read_session
def query_request(request_id, transfertool='fts3', session=None):
    """
    Query the status of a request.

    :param request_id:    Request-ID as a 32 character hex string.
    :param transfertool:  Transfertool name as a string.
    :param session:       Database session to use.
    :returns:             Request status information as a dictionary.
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
            response = FTS3Transfertool(external_host=req['external_host']).query(transfer_ids=[req['external_id']], details=False)
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


@read_session
def query_request_details(request_id, transfertool='fts3', session=None):
    """
    Query the detailed status of a request. Can also be done after the
    external transfer has finished.

    :param request_id:    Request-ID as a 32 character hex string.
    :param transfertool:  Transfertool name as a string.
    :param session:       Database session to use.
    :returns:             Detailed request status information as a dictionary.
    """

    record_counter('core.request.query_request_details')

    req = get_request(request_id, session=session)

    if not req:
        return

    if transfertool == 'fts3':
        ts = time.time()
        tmp = FTS3Transfertool(external_host=req['external_host']).query(transfer_ids=[req['external_id']], details=True)
        record_timer('core.request.query_details_fts3', (time.time() - ts) * 1000)
        return tmp

    raise NotImplementedError


@transactional_session
def set_request_state(request_id, new_state, transfer_id=None, transferred_at=None, started_at=None, staging_started_at=None, staging_finished_at=None, src_rse_id=None, err_msg=None, session=None):
    """
    Update the state of a request. Fails silently if the request_id does not exist.

    :param request_id:   Request-ID as a 32 character hex string.
    :param new_state:    New state as string.
    :param transfer_id:  External transfer job id as a string.
    :param transferred_at: Transferred at timestamp
    :param started_at: Started at timestamp
    :param staging_started_at: Timestamp indicating the moment the stage beggins
    :param staging_finished_at: Timestamp indicating the moment the stage ends
    :param session:      Database session to use.
    """

    # TODO: Should this be a private method?

    record_counter('core.request.set_request_state')

    rowcount = 0
    try:
        update_items = {'state': new_state, 'updated_at': datetime.datetime.utcnow()}
        if transferred_at:
            update_items['transferred_at'] = transferred_at
        if started_at:
            update_items['started_at'] = started_at
        if staging_started_at:
            update_items['staging_started_at'] = staging_started_at
        if staging_finished_at:
            update_items['staging_finished_at'] = staging_finished_at
        if src_rse_id:
            update_items['source_rse_id'] = src_rse_id
        if err_msg:
            update_items['err_msg'] = err_msg

        if transfer_id:
            rowcount = session.query(models.Request).filter_by(id=request_id, external_id=transfer_id).update(update_items, synchronize_session=False)
        else:
            if new_state in [RequestState.FAILED, RequestState.DONE, RequestState.LOST]:
                logging.error("Request %s should not be updated to 'Failed' or 'Done' without external transfer_id" % request_id)
            else:
                rowcount = session.query(models.Request).filter_by(id=request_id).update(update_items, synchronize_session=False)
    except IntegrityError as error:
        raise RucioException(error.args)

    if not rowcount:
        raise UnsupportedOperation("Request %s state cannot be updated." % request_id)


@transactional_session
def set_requests_state(request_ids, new_state, session=None):
    """
    Bulk update the state of requests. Fails silently if the request_id does not exist.

    :param request_ids:  List of (Request-ID as a 32 character hex string).
    :param new_state:    New state as string.
    :param session:      Database session to use.
    """

    record_counter('core.request.set_requests_state')

    try:
        for request_id in request_ids:
            set_request_state(request_id, new_state, session=session)
    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def touch_requests_by_rule(rule_id, session=None):
    """
    Update the update time of requests in a rule. Fails silently if no requests on this rule.

    :param rule_id:  Rule-ID as a 32 character hex string.
    :param session:  Database session to use.
    """

    record_counter('core.request.touch_requests_by_rule')

    try:
        session.query(models.Request).with_hint(models.Request, "INDEX(REQUESTS REQUESTS_RULEID_IDX)", 'oracle')\
                                     .filter_by(rule_id=rule_id)\
                                     .filter(models.Request.state.in_([RequestState.FAILED, RequestState.DONE, RequestState.LOST, RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES]))\
                                     .filter(models.Request.updated_at < datetime.datetime.utcnow())\
                                     .update({'updated_at': datetime.datetime.utcnow() + datetime.timedelta(minutes=20)}, synchronize_session=False)
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_request(request_id, session=None):
    """
    Retrieve a request by its ID.

    :param request_id:  Request-ID as a 32 character hex string.
    :param session:     Database session to use.
    :returns:           Request as a dictionary.
    """

    try:
        tmp = session.query(models.Request).filter_by(id=request_id).first()

        if not tmp:
            return
        else:
            tmp = dict(tmp)
            tmp.pop('_sa_instance_state')
            return tmp
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_requests_by_transfer(external_host, transfer_id, session=None):
    """
    Retrieve requests by its transfer ID.

    :param request_host:  Name of the external host.
    :param transfer_id:   External transfer job id as a string.
    :param session:       Database session to use.
    :returns:             List of Requests.
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
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_request_by_did(scope, name, rse_id, request_type=None, session=None):
    """
    Retrieve a request by its DID for a destination RSE.

    :param scope:          The scope of the data identifier.
    :param name:           The name of the data identifier.
    :param rse_id:         The destination RSE ID of the request.
    :param request_type:   The type of request as rucio.db.sqla.constants.RequestType.
    :param session:        Database session to use.
    :returns:              Request as a dictionary.
    """

    record_counter('core.request.get_request_by_did')
    try:
        tmp = session.query(models.Request).filter_by(scope=scope,
                                                      name=name)

        tmp = tmp.filter_by(dest_rse_id=rse_id)

        if request_type:
            tmp = tmp.filter_by(request_type=request_type)

        tmp = tmp.first()
        if not tmp:
            raise RequestNotFound()
        else:
            tmp = dict(tmp)
            tmp.pop('_sa_instance_state')

            tmp['source_rse'] = get_rse_name(rse_id=tmp['source_rse_id'], session=session) if tmp['source_rse_id'] is not None else None
            tmp['dest_rse'] = get_rse_name(rse_id=tmp['dest_rse_id'], session=session) if tmp['dest_rse_id'] is not None else None

            return tmp
    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def archive_request(request_id, session=None):
    """
    Move a request to the history table.

    :param request_id:  Request-ID as a 32 character hex string.
    :param session:     Database session to use.
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
                                                                requested_at=req['requested_at'],
                                                                submitted_at=req['submitted_at'],
                                                                staging_started_at=req['staging_started_at'],
                                                                staging_finished_at=req['staging_finished_at'],
                                                                started_at=req['started_at'],
                                                                estimated_started_at=req['estimated_started_at'],
                                                                estimated_at=req['estimated_at'],
                                                                transferred_at=req['transferred_at'],
                                                                estimated_transferred_at=req['estimated_transferred_at'])
        hist_request.save(session=session)
        try:
            time_diff = req['updated_at'] - req['created_at']
            time_diff_s = time_diff.seconds + time_diff.days * 24 * 3600
            record_timer('core.request.archive_request.%s' % req['activity'].replace(' ', '_'), time_diff_s)
            session.query(models.Source).filter_by(request_id=request_id).delete()
            session.query(models.Request).filter_by(id=request_id).delete()
        except IntegrityError as error:
            raise RucioException(error.args)


@transactional_session
def cancel_request_did(scope, name, dest_rse_id, request_type=RequestType.TRANSFER, session=None):
    """
    Cancel a request based on a DID and request type.

    :param scope:         Data identifier scope as a string.
    :param name:          Data identifier name as a string.
    :param dest_rse_id:   RSE id as a string.
    :param request_type:  Type of the request.
    :param session:       Database session to use.
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
            logging.warn('Tried to cancel non-existant request for DID %s:%s at RSE %s' % (scope, name, get_rse_name(rse_id=dest_rse_id, session=session)))
    except IntegrityError as error:
        raise RucioException(error.args)

    transfertool_map = {}
    for req in reqs:
        # is there a transfer already in FTS3? if so, try to cancel it
        if req[1] is not None:
            try:
                if req[2] not in transfertool_map:
                    transfertool_map[req[2]] = FTS3Transfertool(external_host=req[2])
                transfertool_map[req[2]].cancel(transfer_ids=[req[1]])
            except Exception as error:
                logging.warn('Could not cancel FTS3 transfer %s on %s: %s' % (req[1], req[2], str(error)))
        archive_request(request_id=req[0], session=session)


def cancel_request_external_id(transfer_id, transfer_host):
    """
    Cancel a request based on external transfer id.

    :param transfer_id:    External-ID as a 32 character hex string.
    :param transfer_host:  Name of the external host.
    """

    record_counter('core.request.cancel_request_external_id')
    try:
        FTS3Transfertool(external_host=transfer_host).cancel(transfer_ids=[transfer_id])
    except Exception:
        raise RucioException('Could not cancel FTS3 transfer %s on %s: %s' % (transfer_id, transfer_host, traceback.format_exc()))


@read_session
def list_stagein_requests_and_source_replicas(total_workers=0, worker_number=0, limit=None, activity=None, older_than=None, rses=None, session=None):
    """
    List stagein requests with source replicas

    :param total_workers:         Number of total workers.
    :param worker_number:         Id of the executing worker.
    :param limit:            Integer of requests to retrieve.
    :param activity:         Activity to be selected.
    :param older_than:       Only select requests older than this DateTime.
    :param rses:             List of rse_id to select requests.
    :param session:          Database session to use.
    :returns:                List.
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

    sub_requests = filter_thread_work(session=session, query=sub_requests, total_threads=total_workers, thread_id=worker_number)

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

    :param request_id:  Request-ID as a 32 character hex string.
    :param rse_id:      RSE ID as a 32 character hex string.
    :param session:     Database session to use.
    :returns:           Sources as a dictionary.
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
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_heavy_load_rses(threshold, session=None):
    """
    Retrieve heavy load rses.

    :param threshold:  Threshold as an int.
    :param session:    Database session to use.
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
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_stats_by_activity_direction_state(state, all_activities=False, direction='destination', session=None):
    """
    Retrieve statistics about requests by destination, activity and state.

    :param state:           Request state.
    :param all_activities:  Boolean whether requests are grouped by activity or if activities are ignored.
    :param direction:       Direction if requests are grouped by source RSE or destination RSE.
    :param session:         Database session to use.
    :returns:               List of (activity, dest_rse_id, state, counter).
    """

    if type(state) is not list:
        state = [state, state]

    try:
        subquery = None
        inner_select = [models.Request.account, models.Request.state,
                        func.count(1).label('counter')]
        if direction == 'destination' and all_activities:
            inner_select.append(models.Request.dest_rse_id)
            group_by = (models.Request.dest_rse_id, )
        elif direction == 'source' and all_activities:
            inner_select.append(models.Request.source_rse_id)
            group_by = (models.Request.source_rse_id, )
        elif direction == 'destination' and not all_activities:
            inner_select.append(models.Request.activity)
            inner_select.append(models.Request.dest_rse_id)
            group_by = (models.Request.dest_rse_id, models.Request.activity)
        elif direction == 'source' and not all_activities:
            inner_select.append(models.Request.activity)
            inner_select.append(models.Request.source_rse_id)
            group_by = (models.Request.source_rse_id, models.Request.activity)

        subquery = session.query(*inner_select)\
                          .with_hint(models.Request, "INDEX(REQUESTS REQUESTS_TYP_STA_UPD_IDX)", 'oracle')\
                          .filter(models.Request.state.in_(state))\
                          .group_by(models.Request.account,
                                    models.Request.state)\
                          .group_by(*group_by)\
                          .subquery()

        outer_select = [subquery.c.account,
                        subquery.c.state,
                        models.RSE.rse,
                        subquery.c.counter]
        if direction == 'destination':
            outer_select.append(subquery.c.dest_rse_id)
            filter_condition = (models.RSE.id == subquery.c.dest_rse_id)
        elif direction == 'source':
            outer_select.append(subquery.c.source_rse_id)
            filter_condition = (models.RSE.id == subquery.c.source_rse_id)

        if not all_activities:
            outer_select.append(subquery.c.activity)

        return session.query(*outer_select)\
                      .with_hint(models.RSE, "INDEX(RSES RSES_PK)", 'oracle')\
                      .filter(filter_condition).all()

    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def release_waiting_requests_per_deadline(rse_id=None, deadline=1, session=None):
    """
    Release waiting requests that were waiting too long and exceeded the maximum waiting time to be released.
    If the DID of a request is attached to a dataset, the oldest requested_at date of all requests related to the dataset will be used for checking and all requests of this dataset will be released.
    :param rse_id:           The source RSE id.
    :param deadline:         Maximal waiting time in hours until a dataset gets released.
    :param session:          The database session.
    """
    amount_released_requests = 0
    if deadline:
        grouped_requests_subquery, filtered_requests_subquery = create_base_query_grouped_fifo(rse_id, filter_by_rse='source', session=session)
        old_requests_subquery = session.query(grouped_requests_subquery.c.name,
                                              grouped_requests_subquery.c.scope,
                                              grouped_requests_subquery.c.oldest_requested_at)\
                                       .filter(grouped_requests_subquery.c.oldest_requested_at < datetime.datetime.now() - datetime.timedelta(hours=deadline))\
                                       .subquery()
        old_requests_subquery = session.query(filtered_requests_subquery.c.id)\
                                       .join(old_requests_subquery, and_(filtered_requests_subquery.c.dataset_name == old_requests_subquery.c.name, filtered_requests_subquery.c.dataset_scope == old_requests_subquery.c.scope))
        old_requests_subquery = old_requests_subquery.subquery()
        statement = update(models.Request).where(models.Request.id.in_(old_requests_subquery)).values(state=RequestState.QUEUED)
        amount_released_requests = session.execute(statement).rowcount
    return amount_released_requests


@transactional_session
def release_waiting_requests_per_free_volume(rse_id, volume=None, session=None):
    """
    Release waiting requests if they fit in available transfer volume. If the DID of a request is attached to a dataset, the volume will be checked for the whole dataset as all requests related to this dataset will be released.

    :param rse_id:  The destination RSE id.
    :param volume:  The maximum volume in bytes that should be transfered.
    :param session: The database session.
    """

    dialect = session.bind.dialect.name
    sum_volume_active_subquery = None
    if dialect == 'mysql' or dialect == 'sqlite':
        sum_volume_active_subquery = session.query(func.ifnull(func.sum(models.Request.bytes), 0).label('sum_bytes'))\
                                            .filter(and_(or_(models.Request.state == RequestState.SUBMITTED, models.Request.state == RequestState.QUEUED),
                                                         models.Request.dest_rse_id == rse_id))
    elif dialect == 'postgresql':
        sum_volume_active_subquery = session.query(func.coalesce(func.sum(models.Request.bytes), 0).label('sum_bytes'))\
                                            .filter(and_(or_(models.Request.state == RequestState.SUBMITTED, models.Request.state == RequestState.QUEUED),
                                                         models.Request.dest_rse_id == rse_id))
    elif dialect == 'oracle':
        sum_volume_active_subquery = session.query(func.nvl(func.sum(models.Request.bytes), 0).label('sum_bytes'))\
                                            .filter(and_(or_(models.Request.state == RequestState.SUBMITTED, models.Request.state == RequestState.QUEUED),
                                                         models.Request.dest_rse_id == rse_id))
    sum_volume_active_subquery = sum_volume_active_subquery.subquery()

    grouped_requests_subquery, filtered_requests_subquery = create_base_query_grouped_fifo(rse_id, filter_by_rse='destination', session=session)

    cumulated_volume_subquery = session.query(grouped_requests_subquery.c.name,
                                              grouped_requests_subquery.c.scope,
                                              func.sum(grouped_requests_subquery.c.volume).over(order_by=grouped_requests_subquery.c.oldest_requested_at).label('cum_volume'))\
                                       .filter(grouped_requests_subquery.c.volume <= volume - sum_volume_active_subquery.c.sum_bytes)\
                                       .subquery()

    cumulated_volume_subquery = session.query(filtered_requests_subquery.c.id)\
                                       .join(cumulated_volume_subquery, and_(filtered_requests_subquery.c.dataset_name == cumulated_volume_subquery.c.name, filtered_requests_subquery.c.dataset_scope == cumulated_volume_subquery.c.scope))\
                                       .filter(cumulated_volume_subquery.c.cum_volume <= volume - sum_volume_active_subquery.c.sum_bytes)\
                                       .subquery()

    statement = update(models.Request).where(models.Request.id.in_(cumulated_volume_subquery)).values(state=RequestState.QUEUED)
    amount_released_requests = session.execute(statement).rowcount
    return amount_released_requests


@read_session
def create_base_query_grouped_fifo(rse_id, filter_by_rse='destination', session=None):
    """
    Build the sqlalchemy queries to filter relevant requests and to group them in datasets.
    Group requests either by same destination RSE or source RSE.

    :param rse_id:           The RSE id.
    :param filter_by_rse:    Decide whether to filter by transfer destination or source RSE (`destination`, `source`).
    :param session:          The database session.
    """
    # query DIDs that are attached to a collection and add a column indicating the order of attachment in case of mulitple attachments
    attachment_order_subquery = session.query(models.DataIdentifierAssociation.child_name, models.DataIdentifierAssociation.child_scope, models.DataIdentifierAssociation.name, models.DataIdentifierAssociation.scope,
                                              func.row_number().over(partition_by=(models.DataIdentifierAssociation.child_name, models.DataIdentifierAssociation.child_scope),
                                                                     order_by=models.DataIdentifierAssociation.created_at).label('order_of_attachment'))\
                                       .subquery()

    # query transfer requests and join with according datasets
    filtered_requests_subquery = None
    grouped_requests_subquery = None
    dialect = session.bind.dialect.name
    if dialect == 'mysql' or dialect == 'sqlite':
        filtered_requests_subquery = session.query(models.Request.id.label('id'),
                                                   func.ifnull(attachment_order_subquery.c.name, models.Request.name).label('dataset_name'),
                                                   func.ifnull(attachment_order_subquery.c.scope, models.Request.scope).label('dataset_scope'))

        combined_attached_unattached_requests = session.query(func.ifnull(attachment_order_subquery.c.scope, models.Request.scope).label('scope'),
                                                              func.ifnull(attachment_order_subquery.c.name, models.Request.name).label('name'),
                                                              models.Request.bytes,
                                                              models.Request.requested_at)
    elif dialect == 'postgresql':
        filtered_requests_subquery = session.query(models.Request.id.label('id'),
                                                   func.coalesce(attachment_order_subquery.c.name, models.Request.name).label('dataset_name'),
                                                   func.coalesce(attachment_order_subquery.c.scope, models.Request.scope).label('dataset_scope'))

        combined_attached_unattached_requests = session.query(func.coalesce(attachment_order_subquery.c.scope, models.Request.scope).label('scope'),
                                                              func.coalesce(attachment_order_subquery.c.name, models.Request.name).label('name'),
                                                              models.Request.bytes,
                                                              models.Request.requested_at)
    elif dialect == 'oracle':
        filtered_requests_subquery = session.query(models.Request.id.label('id'),
                                                   func.nvl(attachment_order_subquery.c.name, models.Request.name).label('dataset_name'),
                                                   func.nvl(attachment_order_subquery.c.scope, models.Request.scope).label('dataset_scope'))

        combined_attached_unattached_requests = session.query(func.nvl(attachment_order_subquery.c.scope, models.Request.scope).label('scope'),
                                                              func.nvl(attachment_order_subquery.c.name, models.Request.name).label('name'),
                                                              models.Request.bytes,
                                                              models.Request.requested_at)

    filtered_requests_subquery = filtered_requests_subquery.join(attachment_order_subquery, and_(models.Request.name == attachment_order_subquery.c.child_name,
                                                                                                 models.Request.scope == attachment_order_subquery.c.child_scope,
                                                                                                 attachment_order_subquery.c.order_of_attachment == 1), isouter=True)

    combined_attached_unattached_requests = combined_attached_unattached_requests.join(attachment_order_subquery, and_(models.Request.name == attachment_order_subquery.c.child_name,
                                                                                                                       models.Request.scope == attachment_order_subquery.c.child_scope,
                                                                                                                       attachment_order_subquery.c.order_of_attachment == 1), isouter=True)

    # depending if throttler is used for reading or writing
    if filter_by_rse == 'source':
        filtered_requests_subquery = filtered_requests_subquery.filter(models.Request.source_rse_id == rse_id)
        combined_attached_unattached_requests = combined_attached_unattached_requests.filter(models.Request.source_rse_id == rse_id)
    elif filter_by_rse == 'destination':
        filtered_requests_subquery = filtered_requests_subquery.filter(models.Request.dest_rse_id == rse_id)
        combined_attached_unattached_requests = combined_attached_unattached_requests.filter(models.Request.dest_rse_id == rse_id)

    filtered_requests_subquery = filtered_requests_subquery.filter(models.Request.state == RequestState.WAITING).subquery()

    combined_attached_unattached_requests = combined_attached_unattached_requests.filter(models.Request.state == RequestState.WAITING).subquery()

    # group requests and calculate properties like oldest requested_at, amount of children, volume
    grouped_requests_subquery = session.query(func.sum(combined_attached_unattached_requests.c.bytes).label('volume'),
                                              func.min(combined_attached_unattached_requests.c.requested_at).label('oldest_requested_at'),
                                              func.count().label('amount_childs'),
                                              combined_attached_unattached_requests.c.name,
                                              combined_attached_unattached_requests.c.scope)\
                                       .group_by(combined_attached_unattached_requests.c.scope, combined_attached_unattached_requests.c.name)\
                                       .subquery()
    return grouped_requests_subquery, filtered_requests_subquery


@transactional_session
def release_waiting_requests_fifo(rse_id, activity=None, count=None, account=None, direction='destination', session=None):
    """
    Release waiting requests. Transfer requests that were requested first, get released first (FIFO).

    :param rse_id:           The RSE id.
    :param activity:         The activity.
    :param count:            The count to be released.
    :param account:          The account name whose requests to release.
    :param direction:        Direction if requests are grouped by source RSE or destination RSE.
    :param session:          The database session.
    """

    dialect = session.bind.dialect.name
    rowcount = 0
    if dialect == 'mysql':
        subquery = session.query(models.Request.id)\
                          .filter(models.Request.state == RequestState.WAITING)\
                          .order_by(asc(models.Request.requested_at))
        if direction == 'destination':
            subquery = subquery.filter(models.Request.dest_rse_id == rse_id)
        elif direction == 'source':
            subquery = subquery.filter(models.Request.source_rse_id == rse_id)

        if activity:
            subquery = subquery.filter(models.Request.activity == activity)
        if account:
            subquery = subquery.filter(models.Request.account == account)
        subquery = subquery.limit(count).subquery()

        # join because IN and LIMIT cannot be used together
        subquery = session.query(models.Request.id)\
                          .join(subquery, models.Request.id == subquery.c.id).subquery()
        # wrap select to update and select from the same table
        subquery = session.query(subquery.c.id).subquery()
        rowcount = session.query(models.Request)\
                          .filter(models.Request.id.in_(subquery))\
                          .update({'state': RequestState.QUEUED},
                                  synchronize_session=False)
    else:
        subquery = session.query(models.Request.id)\
                          .filter(models.Request.state == RequestState.WAITING)
        if direction == 'destination':
            subquery = subquery.filter(models.Request.dest_rse_id == rse_id)
        elif direction == 'source':
            subquery = subquery.filter(models.Request.source_rse_id == rse_id)

        if activity:
            subquery = subquery.filter(models.Request.activity == activity)
        if account:
            subquery = subquery.filter(models.Request.account == account)

        subquery = subquery.order_by(asc(models.Request.requested_at))\
                           .limit(count)
        rowcount = session.query(models.Request)\
                          .filter(models.Request.id.in_(subquery))\
                          .update({'state': RequestState.QUEUED},
                                  synchronize_session=False)
    return rowcount


@transactional_session
def release_waiting_requests_grouped_fifo(rse_id, count=None, direction='destination', deadline=1, volume=0, session=None):
    """
    Release waiting requests. Transfer requests that were requested first, get released first (FIFO).
    Also all requests to DIDs that are attached to the same dataset get released, if one children of the dataset is choosed to be released (Grouped FIFO).

    :param rse_id:           The RSE id.
    :param count:            The count to be released. If None, release all waiting requests.
    :param direction:        Direction if requests are grouped by source RSE or destination RSE.
    :param deadline:         Maximal waiting time in hours until a dataset gets released.
    :param volume:           The maximum volume in bytes that should be transfered.
    :param session:          The database session.
    """

    amount_updated_requests = 0

    # Release requests that exceeded waiting time
    if deadline:
        amount_updated_requests = release_waiting_requests_per_deadline(rse_id=rse_id, deadline=deadline, session=session)
        count = count - amount_updated_requests

    grouped_requests_subquery, filtered_requests_subquery = create_base_query_grouped_fifo(rse_id=rse_id, filter_by_rse=direction, session=session)

    # cumulate amount of children per dataset and combine with each request and only keep requests that dont exceed the limit
    cumulated_children_subquery = session.query(grouped_requests_subquery.c.name,
                                                grouped_requests_subquery.c.scope,
                                                grouped_requests_subquery.c.amount_childs,
                                                grouped_requests_subquery.c.oldest_requested_at,
                                                func.sum(grouped_requests_subquery.c.amount_childs).over(order_by=(grouped_requests_subquery.c.oldest_requested_at)).label('cum_amount_childs'))\
                                         .subquery()
    cumulated_children_subquery = session.query(filtered_requests_subquery.c.id)\
                                         .join(cumulated_children_subquery, and_(filtered_requests_subquery.c.dataset_name == cumulated_children_subquery.c.name, filtered_requests_subquery.c.dataset_scope == cumulated_children_subquery.c.scope))\
                                         .filter(cumulated_children_subquery.c.cum_amount_childs - cumulated_children_subquery.c.amount_childs < count)\
                                         .subquery()

    # needed for mysql to update and select from the same table
    cumulated_children_subquery = session.query(cumulated_children_subquery.c.id).subquery()

    statement = update(models.Request).where(models.Request.id.in_(cumulated_children_subquery)).values(state=RequestState.QUEUED)

    amount_updated_requests += session.execute(statement).rowcount

    # release requests where the whole datasets volume fits in the available volume space
    if volume:
        amount_updated_requests += release_waiting_requests_per_free_volume(rse_id=rse_id, volume=volume, session=session)

    return amount_updated_requests


@transactional_session
def release_all_waiting_requests(rse_id, activity=None, account=None, direction='destination', session=None):
    """
    Release all waiting requests per destination RSE.

    :param rse_id:           The RSE id.
    :param activity:         The activity.
    :param account:          The account name whose requests to release.
    :param direction:        Direction if requests are grouped by source RSE or destination RSE.
    :param session:          The database session.
    """
    try:
        rowcount = 0

        query = session.query(models.Request)
        if direction == 'destination':
            query = query.filter_by(dest_rse_id=rse_id, state=RequestState.WAITING)
        elif direction == 'source':
            query = query.filter_by(src_rse_id=rse_id, state=RequestState.WAITING)

        if activity:
            query = query.filter_by(activity=activity)
        if account:
            query = query.filter_by(account=account)
        rowcount = query.update({'state': RequestState.QUEUED}, synchronize_session=False)
        return rowcount
    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def update_requests_priority(priority, filter, session=None):
    """
    Update priority of requests.

    :param priority:  The priority as an integer from 1 to 5.
    :param filter:    Dictionary such as {'rule_id': rule_id, 'request_id': request_id, 'older_than': time_stamp, 'activities': [activities]}.
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

        transfertool_map = {}
        for item in query.all():
            try:
                if item[2] not in transfertool_map:
                    transfertool_map[item[2]] = FTS3Transfertool(external_host=item[2])
                res = transfertool_map[item[2]].update_priority(transfer_id=item[1], priority=priority)
            except Exception:
                logging.debug("Failed to boost request %s priority: %s" % (item[0], traceback.format_exc()))
            else:
                logging.debug("Update request %s priority to %s: %s" % (item[0], priority, res['http_message']))
    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def update_request_state(response, logging_prepend_str=None, session=None):
    """
    Used by poller and consumer to update the internal state of requests,
    after the response by the external transfertool.

    :param response:              The transfertool response dictionary, retrieved via request.query_request().
    :param logging_prepend_str:   String to prepend to the logging
    :param session:               The database session to use.
    :returns commit_or_rollback:  Boolean.
    """

    prepend_str = ''
    if logging_prepend_str:
        prepend_str = logging_prepend_str
    try:
        if not response['new_state']:
            __touch_request(response['request_id'], session=session)
            return False
        else:
            request = get_request(response['request_id'], session=session)
            if request and request['external_id'] == response['transfer_id'] and request['state'] != response['new_state']:
                response['submitted_at'] = request.get('submitted_at', None)
                response['external_host'] = request['external_host']
                transfer_id = response['transfer_id'] if 'transfer_id' in response else None
                logging.info(prepend_str + 'UPDATING REQUEST %s FOR TRANSFER %s STATE %s' % (str(response['request_id']), transfer_id, str(response['new_state'])))

                job_m_replica = response.get('job_m_replica', None)
                src_url = response.get('src_url', None)
                src_rse = response.get('src_rse', None)
                src_rse_id = response.get('src_rse_id', None)
                staging_started_at = response.get('staging_start', None)
                staging_finished_at = response.get('staging_finished', None)
                started_at = response.get('started_at', None)
                transferred_at = response.get('transferred_at', None)
                if job_m_replica and (str(job_m_replica).lower() == str('true')) and src_url:
                    try:
                        src_rse_name, src_rse_id = __get_source_rse(response['request_id'], src_url, session=session)
                    except Exception:
                        logging.warn(prepend_str + 'Cannot get correct RSE for source url: %s(%s)' % (src_url, traceback.format_exc()))
                        src_rse_name = None
                    if src_rse_name and src_rse_name != src_rse:
                        response['src_rse'] = src_rse_name
                        response['src_rse_id'] = src_rse_id
                        logging.debug(prepend_str + 'Correct RSE: %s for source surl: %s' % (src_rse_name, src_url))
                err_msg = get_transfer_error(response['new_state'], response['reason'] if 'reason' in response else None)

                set_request_state(response['request_id'],
                                  response['new_state'],
                                  transfer_id=transfer_id,
                                  started_at=started_at,
                                  staging_started_at=staging_started_at,
                                  staging_finished_at=staging_finished_at,
                                  transferred_at=transferred_at,
                                  src_rse_id=src_rse_id,
                                  err_msg=err_msg,
                                  session=session)

                add_monitor_message(request, response, session=session)
                return True
            elif not request:
                logging.debug(prepend_str + "Request %s doesn't exist, will not update" % (response['request_id']))
                return False
            elif request['external_id'] != response['transfer_id']:
                logging.warning(prepend_str + "Response %s with transfer id %s is different from the request transfer id %s, will not update" % (response['request_id'], response['transfer_id'], request['external_id']))
                return False
            else:
                logging.debug(prepend_str + "Request %s is already in %s state, will not update" % (response['request_id'], response['new_state']))
                return False
    except UnsupportedOperation as error:
        logging.warning(prepend_str + "Request %s doesn't exist - Error: %s" % (response['request_id'], str(error).replace('\n', '')))
        return False
    except Exception:
        logging.critical(prepend_str + traceback.format_exc())


@read_session
def add_monitor_message(request, response, session=None):
    """
    Take a request and transfer response and create a message for hermes.

    :param request:   The request to create the message for.
    :param response:  The transfertool response dictionary, retrieved via request.query_request().
    :param session:   The database session to use.
    """

    if request['request_type']:
        transfer_status = '%s-%s' % (request['request_type'], response['new_state'])
    else:
        transfer_status = 'transfer-%s' % (response['new_state'])
    transfer_status = transfer_status.lower()

    activity = response.get('activity', None)
    src_type = response.get('src_type', None)
    src_rse = response.get('src_rse', None)
    src_url = response.get('src_url', None)
    dst_type = response.get('dst_type', None)
    dst_rse = response.get('dst_rse', None)
    dst_url = response.get('dst_url', None)
    dst_protocol = dst_url.split(':')[0] if dst_url else None
    reason = response.get('reason', None)
    duration = response.get('duration', -1)
    filesize = response.get('filesize', None)
    md5 = response.get('md5', None)
    adler32 = response.get('adler32', None)
    created_at = response.get('created_at', None)
    submitted_at = response.get('submitted_at', None)
    started_at = response.get('started_at', None)
    transferred_at = response.get('transferred_at', None)
    account = response.get('account', None)

    if response['external_host']:
        transfer_link = '%s/fts3/ftsmon/#/job/%s' % (response['external_host'].replace('8446', '8449'), response['transfer_id'])
    else:
        # for LOST request, response['external_host'] maybe is None
        transfer_link = None

    message = {'activity': activity,
               'request-id': response['request_id'],
               'duration': duration,
               'checksum-adler': adler32,
               'checksum-md5': md5,
               'file-size': filesize,
               'bytes': filesize,
               'guid': None,
               'previous-request-id': response['previous_attempt_id'],
               'protocol': dst_protocol,
               'scope': response['scope'],
               'name': response['name'],
               'src-type': src_type,
               'src-rse': src_rse,
               'src-url': src_url,
               'dst-type': dst_type,
               'dst-rse': dst_rse,
               'dst-url': dst_url,
               'reason': reason,
               'transfer-endpoint': response['external_host'],
               'transfer-id': response['transfer_id'],
               'transfer-link': transfer_link,
               'created_at': str(created_at) if created_at else None,
               'submitted_at': str(submitted_at) if submitted_at else None,
               'started_at': str(started_at) if started_at else None,
               'transferred_at': str(transferred_at) if transferred_at else None,
               'tool-id': 'rucio-conveyor',
               'account': account}

    src_id = response['src_rse_id']
    vo = get_rse_vo(rse_id=src_id)
    if vo != 'def':
        message['vo'] = vo

    add_message(transfer_status, message, session=session)


def get_transfer_error(state, reason=None):
    """
    Transform a specific RequestState to an error message

    :param state:   State of the request.
    :param reason:  Reason of the state.
    :returns:       Error message
    """
    err_msg = None
    if state in [RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES]:
        err_msg = '%s:%s' % (RequestErrMsg.NO_SOURCES, state)
    elif state in [RequestState.SUBMISSION_FAILED]:
        err_msg = '%s:%s' % (RequestErrMsg.SUBMISSION_FAILED, state)
    elif state in [RequestState.SUBMITTING]:
        err_msg = '%s:%s' % (RequestErrMsg.SUBMISSION_FAILED, "Too long time in submitting state")
    elif state in [RequestState.LOST]:
        err_msg = '%s:%s' % (RequestErrMsg.TRANSFER_FAILED, "Transfer job on FTS is lost")
    elif state in [RequestState.FAILED]:
        err_msg = '%s:%s' % (RequestErrMsg.TRANSFER_FAILED, reason)
    elif state in [RequestState.MISMATCH_SCHEME]:
        err_msg = '%s:%s' % (RequestErrMsg.MISMATCH_SCHEME, state)
    return err_msg


@transactional_session
def __touch_request(request_id, session=None):
    """
    Update the timestamp of a request. Fails silently if the request_id does not exist.

    :param request_id:  Request-ID as a 32 character hex string.
    :param session:     Database session to use.
    """

    record_counter('core.request.touch_request')

    try:
        rowcount = session.query(models.Request).filter_by(id=request_id).update({'updated_at': datetime.datetime.utcnow()}, synchronize_session=False)
    except IntegrityError as error:
        raise RucioException(error.args)
    if not rowcount:
        raise UnsupportedOperation("Request %s cannot be touched." % request_id)


@read_session
def __get_source_rse(request_id, src_url, session=None):
    """
    Based on a request, scope, name and src_url extract the source rse name and id.

    :param request_id:  The request_id of the request.
    :param scope:       The scope of the request file.
    :param name:        The name of the request file.
    :param src_url:     The src_url of the request.
    :param session:     The database session to use.
    """

    try:
        if not request_id:
            return None, None

        sources = get_sources(request_id, session=session)
        for source in sources:
            if source['url'] == src_url:
                src_rse_id = source['rse_id']
                src_rse_name = get_rse_name(src_rse_id, session=session)
                logging.debug("Find rse name %s for %s" % (src_rse_name, src_url))
                return src_rse_name, src_rse_id
        # cannot find matched surl
        logging.warn('Cannot get correct RSE for source url: %s' % (src_url))
        return None, None
    except Exception:
        logging.error('Cannot get correct RSE for source url: %s(%s)' % (src_url, traceback.format_exc()))
        return None, None


@stream_session
def list_requests(src_rse_ids, dst_rse_ids, states=[RequestState.WAITING], session=None):
    """
    List all requests in a specific state from a source RSE to a destination RSE.

    :param src_rse_ids: source RSE ids.
    :param dst_rse_ids: destination RSE ids.
    :param states: list of request states.
    :param session: The database session in use.
    """
    query = session.query(models.Request).filter(models.Request.state.in_(states),
                                                 models.Request.source_rse_id.in_(src_rse_ids),
                                                 models.Request.dest_rse_id.in_(dst_rse_ids))
    for request in query.yield_per(500):
        yield request
