# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2017
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2017-2018
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2018

import datetime
import json
import logging
import time
import traceback

from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import asc, bindparam, text, false

from rucio.common import constants
from rucio.common.exception import RucioException, UnsupportedOperation, InvalidRSEExpression, RSEProtocolNotSupported
from rucio.common.rse_attributes import get_rse_attributes
from rucio.common.utils import construct_surl
from rucio.core import did, message as message_core, request as request_core
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import get_rse_name, list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, RequestState, FTSState, RSEType, RequestType, ReplicaState
from rucio.db.sqla.session import read_session, transactional_session
from rucio.rse import rsemanager as rsemgr
from rucio.transfertool import fts3

"""
The core transfer.py is specifically for handling transfer-requests, thus requests
where the external_id is already known.
Requests accessed by request_id  are covered in the core request.py
"""

REGION_SHORT = make_region().configure('dogpile.cache.memcached',
                                       expiration_time=600,
                                       arguments={'url': "127.0.0.1:11211", 'distributed_lock': True})


def submit_bulk_transfers(external_host, files, transfertool='fts3', job_params={}, timeout=None):
    """
    Submit transfer request to a transfertool.

    :param external_host:  External host name as string
    :param files:          List of Dictionary containing request file.
    :param transfertool:   Transfertool as a string.
    :param job_params:     Metadata key/value pairs for all files as a dictionary.
    :returns:              Transfertool external ID.
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
def prepare_sources_for_transfers(transfers, session=None):
    """
    Prepare the sources for transfers.

    :param transfers:  Dictionary containing request transfer info.
    :param session:    Database session to use.
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

    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def set_transfers_state(transfers, submitted_at, session=None):
    """
    Update the transfer info of a request.

    :param transfers:  Dictionary containing request transfer info.
    :param session:    Database session to use.
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

    except IntegrityError as error:
        raise RucioException(error.args)


@read_session
def get_next_transfers(request_type, state, limit=100, older_than=None, rse=None, activity=None,
                       process=None, total_processes=None, thread=None, total_threads=None,
                       activity_shares=None, session=None):
    """
    Retrieve the next transfers matching the request type and state.
    Workers are balanced via hashing to reduce concurrency on database.

    :param request_type:      Type of the request as a string or list of strings.
    :param state:             State of the request as a string or list of strings.
    :param limit:             Integer of requests to retrieve.
    :param older_than:        Only select requests older than this DateTime.
    :param process:           Identifier of the caller process as an integer.
    :param total_processes:   Maximum number of processes as an integer.
    :param thread:            Identifier of the caller thread as an integer.
    :param total_threads:     Maximum number of threads as an integer.
    :param activity_shares:   Activity shares dictionary, with number of requests
    :param session:           Database session to use.
    :returns:                 List of a {external_host, external_id} dictionary.
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
                query = query.filter(text('mod(md5(rule_id), %s) = %s' % (total_processes - 1, process)))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter(text('mod(abs((\'x\'||md5(rule_id::text))::bit(32)::int), %s) = %s' % (total_processes - 1, process)))

        if (total_threads - 1) > 0:
            if session.bind.dialect.name == 'oracle':
                bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads - 1)]
                query = query.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
            elif session.bind.dialect.name == 'mysql':
                query = query.filter(text('mod(md5(rule_id), %s) = %s' % (total_threads - 1, thread)))
            elif session.bind.dialect.name == 'postgresql':
                query = query.filter(text('mod(abs((\'x\'||md5(rule_id::text))::bit(32)::int), %s) = %s' % (total_threads - 1, thread)))

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


def bulk_query_transfers(request_host, transfer_ids, transfertool='fts3', timeout=None):
    """
    Query the status of a transfer.

    :param request_host:  Name of the external host.
    :param transfer_ids:  List of (External-ID as a 32 character hex string)
    :param transfertool:  Transfertool name as a string.
    :returns:             Request status information as a dictionary.
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


@transactional_session
def set_transfer_update_time(external_host, transfer_id, update_time=datetime.datetime.utcnow(), session=None):
    """
    Update the state of a request. Fails silently if the transfer_id does not exist.

    :param external_host:  Selected external host as string in format protocol://fqdn:port
    :param transfer_id:    External transfer job id as a string.
    :param update_time:    Time stamp.
    :param session:        Database session to use.
    """

    record_counter('core.request.set_transfer_update_time')

    try:
        rowcount = session.query(models.Request).filter_by(external_id=transfer_id, state=RequestState.SUBMITTED).update({'updated_at': update_time}, synchronize_session=False)
    except IntegrityError as error:
        raise RucioException(error.args)

    if not rowcount:
        raise UnsupportedOperation("Transfer %s doesn't exist or its status is not submitted." % (transfer_id))


def query_latest(external_host, state, last_nhours=1):
    """
    Query the latest transfers in last n hours with state.

    :param external_host:  FTS host name as a string.
    :param state:          FTS job state as a string or a dictionary.
    :param last_nhours:    Latest n hours as an integer.
    :returns:              Requests status information as a dictionary.
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
            except Exception as error:
                logging.debug("Exception happened when updating transfer updatetime: %s" % str(error).replace('\n', ''))

    return ret_resps


@transactional_session
def touch_transfer(external_host, transfer_id, session=None):
    """
    Update the timestamp of requests in a transfer. Fails silently if the transfer_id does not exist.

    :param request_host:   Name of the external host.
    :param transfer_id:    External transfer job id as a string.
    :param session:        Database session to use.
    """

    record_counter('core.request.touch_transfer')

    try:
        # don't touch it if it's already touched in 30 seconds
        session.query(models.Request).with_hint(models.Request, "INDEX(REQUESTS REQUESTS_EXTERNALID_UQ)", 'oracle')\
                                     .filter_by(external_id=transfer_id)\
                                     .filter(models.Request.state == RequestState.SUBMITTED)\
                                     .filter(models.Request.updated_at < datetime.datetime.utcnow() - datetime.timedelta(seconds=30))\
                                     .update({'updated_at': datetime.datetime.utcnow()}, synchronize_session=False)
    except IntegrityError as error:
        raise RucioException(error.args)


@transactional_session
def update_transfer_state(external_host, transfer_id, state, session=None):
    """
    Used by poller to update the internal state of transfer,
    after the response by the external transfertool.

    :param request_host:          Name of the external host.
    :param transfer_id:           External transfer job id as a string.
    :param state:                 Request state as a string.
    :param session:               The database session to use.
    :returns commit_or_rollback:  Boolean.
    """

    try:
        if state == RequestState.LOST:
            reqs = request_core.get_requests_by_transfer(external_host, transfer_id, session=session)
            for req in reqs:
                logging.info('REQUEST %s OF TRANSFER %s ON %s STATE %s' % (str(req['request_id']), external_host, transfer_id, str(state)))
                src_rse_id = req.get('source_rse_id', None)
                dst_rse_id = req.get('dest_rse_id', None)
                src_rse = None
                dst_rse = None
                if src_rse_id:
                    src_rse = get_rse_name(src_rse_id, session=session)
                if dst_rse_id:
                    dst_rse = get_rse_name(dst_rse_id, session=session)
                response = {'new_state': state,
                            'transfer_id': transfer_id,
                            'job_state': state,
                            'src_url': None,
                            'dst_url': req['dest_url'],
                            'duration': 0,
                            'reason': "The FTS job lost",
                            'scope': req.get('scope', None),
                            'name': req.get('name', None),
                            'src_rse': src_rse,
                            'dst_rse': dst_rse,
                            'request_id': req.get('request_id', None),
                            'activity': req.get('activity', None),
                            'src_rse_id': req.get('source_rse_id', None),
                            'dst_rse_id': req.get('dest_rse_id', None),
                            'previous_attempt_id': req.get('previous_attempt_id', None),
                            'adler32': req.get('adler32', None),
                            'md5': req.get('md5', None),
                            'filesize': req.get('filesize', None),
                            'external_host': external_host,
                            'job_m_replica': None,
                            'created_at': req.get('created_at', None),
                            'submitted_at': req.get('submitted_at', None),
                            'details': None,
                            'account': req.get('account', None)}

                err_msg = request_core.get_transfer_error(response['new_state'], response['reason'] if 'reason' in response else None)
                request_core.set_request_state(req['request_id'],
                                               response['new_state'],
                                               transfer_id=transfer_id,
                                               src_rse_id=src_rse_id,
                                               err_msg=err_msg,
                                               session=session)

                request_core.add_monitor_message(req, response, session=session)
        else:
            __set_transfer_state(external_host, transfer_id, state, session=session)
        return True
    except UnsupportedOperation as error:
        logging.warning("Transfer %s on %s doesn't exist - Error: %s" % (transfer_id, external_host, str(error).replace('\n', '')))
        return False


@read_session
def get_transfer_requests_and_source_replicas(process=None, total_processes=None, thread=None, total_threads=None,
                                              limit=None, activity=None, older_than=None, rses=None, schemes=None,
                                              bring_online=43200, retry_other_fts=False, failover_schemes=None, session=None):
    """
    Get transfer requests and the associated source replicas

    :param process:               Current process.
    :param total_processes:       Total processes.
    :param thread:                Thread number.
    :param total_threads:         Total threads.
    :param limit:                 Limit.
    :param activity:              Activity.
    :param older_than:            Get transfers older than.
    :param rses:                  Include RSES.
    :param schemes:               Include schemes.
    :param bring_online:          Bring online timeout.
    :parm retry_other_fts:        Retry other fts servers.
    :param failover_schemes:      Failover schemes.
    :session:                     The database session in use.
    :returns:                     transfers, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source
    """

    req_sources = __list_transfer_requests_and_source_replicas(process=process,
                                                               total_processes=total_processes,
                                                               thread=thread,
                                                               total_threads=total_threads,
                                                               limit=limit,
                                                               activity=activity,
                                                               older_than=older_than,
                                                               rses=rses,
                                                               session=session)

    unavailable_read_rse_ids = __get_unavailable_read_rse_ids(session=session)

    bring_online_local = bring_online
    transfers, rses_info, protocols, rse_attrs, reqs_no_source, reqs_only_tape_source, reqs_scheme_mismatch = {}, {}, {}, {}, [], [], []
    for id, rule_id, scope, name, md5, adler32, bytes, activity, attributes, previous_attempt_id, dest_rse_id, source_rse_id, rse, deterministic, rse_type, path, retry_count, src_url, ranking, link_ranking in req_sources:
        transfer_src_type = "DISK"
        transfer_dst_type = "DISK"
        allow_tape_source = True
        try:
            if rses and dest_rse_id not in rses:
                continue

            current_schemes = schemes
            if previous_attempt_id and failover_schemes:
                current_schemes = failover_schemes

            if id not in transfers:
                if id not in reqs_no_source:
                    reqs_no_source.append(id)

                # source_rse_id will be None if no source replicas
                # rse will be None if rse is staging area
                if source_rse_id is None or rse is None:
                    continue

                if link_ranking is None:
                    logging.debug("Request %s: no link from %s to %s" % (id, source_rse_id, dest_rse_id))
                    continue

                if source_rse_id in unavailable_read_rse_ids:
                    continue

                # Get destination rse information
                if dest_rse_id not in rses_info:
                    dest_rse = get_rse_name(rse_id=dest_rse_id, session=session)
                    rses_info[dest_rse_id] = rsemgr.get_rse_info(dest_rse, session=session)
                if dest_rse_id not in rse_attrs:
                    rse_attrs[dest_rse_id] = get_rse_attributes(dest_rse_id, session=session)

                # Get the source rse information
                if source_rse_id not in rses_info:
                    source_rse = get_rse_name(rse_id=source_rse_id, session=session)
                    rses_info[source_rse_id] = rsemgr.get_rse_info(source_rse, session=session)

                attr = None
                if attributes:
                    if type(attributes) is dict:
                        attr = json.loads(json.dumps(attributes))
                    else:
                        attr = json.loads(str(attributes))

                # parse source expression
                source_replica_expression = attr["source_replica_expression"] if (attr and "source_replica_expression" in attr) else None
                if source_replica_expression:
                    try:
                        parsed_rses = parse_expression(source_replica_expression, session=session)
                    except InvalidRSEExpression as error:
                        logging.error("Invalid RSE exception %s: %s" % (source_replica_expression, error))
                        continue
                    else:
                        allowed_rses = [x['rse'] for x in parsed_rses]
                        if rse not in allowed_rses:
                            continue

                # parse allow tape source expression, not finally version.
                # allow_tape_source = attr["allow_tape_source"] if (attr and "allow_tape_source" in attr) else True
                allow_tape_source = True

                # Find matching scheme between destination and source
                # TODO: In the future, move to domain "third_party_copy"
                try:
                    matching_scheme = rsemgr.find_matching_scheme(rse_settings_dest=rses_info[dest_rse_id],
                                                                  rse_settings_src=rses_info[source_rse_id],
                                                                  operation_src='read',
                                                                  operation_dest='write',
                                                                  domain='wan',
                                                                  scheme=current_schemes)
                except RSEProtocolNotSupported:
                    logging.error('Operation "write" not supported by %s with schemes %s' % (rses_info[dest_rse_id]['rse'], current_schemes))
                    if id in reqs_no_source:
                        reqs_no_source.remove(id)
                    if id not in reqs_scheme_mismatch:
                        reqs_scheme_mismatch.append(id)
                    continue

                # Get destination protocol
                if dest_rse_id not in protocols:
                    try:
                        protocols[dest_rse_id] = rsemgr.create_protocol(rses_info[dest_rse_id], 'write', matching_scheme[0])
                    except RSEProtocolNotSupported:
                        logging.error('Operation "write" not supported by %s with schemes %s' % (rses_info[dest_rse_id]['rse'], current_schemes))
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
                    if rses_info[dest_rse_id]['rse_type'] == RSEType.TAPE or rses_info[dest_rse_id]['rse_type'] == 'TAPE':
                        if retry_count or activity == 'Recovery':
                            dest_path = '%s_%i' % (dest_path, int(time.time()))

                    dest_url = protocols[dest_rse_id].lfns2pfns(lfns={'scope': scope, 'name': name, 'path': dest_path}).values()[0]

                # Get source protocol
                source_rse_id_key = '%s_%s' % (source_rse_id, '_'.join([matching_scheme[0], matching_scheme[1]]))
                if source_rse_id_key not in protocols:
                    try:
                        protocols[source_rse_id_key] = rsemgr.create_protocol(rses_info[source_rse_id], 'read', matching_scheme[1])
                    except RSEProtocolNotSupported:
                        logging.error('Operation "read" not supported by %s with schemes %s' % (rses_info[source_rse_id]['rse'], matching_scheme[1]))
                        if id in reqs_no_source:
                            reqs_no_source.remove(id)
                        if id not in reqs_scheme_mismatch:
                            reqs_scheme_mismatch.append(id)
                        continue

                source_url = protocols[source_rse_id_key].lfns2pfns(lfns={'scope': scope, 'name': name, 'path': path}).values()[0]

                # Extend the metadata dictionary with request attributes
                overwrite, bring_online = True, None
                if rses_info[source_rse_id]['rse_type'] == RSEType.TAPE or rses_info[source_rse_id]['rse_type'] == 'TAPE':
                    bring_online = bring_online_local
                    transfer_src_type = "TAPE"
                    if not allow_tape_source:
                        if id not in reqs_only_tape_source:
                            reqs_only_tape_source.append(id)
                        if id in reqs_no_source:
                            reqs_no_source.remove(id)
                        continue

                if rses_info[dest_rse_id]['rse_type'] == RSEType.TAPE or rses_info[dest_rse_id]['rse_type'] == 'TAPE':
                    overwrite = False
                    transfer_dst_type = "TAPE"

                # get external_host
                fts_hosts = rse_attrs[dest_rse_id].get('fts', None)
                if not fts_hosts:
                    logging.error('Source RSE %s FTS attribute not defined - SKIP REQUEST %s' % (rse, id))
                    continue
                if retry_count is None:
                    retry_count = 0
                fts_list = fts_hosts.split(",")

                external_host = fts_list[0]
                if retry_other_fts:
                    external_host = fts_list[retry_count % len(fts_list)]

                file_metadata = {'request_id': id,
                                 'scope': scope,
                                 'name': name,
                                 'activity': activity,
                                 'request_type': str(RequestType.TRANSFER).lower(),
                                 'src_type': transfer_src_type,
                                 'dst_type': transfer_dst_type,
                                 'src_rse': rse,
                                 'dst_rse': rses_info[dest_rse_id]['rse'],
                                 'src_rse_id': source_rse_id,
                                 'dest_rse_id': dest_rse_id,
                                 'filesize': bytes,
                                 'md5': md5,
                                 'adler32': adler32,
                                 'verify_checksum': rse_attrs[dest_rse_id].get('verify_checksum', True)}

                if previous_attempt_id:
                    file_metadata['previous_attempt_id'] = previous_attempt_id

                transfers[id] = {'request_id': id,
                                 'schemes': __add_compatible_schemes(schemes=[matching_scheme[0]], allowed_schemes=current_schemes),
                                 # 'src_urls': [source_url],
                                 'sources': [(rse, source_url, source_rse_id, ranking if ranking is not None else 0, link_ranking)],
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
                current_schemes = transfers[id]['schemes']

                # source_rse_id will be None if no source replicas
                # rse will be None if rse is staging area
                if source_rse_id is None or rse is None:
                    continue

                if link_ranking is None or link_ranking == 0:
                    logging.debug("Request %s: no link from %s to %s" % (id, source_rse_id, dest_rse_id))
                    continue

                if source_rse_id in unavailable_read_rse_ids:
                    continue

                attr = None
                if attributes:
                    if type(attributes) is dict:
                        attr = json.loads(json.dumps(attributes))
                    else:
                        attr = json.loads(str(attributes))

                # parse source expression
                source_replica_expression = attr["source_replica_expression"] if (attr and "source_replica_expression" in attr) else None
                if source_replica_expression:
                    try:
                        parsed_rses = parse_expression(source_replica_expression, session=session)
                    except InvalidRSEExpression as error:
                        logging.error("Invalid RSE exception %s: %s" % (source_replica_expression, error))
                        continue
                    else:
                        allowed_rses = [x['rse'] for x in parsed_rses]
                        if rse not in allowed_rses:
                            continue

                # parse allow tape source expression, not finally version.
                allow_tape_source = attr["allow_tape_source"] if (attr and "allow_tape_source" in attr) else True

                # Compute the source rse information
                if source_rse_id not in rses_info:
                    source_rse = get_rse_name(rse_id=source_rse_id, session=session)
                    rses_info[source_rse_id] = rsemgr.get_rse_info(source_rse, session=session)

                # Get protocol
                source_rse_id_key = '%s_%s' % (source_rse_id, '_'.join(current_schemes))
                if source_rse_id_key not in protocols:
                    try:
                        protocols[source_rse_id_key] = rsemgr.create_protocol(rses_info[source_rse_id], 'read', current_schemes)
                    except RSEProtocolNotSupported:
                        logging.error('Operation "read" not supported by %s with schemes %s' % (rses_info[source_rse_id]['rse'], current_schemes))
                        continue
                source_url = protocols[source_rse_id_key].lfns2pfns(lfns={'scope': scope, 'name': name, 'path': path}).values()[0]

                if ranking is None:
                    ranking = 0
                # TAPE should not mixed with Disk and should not use as first try
                # If there is a source whose ranking is no less than the Tape ranking, Tape will not be used.
                if rses_info[source_rse_id]['rse_type'] == RSEType.TAPE or rses_info[source_rse_id]['rse_type'] == 'TAPE':
                    # current src_rse is Tape
                    if not allow_tape_source:
                        continue
                    if not transfers[id]['bring_online']:
                        # the sources already founded are disks.

                        avail_top_ranking = None
                        founded_sources = transfers[id]['sources']
                        for founded_source in founded_sources:
                            if avail_top_ranking is None:
                                avail_top_ranking = founded_source[3]
                                continue
                            if founded_source[3] is not None and founded_source[3] > avail_top_ranking:
                                avail_top_ranking = founded_source[3]

                        if avail_top_ranking >= ranking:
                            # current Tape source is not the highest ranking, will use disk sources
                            continue
                        else:
                            transfers[id]['sources'] = []
                            transfers[id]['bring_online'] = bring_online_local
                            transfer_src_type = "TAPE"
                            transfers[id]['file_metadata']['src_type'] = transfer_src_type
                            transfers[id]['file_metadata']['src_rse'] = rse
                    else:
                        # the sources already founded is Tape too.
                        # multiple Tape source replicas are not allowed in FTS3.
                        if transfers[id]['sources'][0][3] > ranking or (transfers[id]['sources'][0][3] == ranking and transfers[id]['sources'][0][4] <= link_ranking):
                            continue
                        else:
                            transfers[id]['sources'] = []
                            transfers[id]['bring_online'] = bring_online_local
                            transfers[id]['file_metadata']['src_rse'] = rse
                else:
                    # current src_rse is Disk
                    if transfers[id]['bring_online']:
                        # the founded sources are Tape

                        avail_top_ranking = None
                        founded_sources = transfers[id]['sources']
                        for founded_source in founded_sources:
                            if avail_top_ranking is None:
                                avail_top_ranking = founded_source[3]
                                continue
                            if founded_source[3] is not None and founded_source[3] > avail_top_ranking:
                                avail_top_ranking = founded_source[3]

                        if ranking >= avail_top_ranking:
                            # current disk replica has higher ranking than founded sources
                            # remove founded Tape sources
                            transfers[id]['sources'] = []
                            transfers[id]['bring_online'] = None
                            transfer_src_type = "DISK"
                            transfers[id]['file_metadata']['src_type'] = transfer_src_type
                            transfers[id]['file_metadata']['src_rse'] = rse
                        else:
                            continue

                # transfers[id]['src_urls'].append((source_rse_id, source_url))
                transfers[id]['sources'].append((rse, source_url, source_rse_id, ranking, link_ranking))

        except:
            logging.critical("Exception happened when trying to get transfer for request %s: %s" % (id, traceback.format_exc()))
            break

    for id in transfers:
        if id in reqs_no_source:
            reqs_no_source.remove(id)
        if id in reqs_only_tape_source:
            reqs_only_tape_source.remove(id)
        if id in reqs_scheme_mismatch:
            reqs_scheme_mismatch.remove(id)

    return transfers, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source


@read_session
def __list_transfer_requests_and_source_replicas(process=None, total_processes=None, thread=None, total_threads=None,
                                                 limit=None, activity=None, older_than=None, rses=None, session=None):
    """
    List requests with source replicas

    :param process:          Identifier of the caller process as an integer.
    :param total_processes:  Maximum number of processes as an integer.
    :param thread:           Identifier of the caller thread as an integer.
    :param total_threads:    Maximum number of threads as an integer.
    :param limit:            Integer of requests to retrieve.
    :param activity:         Activity to be selected.
    :param older_than:       Only select requests older than this DateTime.
    :param rses:             List of rse_id to select requests.
    :param session:          Database session to use.
    :returns:                List.
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
            sub_requests = sub_requests.filter(text('mod(md5(rule_id), %s) = %s' % (total_processes - 1, process)))
        elif session.bind.dialect.name == 'postgresql':
            sub_requests = sub_requests.filter(text('mod(abs((\'x\'||md5(rule_id::text))::bit(32)::int), %s) = %s' % (total_processes - 1, process)))

    if (total_threads - 1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('thread_number', thread), bindparam('total_threads', total_threads - 1)]
            sub_requests = sub_requests.filter(text('ORA_HASH(rule_id, :total_threads) = :thread_number', bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            sub_requests = sub_requests.filter(text('mod(md5(rule_id), %s) = %s' % (total_threads - 1, thread)))
        elif session.bind.dialect.name == 'postgresql':
            sub_requests = sub_requests.filter(text('mod(abs((\'x\'||md5(rule_id::text))::bit(32)::int), %s) = %s' % (total_threads - 1, thread)))

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


@transactional_session
def __set_transfer_state(external_host, transfer_id, new_state, session=None):
    """
    Update the state of a transfer. Fails silently if the transfer_id does not exist.

    :param external_host:  Selected external host as string in format protocol://fqdn:port
    :param transfer_id:    External transfer job id as a string.
    :param new_state:      New state as string.
    :param session:        Database session to use.
    """

    record_counter('core.request.set_transfer_state')

    try:
        rowcount = session.query(models.Request).filter_by(external_id=transfer_id).update({'state': new_state, 'updated_at': datetime.datetime.utcnow()}, synchronize_session=False)
    except IntegrityError as error:
        raise RucioException(error.args)

    if not rowcount:
        raise UnsupportedOperation("Transfer %s on %s state %s cannot be updated." % (transfer_id, external_host, new_state))


@read_session
def __get_unavailable_read_rse_ids(session=None):
    """
    Get unavailable read rse ids
    """

    key = 'unavailable_read_rse_ids'
    result = REGION_SHORT.get(key)
    if type(result) is NoValue:
        try:
            logging.debug("Refresh unavailable read rses")
            unavailable_read_rses = list_rses(filters={'availability_read': False}, session=session)
            unavailable_read_rse_ids = [r['id'] for r in unavailable_read_rses]
            REGION_SHORT.set(key, unavailable_read_rse_ids)
            return unavailable_read_rse_ids
        except:
            logging.warning("Failed to refresh unavailable read rses, error: %s" % (traceback.format_exc()))
            return []
    return result


def __add_compatible_schemes(schemes, allowed_schemes):
    """
    Add the compatible schemes to a list of schemes

    :param schemes:           Schemes as input.
    :param allowed_schemes:   Allowed schemes, only these can be in the output.
    :returns:                 List of schemes
    """

    return_schemes = []
    for scheme in schemes:
        if scheme in allowed_schemes:
            return_schemes.append(scheme)
            for scheme_map_scheme in constants.SCHEME_MAP.get(scheme, []):
                if scheme_map_scheme not in allowed_schemes:
                    continue
                else:
                    return_schemes.append(scheme_map_scheme)
    return list(set(return_schemes))
