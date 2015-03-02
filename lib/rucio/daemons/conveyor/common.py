# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014-2015
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

"""
Methods common to different conveyor daemons.
"""

import datetime
import logging
import sys
import time
import traceback

from re import match
from sqlalchemy.exc import DatabaseError

from rucio.common import exception
from rucio.common.exception import DatabaseException, UnsupportedOperation
from rucio.core import replica as replica_core, request as request_core, rse as rse_core
from rucio.core.message import add_message
from rucio.core.monitor import record_timer
from rucio.db.constants import DIDType, RequestState, ReplicaState, RequestType
from rucio.db.session import transactional_session


@transactional_session
def update_requests_states(responses, session=None):
    """
    Bulk version used by poller and consumer to update the internal state of requests,
    after the response by the external transfertool.

    :param reqs: List of (req, response) tuples.
    :param session: The database session to use.
    """

    for response in responses:
        update_request_state(response=response, session=session)


@transactional_session
def update_request_state(response, session=None):
    """
    Used by poller and consumer to update the internal state of requests,
    after the response by the external transfertool.

    :param response: The transfertool response dictionary, retrieved via request.query_request().
    :param session: The database session to use.
    :returns commit_or_rollback: Boolean.
    """

    try:
        if not response['new_state']:
            request_core.touch_request(response['request_id'], session=session)
            return False
        transfer_id = response['transfer_id'] if 'transfer_id' in response else None
        logging.debug('UPDATING REQUEST %s FOR TRANSFER %s STATE %s' % (str(response['request_id']), transfer_id, str(response['new_state'])))
        request_core.set_request_state(response['request_id'],
                                       response['new_state'],
                                       session=session)

        add_monitor_message(response, session=session)
        return True
    except exception.UnsupportedOperation, e:
        logging.warning("Request %s doesn't exist - Error: %s" % (response['request_id'], str(e).replace('\n', '')))
        return False


def handle_requests(reqs):
    """
    used by finisher to handle terminated requests,

    :param reqs: List of requests.
    """

    replicas = {}
    for req in reqs:
        try:
            replica = {'scope': req['scope'], 'name': req['name'], 'rse_id': req['dest_rse_id'], 'bytes': req['bytes'], 'adler32': req['adler32'], 'request_id': req['request_id']}

            replica['pfn'] = req['dest_url']
            replica['request_type'] = req['request_type']

            if req['request_type'] not in replicas:
                replicas[req['request_type']] = {}
            if req['rule_id'] not in replicas[req['request_type']]:
                replicas[req['request_type']][req['rule_id']] = []

            if req['state'] == RequestState.DONE:
                replica['state'] = ReplicaState.AVAILABLE
                replica['archived'] = False
                replicas[req['request_type']][req['rule_id']].append(replica)
            elif req['state'] == RequestState.FAILED or req['state'] == RequestState.LOST:
                tss = time.time()
                new_req = request_core.requeue_and_archive(req['request_id'])
                record_timer('daemons.conveyor.common.update_request_state.request-requeue_and_archive', (time.time()-tss)*1000)

                tss = time.time()
                if new_req is None:
                    logging.warn('EXCEEDED DID %s:%s REQUEST %s' % (req['scope'], req['name'], req['request_id']))
                    replica['state'] = ReplicaState.UNAVAILABLE
                    replica['archived'] = True
                    replicas[req['request_type']][req['rule_id']].append(replica)
                else:
                    logging.warn('REQUEUED DID %s:%s REQUEST %s AS %s TRY %s' % (req['scope'],
                                                                                 req['name'],
                                                                                 req['request_id'],
                                                                                 new_req['request_id'],
                                                                                 new_req['retry_count']))
        except:
            logging.error("Something unexpected happened when handling request %s(%s:%s) at %s: %s" % (req['request_id'],
                                                                                                       req['scope'],
                                                                                                       req['name'],
                                                                                                       req['dest_rse_id'],
                                                                                                       traceback.format_exc()))

    handle_terminated_replicas(replicas)


def handle_terminated_replicas(replicas):
    """
    Used by finisher to handle available and unavailable replicas.

    :param replicas: List of replicas.
    """

    for req_type in replicas:
        for rule_id in replicas[req_type]:
            try:
                handle_bulk_replicas(replicas[req_type][rule_id], req_type, rule_id)
            except UnsupportedOperation:
                # one replica in the bulk cannot be found. register it one by one
                for replica in replicas[req_type][rule_id]:
                    try:
                        handle_one_replica(replica, req_type, rule_id)
                    except (DatabaseException, DatabaseError), e:
                        if isinstance(e.args[0], tuple) and (match('.*ORA-00054.*', e.args[0][0]) or ('ERROR 1205 (HY000)' in e.args[0][0])):
                            logging.warn("Locks detected when handling replica %s:%s at RSE %s" % (replica['scope'], replica['name'], replica['rse_id']))
                        else:
                            logging.error("Could not finish handling replicas %s:%s at RSE %s (%s)" % (replica['scope'], replica['name'], replica['rse_id'], traceback.format_exc()))
                    except:
                        logging.error("Something unexpected happened when updating replica state for transfer %s:%s at %s (%s)" % (replica['scope'],
                                                                                                                                   replica['name'],
                                                                                                                                   replica['rse_id'],
                                                                                                                                   traceback.format_exc()))
            except (DatabaseException, DatabaseError), e:
                if isinstance(e.args[0], tuple) and (match('.*ORA-00054.*', e.args[0][0]) or ('ERROR 1205 (HY000)' in e.args[0][0])):
                    logging.warn("Locks detected when handling replicas on %s rule %s" % (req_type, rule_id))
                else:
                    logging.error("Could not finish handling replicas on %s rule %s: %s" % (req_type, rule_id, traceback.format_exc()))
            except:
                logging.error("Something unexpected happened when handling replicas on %s rule %s: %s" % (req_type, rule_id, traceback.format_exc()))


@transactional_session
def handle_bulk_replicas(replicas, req_type, rule_id, session=None):
    """
    Used by finisher to handle available and unavailable replicas blongs to same rule in bulk way.

    :param replicas: List of replicas.
    :param req_type: Request type: STAGEIN, STAGEOUT, TRANSFER.
    :param rule_id: RULE id.
    :param session: The database session to use.
    :returns commit_or_rollback: Boolean.
    """

    replica_core.update_replicas_states(replicas, nowait=True, session=session)
    for replica in replicas:
        if not replica['archived']:
            request_core.archive_request(replica['request_id'], session=session)
        logging.info("HANDLED REQUEST %s DID %s:%s AT RSE %s STATE %s" % (replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state'])))
    return True


@transactional_session
def handle_one_replica(replica, req_type, rule_id, session=None):
    """
    Used by finisher to handle a replica.

    :param replica: replica as a dictionary.
    :param req_type: Request type: STAGEIN, STAGEOUT, TRANSFER.
    :param rule_id: RULE id.
    :param session: The database session to use.
    :returns commit_or_rollback: Boolean.
    """

    try:
        replica_core.update_replicas_states([replica], nowait=True, session=session)
        if not replica['archived']:
            request_core.archive_request(replica['request_id'], session=session)
        logging.info("HANDLED REQUEST %s DID %s:%s AT RSE %s STATE %s" % (replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state'])))
    except UnsupportedOperation:
        # replica cannot be found. register it and schedule it for deletion
        try:
            if replica['state'] == ReplicaState.AVAILABLE and replica['request_type'] != RequestType.STAGEIN:
                logging.info("Replica cannot be found. Adding a replica %s:%s AT RSE %s with tombstone=utcnow" % (replica['scope'], replica['name'], replica['rse_id']))
                rse = rse_core.get_rse(rse=None, rse_id=replica['rse_id'])
                replica_core.add_replica(rse['rse'],
                                         replica['scope'],
                                         replica['name'],
                                         replica['bytes'],
                                         pfn=replica['pfn'] if 'pfn' in replica else None,
                                         account='root',  # it will deleted immediately, do we need to get the accurate account from rule?
                                         adler32=replica['adler32'],
                                         tombstone=datetime.datetime.utcnow(),
                                         session=session)
            if not replica['archived']:
                request_core.archive_request(replica['request_id'], session=session)
            logging.info("HANDLED REQUEST %s DID %s:%s AT RSE %s STATE %s" % (replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state'])))
        except:
            logging.error('Cannot register replica for DID %s:%s at RSE %s - potential dark data' % (replica['scope'],
                                                                                                     replica['name'],
                                                                                                     replica['rse_id']))
            raise

    return True


def get_source_rse(scope, name, src_url):
    try:
        scheme = src_url.split(":")[0]
        replications = replica_core.list_replicas([{'scope': scope, 'name': name, 'type': DIDType.FILE}], schemes=[scheme], unavailable=True)
        for source in replications:
            for source_rse in source['rses']:
                for pfn in source['rses'][source_rse]:
                    if pfn == src_url:
                        return source_rse
        # cannot find matched surl
        logging.warn('Cannot get correct RSE for source url: %s' % (src_url))
        return None
    except:
        logging.error('Cannot get correct RSE for source url: %s(%s)' % (src_url, sys.exc_info()[1]))
        return None


@transactional_session
def add_monitor_message(response, session=None):
    if response['new_state'] == RequestState.DONE:
        transfer_status = 'transfer-done'
    elif response['new_state'] == RequestState.FAILED:
        transfer_status = 'transfer-failed'
    elif response['new_state'] == RequestState.LOST:
        transfer_status = 'transfer-lost'

    activity = response.get('activity', None)
    src_rse = response.get('src_rse', None)
    src_url = response.get('src_url', None)
    dst_rse = response.get('dst_rse', None)
    dst_url = response.get('dst_url', None)
    dst_protocol = dst_url.split(':')[0] if dst_url else None
    reason = response.get('reason', None)
    duration = response.get('duration', -1)
    filesize = response.get('filesize', None)
    md5 = response.get('md5', None)
    adler32 = response.get('adler32', None)
    scope = response.get('scope', None)
    name = response.get('name', None)
    job_m_replica = response.get('job_m_replica', None)
    if job_m_replica and str(job_m_replica) == str('true') and src_url:
        try:
            rse_name = get_source_rse(scope, name, src_url)
        except:
            logging.warn('Cannot get correct RSE for source url: %s(%s)' % (src_url, sys.exc_info()[1]))
            rse_name = None
        if rse_name and rse_name != src_rse:
            src_rse = rse_name
            logging.info('find RSE: %s for source surl: %s' % (src_rse, src_url))

    if response['external_host']:
        transfer_link = '%s/fts3/ftsmon/#/job/%s' % (response['external_host'].replace('8446', '8449'), response['transfer_id'])
    else:
        # for LOST request, response['external_host'] maybe is None
        transfer_link = None

    add_message(transfer_status, {'activity': activity,
                                  'request-id': response['request_id'],
                                  'duration': duration,
                                  'checksum-adler': adler32,
                                  'checksum-md5': md5,
                                  'file-size': filesize,
                                  'guid': None,
                                  'previous-request-id': response['previous_attempt_id'],
                                  'protocol': dst_protocol,
                                  'scope': response['scope'],
                                  'name': response['name'],
                                  'src-rse': src_rse,
                                  'src-url': src_url,
                                  'dst-rse': dst_rse,
                                  'dst-url': dst_url,
                                  'reason': reason,
                                  'transfer-endpoint': response['external_host'],
                                  'transfer-id': response['transfer_id'],
                                  'transfer-link': transfer_link,
                                  'tool-id': 'rucio-conveyor'},
                session=session)
