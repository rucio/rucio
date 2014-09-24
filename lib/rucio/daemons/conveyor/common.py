# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

"""
Methods common to different conveyor daemons.
"""

import datetime
import json
import logging
import sys
import time
import traceback

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core import did, lock, replica, request, rse
from rucio.core.message import add_message
from rucio.core.monitor import record_timer
from rucio.db.constants import RequestState, ReplicaState
from rucio.db.session import transactional_session


@transactional_session
def update_requests_states(reqs, session=None):
    """
    Bulk version used by poller and consumer to update the internal state of requests,
    after the response by the external transfertool.

    :param reqs: List of (req, response) tuples.
    :param session: The database session to use.
    """

    for req, response in reqs:
        update_request_state(req=req, response=response, session=session)


@transactional_session
def update_request_state(req, response, session=None):
    """
    Used by poller and consumer to update the internal state of requests,
    after the response by the external transfertool.

    :param req: The internal request dictionary.
    :param response: The transfertool response dictionary, retrieved via request.query_request().
    :param session: The database session to use.
    :returns commit_or_rollback: Boolean.
    """

    request.touch_request(req['request_id'], session=session)

    if not response['new_state'] and isinstance(response['details'], Exception):
        logging.warning('REQUEST %s STATE IS UNKNOWN %s' % (str(req['request_id']), str(response['details'])))
    elif response['new_state'] == RequestState.LOST:
        logging.debug('UPDATING REQUEST %s FOR STATE %s' % (str(req['request_id']), str(response['new_state'])))
    elif response['new_state'] and 'job_state' in response and response['job_state']:
        logging.debug('UPDATING REQUEST %s FOR TRANSFER STATE %s' % (str(req['request_id']), str(response['job_state'])))
    else:
        return False

    if response['new_state']:
        rse_name = None

        tss = time.time()
        try:
            rse_name = rse.get_rse_name(rse_id=req['dest_rse_id'],
                                        session=session)
        except exception.RSENotFound:
            logging.error('RSE ID %s not found - Cannot proceed updating the state for this request' % req['dest_rse_id'])
            return False
        record_timer('daemons.conveyor.common.update_request_state.rse-get_rse_by_id', (time.time()-tss)*1000)

        tss = time.time()
        did_meta = did.get_metadata(req['scope'], req['name'], session=session)
        record_timer('daemons.conveyor.common.update_request_state.did-get_metadata', (time.time()-tss)*1000)

        request.set_request_state(req['request_id'],
                                  response['new_state'],
                                  session=session)

        if not response['details'] or isinstance(response['details'], Exception):
            details = None
            logging.warning('Could not request detailed transfer information (%s)- reporting will be missing values.' % response['details'])
        else:
            details = response['details']['files'] if 'files' in response['details'] else None
            if not details or isinstance(details, Exception):
                logging.warning('Could not request detailed transfer information (%s)- reporting will be missing values.' % details)
                details = None
            else:
                if type(details) == list or type(details) == tuple:
                    details = details[0]  # there is always only one file

        activity = 'default'
        if req['attributes']:
            if type(req['attributes']) is dict:
                req_attributes = json.loads(json.dumps(req['attributes']))
            else:
                req_attributes = json.loads(str(req['attributes']))
            activity = req_attributes['activity'] if req_attributes['activity'] else 'default'

        if response['new_state'] == RequestState.DONE:
            try:
                tss = time.time()
                logging.debug('UPDATE REPLICA STATE DID %s:%s RSE %s' % (req['scope'], req['name'], rse_name))

                # make sure we do not leave the transaction
                try:
                    # try quickly
                    replica.update_replicas_states([{'rse': rse_name,
                                                     'scope': req['scope'],
                                                     'name': req['name'],
                                                     'state': ReplicaState.AVAILABLE}],
                                                   nowait=True,
                                                   session=session)
                except:
                    try:
                        # didn't work, do it slowly
                        replica.update_replicas_states([{'rse': rse_name,
                                                         'scope': req['scope'],
                                                         'name': req['name'],
                                                         'state': ReplicaState.AVAILABLE}],
                                                       nowait=False,
                                                       session=session)
                    except Exception, e:
                        # could not update successful lock
                        record_timer('daemons.conveyor.common.update_request_state.replica-update_replicas_states', (time.time()-tss)*1000)
                        raise

                record_timer('daemons.conveyor.common.update_request_state.replica-update_replicas_states', (time.time()-tss)*1000)

                tss = time.time()
                request.archive_request(req['request_id'], session=session)
                record_timer('daemons.conveyor.common.update_request_state.request-archive_request', (time.time()-tss)*1000)

                add_monitor_message(req, response, did_meta, details, activity, session=session)
            except exception.UnsupportedOperation, e:
                # The replica doesn't exist
                request.archive_request(req['request_id'], session=session)
                logging.warning(str(e).replace('\n', ''))
                return True
            except Exception, e:
                # could not update successful lock
                logging.critical("Could not update replica state for succesful transfer %s:%s at %s (%s)" % (req['scope'],
                                                                                                             req['name'],
                                                                                                             rse_name,
                                                                                                             traceback.format_exc()))
                return True

        elif response['new_state'] == RequestState.FAILED:
            tss = time.time()
            new_req = request.requeue_and_archive(req['request_id'], session=session)
            record_timer('daemons.conveyor.common.update_request_state.request-requeue_and_archive', (time.time()-tss)*1000)

            add_monitor_message(req, response, did_meta, details, activity, session=session)

            tss = time.time()
            if new_req is None:
                logging.error('EXCEEDED DID %s:%s REQUEST %s' % (req['scope'],
                                                                 req['name'],
                                                                 req['request_id']))
                try:
                    replica.update_replicas_states([{'rse': rse_name,
                                                     'scope': req['scope'],
                                                     'name': req['name'],
                                                     'state': ReplicaState.UNAVAILABLE}],
                                                   nowait=True,
                                                   session=session)
                except Exception, e:
                    logging.critical("Could not update replica state for failed transfer %s:%s at %s (%s)" % (req['scope'],
                                                                                                              req['name'],
                                                                                                              rse_name,
                                                                                                              traceback.format_exc()))
                tss = time.time()
                try:
                    lock.failed_transfer(req['scope'],
                                         req['name'],
                                         req['dest_rse_id'],
                                         session=session)
                except:
                    logging.warn('Could not update lock for failed transfer %s:%s at %s (%s)' % (req['scope'],
                                                                                                 req['name'],
                                                                                                 rse_name,
                                                                                                 sys.exc_info()[1]))
                    return
                record_timer('daemons.conveyor.common.update_request_state.lock-failed_transfer', (time.time()-tss)*1000)
            else:
                logging.warn('REQUEUED DID %s:%s REQUEST %s AS %s TRY %s' % (req['scope'],
                                                                             req['name'],
                                                                             req['request_id'],
                                                                             new_req['request_id'],
                                                                             new_req['retry_count']))

        elif response['new_state'] == RequestState.LOST:
            tss = time.time()
            record_timer('daemons.conveyor.common.update_request_state.lock-failed_transfer', (time.time()-tss)*1000)

            add_monitor_message(req, response, did_meta, details, activity, session=session)

            request.archive_request(req['request_id'], session=session)
            logging.error('LOST DID %s:%s REQUEST %s' % (req['scope'],
                                                         req['name'],
                                                         req['request_id']))

            try:
                lock.failed_transfer(req['scope'],
                                     req['name'],
                                     req['dest_rse_id'],
                                     session=session)
            except:
                logging.warn('Could not update lock for lost transfer %s:%s at %s (%s)' % (req['scope'],
                                                                                           req['name'],
                                                                                           rse_name,
                                                                                           sys.exc_info()[1]))
                return

        logging.info('UPDATED REQUEST %s DID %s:%s AT %s TO %s' % (req['request_id'],
                                                                   req['scope'],
                                                                   req['name'],
                                                                   rse_name,
                                                                   response['new_state']))

    return True


@transactional_session
def add_monitor_message(req, response, did_meta, details, activity, session=None):
    if response['new_state'] == RequestState.DONE:
        transfer_status = 'transfer-done'
    elif response['new_state'] == RequestState.FAILED:
        transfer_status = 'transfer-failed'
    elif response['new_state'] == RequestState.LOST:
        transfer_status = 'transfer-lost'

    src_rse = 'unknown'
    src_url = 'unknown'
    dst_rse = 'unknown'
    dst_url = 'unknown'
    dst_protocol = None
    reason = None
    duration = -1

    if details:
        # propagate the correct source
        if 'source_surl' not in details:
            src_url = response['src_url']
        else:
            src_url = details['source_surl']
        if 'src_rse' not in response and 'src_rse' in req:
            src_rse = req['src_rse']
        elif 'src_rse' in response:
            src_rse = response['src_rse']

        # propagate the correct destination and protocol
        if 'dest_surl' not in details:
            dst_url = response['dst_url']
        else:
            dst_url = details['dest_surl']
        dst_protocol = dst_url.split(':')[0]
        if 'dst_rse' not in response and 'dst_rse' in req:
            dst_rse = req['dst_rse']
        elif 'dst_rse' in response:
            dst_rse = response['dst_rse']

        # propagate the correct error message
        if 'reason' not in details and 'reason' in response:
            reason = response['reason']
        elif 'reason' in details:
            reason = details['reason']

        if 'start_time' in details and details['start_time']:
            duration = (datetime.datetime.strptime(details['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                        datetime.datetime.strptime(details['start_time'], '%Y-%m-%dT%H:%M:%S')).seconds
        elif 'staging_start' in details and details['staging_start']:
            # In case of staging request
            duration = (datetime.datetime.strptime(details['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                        datetime.datetime.strptime(details['staging_start'], '%Y-%m-%dT%H:%M:%S')).seconds
        else:
            duration = -1

    add_message(transfer_status, {'activity': activity,
                                  'request-id': req['request_id'],
                                  'duration': duration,
                                  'checksum-adler': did_meta['adler32'],
                                  'checksum-md5': did_meta['md5'],
                                  'file-size': did_meta['bytes'],
                                  'guid': did_meta['guid'],
                                  'previous-request-id': req['previous_attempt_id'],
                                  'protocol': dst_protocol,
                                  'scope': req['scope'],
                                  'name': req['name'],
                                  'src-rse': src_rse,
                                  'src-url': src_url,
                                  'dst-rse': dst_rse,
                                  'dst-url': dst_url,
                                  'reason': reason,
                                  'transfer-endpoint': req['external_host'],
                                  'transfer-id': response['transfer_id'],
                                  'transfer-link': '%s/fts3/ftsmon/#/job/%s' % (req['external_host'].replace('8446', '8449'),
                                                                                response['transfer_id']),
                                  'tool-id': 'rucio-conveyor'},
                session=session)


@transactional_session
def update_bad_request(req, dest_rse, new_state, detail, session=None):
    if new_state == RequestState.FAILED:
        request.set_request_state(req['request_id'], new_state, session=session)

        activity = 'default'
        if req['attributes']:
            if type(req['attributes']) is dict:
                req_attributes = json.loads(json.dumps(req['attributes']))
            else:
                req_attributes = json.loads(str(req['attributes']))
            activity = req_attributes['activity'] if req_attributes['activity'] else 'default'

        tss = time.time()
        add_message('transfer-failed', {'activity': activity,
                                        'request-id': req['request_id'],
                                        'checksum-adler': None,
                                        'checksum-md5': None,
                                        'dst-rse': dest_rse,
                                        'dst-url': None,
                                        'name': req['name'],
                                        'guid': None,
                                        'file-size': None,
                                        'previous-request-id': req['request_id'],
                                        'protocol': None,
                                        'reason': detail,
                                        'transfer-link': None,
                                        'scope': req['scope'],
                                        'src-rse': None,
                                        'src-url': None,
                                        'tool-id': 'rucio-conveyor',
                                        'transfer-endpoint': config_get('conveyor', 'ftshosts'),
                                        'transfer-id': None},
                    session=session)

        request.archive_request(req['request_id'], session=session)
        logging.error('BAD DID %s:%s REQUEST %s details: %s' % (req['scope'],
                                                                req['name'],
                                                                req['request_id'],
                                                                detail))
        replica.update_replicas_states([{'rse': dest_rse,
                                         'scope': req['scope'],
                                         'name': req['name'],
                                         'state': ReplicaState.UNAVAILABLE}],
                                       session=session)
        tss = time.time()
        try:
            lock.failed_transfer(req['scope'],
                                 req['name'],
                                 req['dest_rse_id'],
                                 session=session)
        except:
            logging.warn('Could not update lock for failed transfer %s:%s at %s (%s)' % (req['scope'],
                                                                                         req['name'],
                                                                                         dest_rse,
                                                                                         sys.exc_info()[1]))
            return
        record_timer('daemons.conveyor.common.update_request_state.lock-failed_transfer', (time.time()-tss)*1000)
