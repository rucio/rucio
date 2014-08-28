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


"""
Methods common to different conveyor daemons.
"""

import datetime
import logging
import sys
import time

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core import did, lock, replica, request, rse
from rucio.core.message import add_message
from rucio.core.monitor import record_timer
from rucio.db.constants import RequestState, ReplicaState
from rucio.db.session import transactional_session


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

    try:
        logging.debug('UPDATING REQUEST %s FOR TRANSFER STATE %s' % (str(req['request_id']), str(response['job_state'])))
    except:
        logging.error('Cannot get request_id and job_state')

    request.touch_request(req['request_id'], session=session)

    if response['new_state']:

        rse_name = None

        tss = time.time()
        try:
            rse_name = rse.get_rse_name(rse_id=req['dest_rse_id'],
                                        session=session)
        except exception.RSENotFound:
            logging.warning('RSE ID %s not found - Cannot proceed updating the state for this request' % req['dest_rse_id'])
            return False
        record_timer('daemons.conveyor.common.update_request_state.rse-get_rse_by_id', (time.time()-tss)*1000)

        tss = time.time()
        did_meta = did.get_metadata(req['scope'], req['name'], session=session)
        record_timer('daemons.conveyor.common.update_request_state.did-get_metadata', (time.time()-tss)*1000)

        request.set_request_state(req['request_id'],
                                  response['new_state'],
                                  session=session)

        details = request.query_request_details(req['request_id'], session=session)
        if not details:
            logging.warning('Could not request detailed transfer information - reporting will be missing values.')
        else:
            if type(details) == list or type(details) == tuple:
                details = details[0]  # there is always only one file

        if response['new_state'] == RequestState.DONE:

            tss = time.time()
            try:
                lock.successful_transfer(req['scope'],
                                         req['name'],
                                         req['dest_rse_id'],
                                         session=session)
            except:
                logging.warn('Could not update lock for successful transfer %s:%s at %s (%s)' % (req['scope'],
                                                                                                 req['name'],
                                                                                                 rse_name,
                                                                                                 sys.exc_info()[1]))
                raise

            record_timer('daemons.conveyor.common.update_request_state.lock-successful_transfer', (time.time()-tss)*1000)

            tss = time.time()
            try:
                logging.debug('UPDATE REPLICA STATE DID %s:%s RSE %s' % (req['scope'], req['name'], rse_name))
                replica.update_replicas_states([{'rse': rse_name,
                                                 'scope': req['scope'],
                                                 'name': req['name'],
                                                 'state': ReplicaState.AVAILABLE}],
                                               session=session)
                record_timer('daemons.conveyor.common.update_request_state.replica-update_replicas_states', (time.time()-tss)*1000)

                tss = time.time()

                request.archive_request(req['request_id'], session=session)

                if details and 'start_time' in details and details['start_time']:
                    duration = (datetime.datetime.strptime(details['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                                datetime.datetime.strptime(details['start_time'], '%Y-%m-%dT%H:%M:%S')).seconds
                elif details and 'staging_start' in details and details['staging_start']:
                    # In case of staging resquest
                    duration = (datetime.datetime.strptime(details['finish_time'], '%Y-%m-%dT%H:%M:%S') -
                                datetime.datetime.strptime(details['staging_start'], '%Y-%m-%dT%H:%M:%S')).seconds
                else:
                    # TODO: Proper error propagation
                    duration = -1

                if details:
                    add_message('transfer-done', {'activity': 'rucio-integration',  # no other support for now
                                                  'request-id': req['request_id'],
                                                  'duration': duration,
                                                  'file-size': did_meta['bytes'],
                                                  'guid': did_meta['guid'],
                                                  'previous-request-id': req['previous_attempt_id'],
                                                  'protocol': details['dest_surl'].split(':')[0],
                                                  'scope': req['scope'],
                                                  'name': req['name'],
                                                  'src-rse': response['details']['job_metadata']['src_rse'],
                                                  'src-url': details['source_surl'],
                                                  'dst-rse': response['details']['job_metadata']['dst_rse'],
                                                  'dst-url': details['dest_surl'],
                                                  'transfer-endpoint': config_get('conveyor', 'ftshosts'),
                                                  'transfer-id': response['transfer_id'],
                                                  'transfer-link': '%s/fts3/ftsmon/#/job/%s' % (config_get('conveyor', 'ftshosts').replace('8446', '8449'),
                                                                                                response['transfer_id']),
                                                  'tool-id': 'rucio-conveyor'},
                                session=session)

                record_timer('daemons.conveyor.common.update_request_state.request-archive_request', (time.time()-tss)*1000)
            except exception.UnsupportedOperation, e:
                # The replica doesn't exist
                request.archive_request(req['request_id'], session=session)
                logging.warning(e)
                return True

        elif response['new_state'] == RequestState.FAILED:
            tss = time.time()
            new_req = request.requeue_and_archive(req['request_id'], session=session)
            record_timer('daemons.conveyor.common.update_request_state.request-requeue_and_archive', (time.time()-tss)*1000)

            tss = time.time()
            add_message('transfer-failed', {'activity': 'rucio-integration',  # no other support for now
                                            'request-id': req['request_id'],
                                            'checksum-adler': did_meta['adler32'],
                                            'checksum-md5': did_meta['md5'],
                                            'dst-rse': response['details']['job_metadata']['dst_rse'],
                                            'dst-url': details['dest_surl'],
                                            'name': req['name'],
                                            'guid': did_meta['guid'],
                                            'file-size': did_meta['bytes'],
                                            'previous-request-id': req['request_id'],
                                            'protocol': details['dest_surl'].split(':')[0],
                                            'reason': details['reason'],
                                            'transfer-link': '%s/fts3/ftsmon/#/job/%s' % (config_get('conveyor', 'ftshosts').replace('8446', '8449'),
                                                                                          response['transfer_id']),
                                            'scope': req['scope'],
                                            'src-rse': response['details']['job_metadata']['src_rse'],
                                            'src-url': details['source_surl'],
                                            'tool-id': 'rucio-conveyor',
                                            'transfer-endpoint': config_get('conveyor', 'ftshosts'),
                                            'transfer-id': response['transfer_id']},
                        session=session)
            if new_req is None:
                logging.critical('EXCEEDED DID %s:%s REQUEST %s' % (req['scope'],
                                                                    req['name'],
                                                                    req['request_id']))
                replica.update_replicas_states([{'rse': rse_name,
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
                                                                                                 rse_name,
                                                                                                 sys.exc_info()[1]))
                    raise
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

            add_message('transfer-lost', {'activity': 'rucio-integration',  # no other support for now
                                          'request-id': req['request_id'],
                                          'checksum-adler': did_meta['adler32'],
                                          'checksum-md5': did_meta['md5'],
                                          'dst-rse': response['details']['job_metadata']['dst_rse'],
                                          'dst-url': details['dest_surl'],
                                          'name': req['name'],
                                          'guid': did_meta['guid'],
                                          'file-size': did_meta['bytes'],
                                          'previous-request-id': req['request_id'],
                                          'protocol': details['dest_surl'].split(':')[0],
                                          'reason': details['reason'],
                                          'transfer-link': '%s/fts3/ftsmon/#/job/%s' % (config_get('conveyor', 'ftshosts').replace('8446', '8449'),
                                                                                        response['transfer_id']),
                                          'scope': req['scope'],
                                          'src-rse': response['details']['job_metadata']['src_rse'],
                                          'src-url': details['source_surl'],
                                          'tool-id': 'rucio-conveyor',
                                          'transfer-endpoint': config_get('conveyor', 'ftshosts'),
                                          'transfer-id': response['transfer_id']},
                        session=session)

            request.archive_request(req['request_id'], session=session)
            logging.critical('LOST DID %s:%s REQUEST %s' % (req['scope'],
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
                raise

        logging.info('UPDATED REQUEST %s DID %s:%s AT %s TO %s' % (req['request_id'],
                                                                   req['scope'],
                                                                   req['name'],
                                                                   rse_name,
                                                                   response['new_state']))

    return True


@transactional_session
def update_requests_states(reqs, session=None):
    for req, response in reqs:
        update_request_state(req=req, response=response, session=session)
