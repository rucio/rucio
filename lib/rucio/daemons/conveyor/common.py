# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014


"""
Methods common to different conveyor daemons.
"""

import logging
import time

from rucio.core import lock, replica, request, rse
from rucio.core.monitor import record_timer
from rucio.db.constants import RequestState, ReplicaState


def update_request_state(req, response, session):
    """
    Used by poller and consumer to update the internal state of requests,
    after the response by the external transfertool.

    :param req: The internal request dictionary
    :param response: The transfertool response dictionary, retrieved via request.query_request()
    :param session: The database session to use
    """

    if response['new_state'] is not None:
        request.set_request_state(req['request_id'],
                                  response['new_state'],
                                  session=session)
        if response['new_state'] == RequestState.DONE:
            tss = time.time()
            try:
                lock.successful_transfer(req['scope'],
                                         req['name'],
                                         req['dest_rse_id'],
                                         session=session)
            except:
                session.rollback()
                logging.warn('Could not update lock for successful transfer %s:%s at %s' % (req['scope'],
                                                                                            req['name'],
                                                                                            req['dest_rse_id']))
                return
            record_timer('daemons.conveyor.common.update_request_state.001-lock-successful_transfer', (time.time()-tss)*1000)

            tss = time.time()
            rse_name = rse.get_rse_by_id(req['dest_rse_id'],
                                         session=session)['rse']
            record_timer('daemons.conveyor.common.update_request_state.002-replica-get_rse', (time.time()-tss)*1000)

            tss = time.time()
            replica.update_replicas_states([{'rse': rse_name,
                                             'scope': req['scope'],
                                             'name': req['name'],
                                             'state': ReplicaState.AVAILABLE}],
                                           session=session)
            record_timer('daemons.conveyor.common.update_request_state.003-replica-set_available', (time.time()-tss)*1000)

            tss = time.time()
            request.archive_request(req['request_id'],
                                    session=session)
            record_timer('daemons.conveyor.common.update_request_state.004-request-archive_successful', (time.time()-tss)*1000)

        elif response['new_state'] == RequestState.FAILED:
            tss = time.time()
            try:
                lock.failed_transfer(req['scope'],
                                     req['name'],
                                     req['dest_rse_id'],
                                     session=session)
            except:
                session.rollback()
                logging.warn('Could not update lock for failed transfer %s:%s at %s' % (req['scope'],
                                                                                        req['name'],
                                                                                        req['dest_rse_id']))
                return
            record_timer('daemons.conveyor.common.update_request_state.005-lock-failed_transfer', (time.time()-tss)*1000)

            tss = time.time()
            new_req = request.requeue_and_archive(req['request_id'], session=session)

            if new_req is None:
                logging.critical('EXCEEDED DID %s:%s REQUEST %s' % (req['scope'],
                                                                    req['name'],
                                                                    req['request_id']))
            else:
                logging.warn('REQUEUED DID %s:%s REQUEST %s AS %s TRY %s' % (req['scope'],
                                                                             req['name'],
                                                                             req['request_id'],
                                                                             new_req['request_id'],
                                                                             new_req['retry_count']))

            record_timer('daemons.conveyor.common.update_request_state.006-request.resubmit', (time.time()-tss)*1000)

        elif response['new_state'] == RequestState.LOST:
            tss = time.time()
            try:
                lock.failed_transfer(req['scope'],
                                     req['name'],
                                     req['dest_rse_id'],
                                     session=session)
            except:
                session.rollback()
                logging.warn('Could not update lock for failed transfer %s:%s at %s' % (req['scope'],
                                                                                        req['name'],
                                                                                        req['dest_rse_id']))
                return
            record_timer('daemons.conveyor.common.update_request_state.007-lock-failed_transfer', (time.time()-tss)*1000)

            logging.critical('LOST DID %s:%s REQUEST %s' % (req['scope'],
                                                            req['name'],
                                                            req['request_id']))

        logging.info('UPDATED REQUEST %s DID %s:%s AT %s TO %s' % (req['request_id'],
                                                                   req['scope'],
                                                                   req['name'],
                                                                   rse.get_rse_by_id(req['dest_rse_id'],
                                                                                     session=session)['rse'],
                                                                   response['new_state']))
