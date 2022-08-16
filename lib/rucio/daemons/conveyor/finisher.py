# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Conveyor finisher is a daemon to update replicas and rules based on requests.
"""

import datetime
import functools
import logging
import os
import re
import threading

from dogpile.cache.api import NoValue
from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.cache import make_region_memcached
from rucio.common.exception import DatabaseException, ConfigNotFound, UnsupportedOperation, ReplicaNotFound, RequestNotFound, RSEProtocolNotSupported
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.common.utils import chunks
from rucio.core import request as request_core, replica as replica_core
from rucio.core.config import items
from rucio.core.monitor import record_counter, Timer
from rucio.core.rse import list_rses
from rucio.daemons.common import run_daemon
from rucio.db.sqla.constants import RequestState, RequestType, ReplicaState, BadFilesStatus
from rucio.db.sqla.session import transactional_session
from rucio.rse import rsemanager

from urllib.parse import urlparse

graceful_stop = threading.Event()

region = make_region_memcached(expiration_time=900)


def run_once(bulk, db_bulk, suspicious_patterns, retry_protocol_mismatches, heartbeat_handler, activity):
    worker_number, total_workers, logger = heartbeat_handler.live()

    try:
        logger(logging.DEBUG, 'Working on activity %s', activity)

        with Timer('daemons.conveyor.finisher.get_next'):
            reqs = request_core.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                         state=[RequestState.DONE, RequestState.FAILED,
                                                RequestState.LOST, RequestState.SUBMITTING,
                                                RequestState.SUBMISSION_FAILED, RequestState.NO_SOURCES,
                                                RequestState.ONLY_TAPE_SOURCES, RequestState.MISMATCH_SCHEME],
                                         limit=db_bulk,
                                         older_than=datetime.datetime.utcnow(),
                                         total_workers=total_workers,
                                         worker_number=worker_number,
                                         mode_all=True,
                                         include_dependent=False,
                                         hash_variable='rule_id')

        if reqs:
            logger(logging.DEBUG, 'Updating %i requests for activity %s', len(reqs), activity)

        timer = Timer()

        for chunk in chunks(reqs, bulk):
            try:
                worker_number, total_workers, logger = heartbeat_handler.live()
                with Timer('daemons.conveyor.finisher.handle_requests_time', divisor=len(chunk) or 1):
                    __handle_requests(chunk, suspicious_patterns, retry_protocol_mismatches, logger=logger)
                record_counter('daemons.conveyor.finisher.handle_requests', delta=len(chunk))
            except Exception as error:
                logger(logging.WARNING, '%s', str(error))

        timer.stop()

        if reqs:
            logger(logging.DEBUG, 'Finish to update %s finished requests for activity %s in %s seconds', len(reqs), activity, timer.elapsed)

    except (DatabaseException, DatabaseError) as error:
        if re.match('.*ORA-00054.*', error.args[0]) or re.match('.*ORA-00060.*', error.args[0]) or 'ERROR 1205 (HY000)' in error.args[0]:
            logger(logging.WARNING, 'Lock detected when handling request - skipping: %s', str(error))
        else:
            raise
    return True


def finisher(once=False, sleep_time=60, activities=None, bulk=100, db_bulk=1000, partition_wait_time=10):
    """
    Main loop to update the replicas and rules based on finished requests.
    """
    try:
        conveyor_config = {item[0]: item[1] for item in items('conveyor')}
    except ConfigNotFound:
        logging.log(logging.INFO, 'No configuration found for conveyor')
        conveyor_config = {}

    # Get suspicious patterns
    suspicious_patterns = conveyor_config.get('suspicious_pattern', [])
    if suspicious_patterns:
        pattern = str(suspicious_patterns)
        patterns = pattern.split(",")
        suspicious_patterns = [re.compile(pat.strip()) for pat in patterns]
    logging.log(logging.DEBUG, "Suspicious patterns: %s" % [pat.pattern for pat in suspicious_patterns])

    retry_protocol_mismatches = conveyor_config.get('retry_protocol_mismatches', False)

    logger_prefix = executable = 'conveyor-finisher'
    if activities:
        activities.sort()
        executable += '--activities ' + str(activities)

    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        logger_prefix=logger_prefix,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            bulk=bulk,
            db_bulk=db_bulk,
            suspicious_patterns=suspicious_patterns,
            retry_protocol_mismatches=retry_protocol_mismatches,
        ),
        activities=activities,
    )


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, total_threads=1, sleep_time=60, activities=None, bulk=100, db_bulk=1000):
    """
    Starts up the conveyer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.log(logging.INFO, 'executing one finisher iteration only')
        finisher(once=once, activities=activities, bulk=bulk, db_bulk=db_bulk)

    else:

        logging.log(logging.INFO, 'starting finisher threads')
        threads = [threading.Thread(target=finisher, kwargs={'sleep_time': sleep_time,
                                                             'activities': activities,
                                                             'db_bulk': db_bulk,
                                                             'bulk': bulk}) for _ in range(0, total_threads)]

        [thread.start() for thread in threads]

        logging.log(logging.INFO, 'waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads:
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]


def __handle_requests(reqs, suspicious_patterns, retry_protocol_mismatches, logger=logging.log):
    """
    Used by finisher to handle terminated requests,

    :param reqs:                         List of requests.
    :param suspicious_patterns:          List of suspicious patterns.
    :param retry_protocol_mismatches:    Boolean to retry the transfer in case of protocol mismatch.
    :param prepend_str: String to prepend to logging.
    """

    failed_during_submission = [RequestState.SUBMITTING, RequestState.SUBMISSION_FAILED, RequestState.LOST]
    failed_no_submission_attempts = [RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES, RequestState.MISMATCH_SCHEME]
    undeterministic_rses = __get_undeterministic_rses(logger=logger)
    rses_info, protocols = {}, {}
    replicas = {}
    for req in reqs:
        try:
            replica = {'scope': req['scope'], 'name': req['name'], 'rse_id': req['dest_rse_id'], 'bytes': req['bytes'], 'adler32': req['adler32'], 'request_id': req['request_id']}

            replica['pfn'] = req['dest_url']
            replica['request_type'] = req['request_type']
            replica['error_message'] = None

            if req['request_type'] not in replicas:
                replicas[req['request_type']] = {}
            if req['rule_id'] not in replicas[req['request_type']]:
                replicas[req['request_type']][req['rule_id']] = []

            if req['state'] == RequestState.DONE:
                replica['state'] = ReplicaState.AVAILABLE
                replica['archived'] = False

                # for TAPE, replica path is needed
                if req['request_type'] in (RequestType.TRANSFER, RequestType.STAGEIN) and req['dest_rse_id'] in undeterministic_rses:
                    if req['dest_rse_id'] not in rses_info:
                        rses_info[req['dest_rse_id']] = rsemanager.get_rse_info(rse_id=req['dest_rse_id'])
                    pfn = req['dest_url']
                    scheme = urlparse(pfn).scheme
                    dest_rse_id_scheme = '%s_%s' % (req['dest_rse_id'], scheme)
                    if dest_rse_id_scheme not in protocols:
                        protocols[dest_rse_id_scheme] = rsemanager.create_protocol(rses_info[req['dest_rse_id']], 'write', scheme)
                    path = protocols[dest_rse_id_scheme].parse_pfns([pfn])[pfn]['path']
                    replica['path'] = os.path.join(path, os.path.basename(pfn))

                # replica should not be added to replicas until all info are filled
                replicas[req['request_type']][req['rule_id']].append(replica)

            # Standard failure from the transfer tool
            elif req['state'] == RequestState.FAILED:
                __check_suspicious_files(req, suspicious_patterns, logger=logger)
                timer = Timer()
                try:
                    if request_core.should_retry_request(req, retry_protocol_mismatches):
                        new_req = request_core.requeue_and_archive(req, source_ranking_update=True, retry_protocol_mismatches=retry_protocol_mismatches, logger=logger)
                        # should_retry_request and requeue_and_archive are not in one session,
                        # another process can requeue_and_archive and this one will return None.
                        timer.record('daemons.conveyor.common.update_request_state.request_requeue_and_archive')
                        logger(logging.WARNING, 'REQUEUED DID %s:%s REQUEST %s AS %s TRY %s' % (req['scope'],
                                                                                                req['name'],
                                                                                                req['request_id'],
                                                                                                new_req['request_id'],
                                                                                                new_req['retry_count']))
                    else:
                        # No new_req is return if should_retry_request returns False
                        logger(logging.WARNING, 'EXCEEDED SUBMITTING DID %s:%s REQUEST %s in state %s', req['scope'], req['name'], req['request_id'], req['state'])
                        replica['state'] = ReplicaState.UNAVAILABLE
                        replica['archived'] = False
                        replica['error_message'] = req['err_msg'] if req['err_msg'] else request_core.get_transfer_error(req['state'])
                        replicas[req['request_type']][req['rule_id']].append(replica)
                except RequestNotFound:
                    logger(logging.WARNING, 'Cannot find request %s anymore', req['request_id'])

            # All other failures
            elif req['state'] in failed_during_submission or req['state'] in failed_no_submission_attempts:
                if req['state'] in failed_during_submission and req['updated_at'] > (datetime.datetime.utcnow() - datetime.timedelta(minutes=120)):
                    # To prevent race conditions
                    continue
                try:
                    timer = Timer()
                    if request_core.should_retry_request(req, retry_protocol_mismatches):
                        new_req = request_core.requeue_and_archive(req, source_ranking_update=False, retry_protocol_mismatches=retry_protocol_mismatches, logger=logger)
                        timer.record('daemons.conveyor.common.update_request_state.request_requeue_and_archive')
                        logger(logging.WARNING, 'REQUEUED SUBMITTING DID %s:%s REQUEST %s AS %s TRY %s' % (req['scope'],
                                                                                                           req['name'],
                                                                                                           req['request_id'],
                                                                                                           new_req['request_id'],
                                                                                                           new_req['retry_count']))
                    else:
                        # No new_req is return if should_retry_request returns False
                        logger(logging.WARNING, 'EXCEEDED SUBMITTING DID %s:%s REQUEST %s in state %s', req['scope'], req['name'], req['request_id'], req['state'])
                        replica['state'] = ReplicaState.UNAVAILABLE
                        replica['archived'] = False
                        replica['error_message'] = req['err_msg'] if req['err_msg'] else request_core.get_transfer_error(req['state'])
                        replicas[req['request_type']][req['rule_id']].append(replica)
                except RequestNotFound:
                    logger(logging.WARNING, 'Cannot find request %s anymore', req['request_id'])

        except Exception as error:
            logger(logging.ERROR, "Something unexpected happened when handling request %s(%s:%s) at %s: %s" % (req['request_id'],
                                                                                                               req['scope'],
                                                                                                               req['name'],
                                                                                                               req['dest_rse_id'],
                                                                                                               str(error)))

    __handle_terminated_replicas(replicas, logger=logger)


def __get_undeterministic_rses(logger=logging.log):
    """
    Get the undeterministic rses from the database

    :returns:  List of undeterministc rses
    """
    key = 'undeterministic_rses'
    result = region.get(key)
    if isinstance(result, NoValue):
        rses_list = list_rses(filters={'deterministic': False})
        result = [rse['id'] for rse in rses_list]
        try:
            region.set(key, result)
        except Exception as error:
            logger(logging.WARNING, "Failed to set dogpile cache, error: %s", str(error))
    return result


def __check_suspicious_files(req, suspicious_patterns, logger=logging.log):
    """
    Check suspicious files when a transfer failed.

    :param req:                  Request object.
    :param suspicious_patterns:  A list of regexp pattern object.
    """
    is_suspicious = False
    if not suspicious_patterns:
        return is_suspicious

    try:
        logger(logging.DEBUG, "Checking suspicious file for request: %s, transfer error: %s", req['request_id'], req['err_msg'])
        for pattern in suspicious_patterns:
            if pattern.match(req['err_msg']):
                is_suspicious = True
                break

        if is_suspicious:
            reason = req['err_msg'][:255]
            urls = request_core.get_sources(req['request_id'], rse_id=req['source_rse_id'])
            if urls:
                pfns = []
                for url in urls:
                    pfns.append(url['url'])
                if pfns:
                    logger(logging.DEBUG, "Found suspicious urls: %s", str(pfns))
                    replica_core.declare_bad_file_replicas(pfns, reason=reason, issuer=InternalAccount('root', vo=req['scope'].vo), status=BadFilesStatus.SUSPICIOUS)
    except Exception as error:
        logger(logging.WARNING, "Failed to check suspicious file with request: %s - %s", req['request_id'], str(error))
    return is_suspicious


def __handle_terminated_replicas(replicas, logger=logging.log):
    """
    Used by finisher to handle available and unavailable replicas.

    :param replicas: List of replicas.
    :param prepend_str: String to prepend to logging.
    """

    for req_type in replicas:
        for rule_id in replicas[req_type]:
            try:
                __update_bulk_replicas(replicas[req_type][rule_id], logger=logger)
            except (UnsupportedOperation, ReplicaNotFound):
                # one replica in the bulk cannot be found. register it one by one
                logger(logging.WARNING, 'Problem to bulk update the replicas states. Will try one by one')
                for replica in replicas[req_type][rule_id]:
                    try:
                        __update_replica(replica, logger=logger)
                    except (DatabaseException, DatabaseError) as error:
                        if re.match('.*ORA-00054.*', error.args[0]) or re.match('.*ORA-00060.*', error.args[0]) or 'ERROR 1205 (HY000)' in error.args[0]:
                            logger(logging.WARNING, "Locks detected when handling replica %s:%s at RSE %s", replica['scope'], replica['name'], replica['rse_id'])
                        else:
                            logger(logging.ERROR, "Could not finish handling replicas %s:%s at RSE %s", replica['scope'], replica['name'], replica['rse_id'], exc_info=True)
                    except Exception as error:
                        logger(logging.ERROR, "Something unexpected happened when updating replica state for transfer %s:%s at %s (%s)", replica['scope'], replica['name'], replica['rse_id'], str(error))
            except (DatabaseException, DatabaseError) as error:
                if re.match('.*ORA-00054.*', error.args[0]) or re.match('.*ORA-00060.*', error.args[0]) or 'ERROR 1205 (HY000)' in error.args[0]:
                    logger(logging.WARNING, "Locks detected when handling replicas on %s rule %s, update updated time.", req_type, rule_id)
                    try:
                        request_core.touch_requests_by_rule(rule_id)
                    except (DatabaseException, DatabaseError):
                        logger(logging.ERROR, "Failed to touch requests by rule(%s)", rule_id, exc_info=True)
                else:
                    logger(logging.ERROR, "Could not finish handling replicas on %s rule %s", req_type, rule_id, exc_info=True)
            except Exception:
                logger(logging.ERROR, "Something unexpected happened when handling replicas on %s rule %s", req_type, rule_id, exc_info=True)


@transactional_session
def __update_bulk_replicas(replicas, session=None, logger=logging.log):
    """
    Used by finisher to handle available and unavailable replicas blongs to same rule in bulk way.

    :param replicas:              List of replicas.
    :param session:               The database session to use.
    :returns commit_or_rollback:  Boolean.
    """
    try:
        replica_core.update_replicas_states(replicas, nowait=True, session=session)
    except ReplicaNotFound as error:
        logger(logging.WARNING, 'Failed to bulk update replicas, will do it one by one: %s', str(error))
        raise ReplicaNotFound(error)

    for replica in replicas:
        if not replica['archived']:
            request_core.archive_request(replica['request_id'], session=session)
        logger(logging.INFO, "HANDLED REQUEST %s DID %s:%s AT RSE %s STATE %s", replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state']))
    return True


@transactional_session
def __update_replica(replica, session=None, logger=logging.log):
    """
    Used by finisher to update a replica to a finished state.

    :param replica:               Replica as a dictionary.
    :param rule_id:               RULE id.
    :param session:               The database session to use.
    :returns commit_or_rollback:  Boolean.
    """
    try:
        replica_found = True
        try:
            replica_core.update_replicas_states([replica], nowait=True, session=session)
        except ReplicaNotFound:
            replica_found = False

        if not replica_found and replica['state'] == ReplicaState.AVAILABLE and replica['request_type'] != RequestType.STAGEIN:
            # FTS tells us that the Replica was successfully transferred, but there is no such replica in Rucio,
            # this can happen if the replica was deleted from rucio in the meantime. As fts tells us that the
            # replica is available, there is a high probability that we just generated dark data.
            # This opportunistic workflow tries to cleanup this dark data by adding a replica with an expired
            # tombstone and letting reaper take care of its deletion.
            logger(logging.INFO, "Replica cannot be found. Adding a replica %s:%s AT RSE %s with tombstone=utcnow", replica['scope'], replica['name'], replica['rse_id'])
            add_replica_kwargs = {
                'rse_id': replica['rse_id'],
                'scope': replica['scope'],
                'name': replica['name'],
                'bytes_': replica['bytes'],
                'account': InternalAccount('root', vo=replica['scope'].vo),  # it will deleted immediately, do we need to get the accurate account from rule?
                'adler32': replica['adler32'],
                'tombstone': datetime.datetime.utcnow(),
            }
            try:
                try:
                    replica_core.add_replica(**add_replica_kwargs, pfn=replica['pfn'] if 'pfn' in replica else None, session=session)
                except RSEProtocolNotSupported as error:
                    # The pfn cannot be matched to any of the protocols configured on the RSE.
                    # Most probably the RSE protocol configuration changed since the submission.
                    # Try again without explicit pfn. On non-deterministic RSEs it will fail
                    # with UnsupportedOperation exception
                    logger(logging.ERROR, 'Protocol not supported for DID %s:%s at RSE %s - potential dark data - %s', replica['scope'], replica['name'], replica['rse_id'], str(error))
                    replica_core.add_replica(**add_replica_kwargs, pfn=None, session=session)
            except Exception as error:
                logger(logging.ERROR, 'Cannot register replica for DID %s:%s at RSE %s - potential dark data - %s', replica['scope'], replica['name'], replica['rse_id'], str(error))
                raise

        if not replica['archived']:
            request_core.archive_request(replica['request_id'], session=session)

    except Exception as error:
        logger(logging.WARNING, "ERROR WHEN HANDLING REQUEST %s DID %s:%s AT RSE %s STATE %s: %s", replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state']), str(error))
        raise

    logger(logging.INFO, "HANDLED REQUEST %s DID %s:%s AT RSE %s STATE %s", replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state']))
