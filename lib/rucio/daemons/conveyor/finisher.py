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
from types import FrameType
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

from dogpile.cache.api import NoValue
from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get_list, config_get_bool
from rucio.common.exception import DatabaseException, UnsupportedOperation, ReplicaNotFound, RequestNotFound, RSEProtocolNotSupported
from rucio.common.logging import setup_logging
from rucio.common.stopwatch import Stopwatch
from rucio.common.types import InternalAccount
from rucio.common.utils import chunks
from rucio.core import request as request_core, replica as replica_core
from rucio.core.monitor import MetricManager
from rucio.core.rse import list_rses
from rucio.core.transfer import ProtocolFactory
from rucio.core.topology import Topology, ExpiringObjectCache
from rucio.daemons.common import db_workqueue, ProducerConsumerDaemon
from rucio.db.sqla.constants import MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED, ORACLE_DEADLOCK_DETECTED_REGEX, ORACLE_RESOURCE_BUSY_REGEX, RequestState, RequestType, ReplicaState, BadFilesStatus
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from rucio.daemons.common import HeartbeatHandler

GRACEFUL_STOP = threading.Event()

REGION = make_region_memcached(expiration_time=900)
METRICS = MetricManager(module=__name__)
DAEMON_NAME = 'conveyor-finisher'
FAILED_DURING_SUBMISSION_DELAY = datetime.timedelta(minutes=120)


def _fetch_requests(
        db_bulk,
        set_last_processed_by: bool,
        cached_topology,
        heartbeat_handler,
        activity,
):
    worker_number, total_workers, logger = heartbeat_handler.live()

    logger(logging.DEBUG, 'Working on activity %s', activity)

    topology = cached_topology.get() if cached_topology else Topology()

    get_requests_fnc = functools.partial(
        request_core.get_and_mark_next,
        rse_collection=topology,
        request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
        processed_by=heartbeat_handler.short_executable if set_last_processed_by else None,
        limit=db_bulk,
        total_workers=total_workers,
        worker_number=worker_number,
        mode_all=True,
        include_dependent=False,
        hash_variable='rule_id',
    )
    reqs = get_requests_fnc(
        state=[
            RequestState.DONE,
            RequestState.FAILED,
            RequestState.LOST,
            RequestState.SUBMISSION_FAILED,
            RequestState.NO_SOURCES,
            RequestState.ONLY_TAPE_SOURCES,
            RequestState.MISMATCH_SCHEME
        ],
    )
    reqs.extend(
        get_requests_fnc(
            state=[RequestState.SUBMITTING],
            older_than=datetime.datetime.utcnow() - FAILED_DURING_SUBMISSION_DELAY
        )
    )

    must_sleep = False
    if len(reqs) < db_bulk / 2:
        logger(logging.INFO, "Only %s transfers, which is less than half of the bulk %s", len(reqs), db_bulk)
        must_sleep = True
    return must_sleep, (reqs, topology)


def _handle_requests(
        batch,
        bulk,
        suspicious_patterns,
        retry_protocol_mismatches,
        *,
        logger=logging.log,
):
    reqs, topology = batch
    if not reqs:
        return

    try:
        logger(logging.DEBUG, 'Updating %i requests', len(reqs))

        total_stopwatch = Stopwatch()

        for chunk in chunks(reqs, bulk):
            try:
                stopwatch = Stopwatch()
                _finish_requests(topology, chunk, suspicious_patterns, retry_protocol_mismatches, logger=logger)
                METRICS.timer('handle_requests_time').observe(stopwatch.elapsed / (len(chunk) or 1))
                METRICS.counter('handle_requests').inc(len(chunk))
            except Exception as error:
                logger(logging.WARNING, '%s', str(error))

        logger(logging.DEBUG, 'Finish to update %s finished requests in %s seconds', len(reqs), total_stopwatch.elapsed)

    except (DatabaseException, DatabaseError) as error:
        if re.match(ORACLE_RESOURCE_BUSY_REGEX, error.args[0]) or re.match(ORACLE_DEADLOCK_DETECTED_REGEX, error.args[0]) or MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED in error.args[0]:
            logger(logging.WARNING, 'Lock detected when handling request - skipping: %s', str(error))
        else:
            raise


def finisher(
        once=False,
        sleep_time=60,
        activities=None,
        bulk=100,
        db_bulk=1000,
        partition_wait_time=10,
        cached_topology=None,
        total_threads=1,
):
    """
    Main loop to update the replicas and rules based on finished requests.
    """
    # Get suspicious patterns
    suspicious_patterns = config_get_list('conveyor', 'suspicious_pattern', default=[])
    suspicious_patterns = [re.compile(pat.strip()) for pat in suspicious_patterns]
    logging.log(logging.DEBUG, "Suspicious patterns: %s" % [pat.pattern for pat in suspicious_patterns])

    retry_protocol_mismatches = config_get_bool('conveyor', 'retry_protocol_mismatches', default=False)

    executable = DAEMON_NAME
    if activities:
        activities.sort()
        executable += '--activities ' + str(activities)

    @db_workqueue(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=executable,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        activities=activities,
    )
    def _db_producer(*, activity: str, heartbeat_handler: "HeartbeatHandler"):
        return _fetch_requests(
            db_bulk=db_bulk,
            cached_topology=cached_topology,
            activity=activity,
            set_last_processed_by=not once,
            heartbeat_handler=heartbeat_handler,
        )

    def _consumer(batch):
        return _handle_requests(
            batch=batch,
            bulk=bulk,
            suspicious_patterns=suspicious_patterns,
            retry_protocol_mismatches=retry_protocol_mismatches,
        )

    ProducerConsumerDaemon(
        producers=[_db_producer],
        consumers=[_consumer for _ in range(total_threads)],
        graceful_stop=GRACEFUL_STOP,
    ).run()


def stop(signum: Optional[int] = None, frame: Optional[FrameType] = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(once=False, total_threads=1, sleep_time=60, activities=None, bulk=100, db_bulk=1000):
    """
    Starts up the conveyer threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    cached_topology = ExpiringObjectCache(ttl=300, new_obj_fnc=lambda: Topology())
    finisher(
        once=once,
        activities=activities,
        bulk=bulk,
        db_bulk=db_bulk,
        sleep_time=sleep_time,
        cached_topology=cached_topology,
        total_threads=total_threads
    )


def _finish_requests(topology: "Topology", reqs, suspicious_patterns, retry_protocol_mismatches, logger=logging.log):
    """
    Used by finisher to handle terminated requests,

    :param reqs:                         List of requests.
    :param suspicious_patterns:          List of suspicious patterns.
    :param retry_protocol_mismatches:    Boolean to retry the transfer in case of protocol mismatch.
    """

    failed_during_submission = [RequestState.SUBMITTING, RequestState.SUBMISSION_FAILED, RequestState.LOST]
    failed_no_submission_attempts = [RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES, RequestState.MISMATCH_SCHEME]
    undeterministic_rses = __get_undeterministic_rses(logger=logger)
    protocol_factory = ProtocolFactory()
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
                    dst_rse = topology[req['dest_rse_id']].ensure_loaded(load_info=True)
                    pfn = req['dest_url']
                    scheme = urlparse(pfn).scheme
                    protocol = protocol_factory.protocol(dst_rse, scheme, 'write')
                    path = protocol.parse_pfns([pfn])[pfn]['path']
                    replica['path'] = os.path.join(path, os.path.basename(pfn))

                # replica should not be added to replicas until all info are filled
                replicas[req['request_type']][req['rule_id']].append(replica)

            # Standard failure from the transfer tool
            elif req['state'] == RequestState.FAILED:
                __check_suspicious_files(req, suspicious_patterns, logger=logger)
                try:
                    if request_core.should_retry_request(req, retry_protocol_mismatches):
                        new_req = request_core.requeue_and_archive(req, source_ranking_update=True, retry_protocol_mismatches=retry_protocol_mismatches, logger=logger)
                        # should_retry_request and requeue_and_archive are not in one session,
                        # another process can requeue_and_archive and this one will return None.
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
                try:
                    if request_core.should_retry_request(req, retry_protocol_mismatches):
                        new_req = request_core.requeue_and_archive(req, source_ranking_update=False, retry_protocol_mismatches=retry_protocol_mismatches, logger=logger)
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
    result = REGION.get(key)
    if isinstance(result, NoValue):
        rses_list = list_rses(filters={'deterministic': False})
        result = [rse['id'] for rse in rses_list]
        try:
            REGION.set(key, result)
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
                        if re.match(ORACLE_RESOURCE_BUSY_REGEX, error.args[0]) or re.match(ORACLE_DEADLOCK_DETECTED_REGEX, error.args[0]) or MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED in error.args[0]:
                            logger(logging.WARNING, "Locks detected when handling replica %s:%s at RSE %s", replica['scope'], replica['name'], replica['rse_id'])
                        else:
                            logger(logging.ERROR, "Could not finish handling replicas %s:%s at RSE %s", replica['scope'], replica['name'], replica['rse_id'], exc_info=True)
                    except Exception as error:
                        logger(logging.ERROR, "Something unexpected happened when updating replica state for transfer %s:%s at %s (%s)", replica['scope'], replica['name'], replica['rse_id'], str(error))
            except (DatabaseException, DatabaseError) as error:
                if re.match(ORACLE_RESOURCE_BUSY_REGEX, error.args[0]) or re.match(ORACLE_DEADLOCK_DETECTED_REGEX, error.args[0]) or MYSQL_LOCK_WAIT_TIMEOUT_EXCEEDED in error.args[0]:
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
def __update_bulk_replicas(replicas, *, session, logger=logging.log):
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
def __update_replica(replica, *, session, logger=logging.log):
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
