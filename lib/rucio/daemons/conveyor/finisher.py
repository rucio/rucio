# Copyright 2015-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Wen Guan <wguan.icedew@gmail.com>, 2015-2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2015
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017-2018

"""
Conveyor finisher is a daemon to update replicas and rules based on requests.
"""

import datetime
import logging
import os
import re
import socket
import sys
import threading
import time
import traceback

from urlparse import urlparse

from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from sqlalchemy.exc import DatabaseError

from rucio.common.config import config_get
from rucio.common.utils import chunks
from rucio.common.exception import DatabaseException, ConfigNotFound, UnsupportedOperation, ReplicaNotFound
from rucio.core import request as request_core, heartbeat, replica as replica_core
from rucio.core.config import get
from rucio.core.monitor import record_timer, record_counter
from rucio.core.rse import list_rses, get_rse_name, get_rse
from rucio.db.sqla.constants import RequestState, RequestType, ReplicaState, BadFilesStatus
from rucio.db.sqla.session import transactional_session
from rucio.rse import rsemanager


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()

region = make_region().configure('dogpile.cache.memory', expiration_time=3600)


def finisher(once=False, process=0, total_processes=1, thread=0, total_threads=1, sleep_time=60, activities=None, bulk=100, db_bulk=1000):
    """
    Main loop to update the replicas and rules based on finished requests.
    """

    logging.info('finisher starting - process (%i/%i) thread (%i/%i) db_bulk(%i) bulk (%i)' % (process, total_processes,
                                                                                               thread, total_threads,
                                                                                               db_bulk, bulk))
    try:
        suspicious_patterns = []
        pattern = get(section='conveyor', option='suspicious_pattern', session=None)
        pattern = str(pattern)
        patterns = pattern.split(",")
        for pat in patterns:
            suspicious_patterns.append(re.compile(pat.strip()))
    except ConfigNotFound:
        suspicious_patterns = []
    logging.debug("Suspicious patterns: %s" % [pat.pattern for pat in suspicious_patterns])

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    # Make an initial heartbeat so that all finishers have the correct worker number on the next try
    hb = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'] + 1, hb['nr_threads'])
    graceful_stop.wait(10)
    while not graceful_stop.is_set():

        start_time = time.time()
        try:
            hb = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'] + 1, hb['nr_threads'])
            logging.debug(prepend_str + 'Starting new cycle')
            if activities is None:
                activities = [None]

            for activity in activities:
                logging.debug(prepend_str + 'Working on activity %s' % activity)
                ts = time.time()
                reqs = request_core.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                             state=[RequestState.DONE, RequestState.FAILED, RequestState.LOST, RequestState.SUBMITTING,
                                                    RequestState.SUBMISSION_FAILED, RequestState.NO_SOURCES, RequestState.ONLY_TAPE_SOURCES],
                                             limit=db_bulk,
                                             older_than=datetime.datetime.utcnow(),
                                             activity=activity,
                                             process=process, total_processes=total_processes,
                                             thread=hb['assign_thread'], total_threads=hb['nr_threads'])
                record_timer('daemons.conveyor.finisher.000-get_next', (time.time() - ts) * 1000)
                stime1 = time.time()
                if reqs:
                    logging.debug(prepend_str + 'Updating %i requests for activity %s' % (len(reqs), activity))

                for chunk in chunks(reqs, bulk):
                    try:
                        ts = time.time()
                        __handle_requests(chunk, suspicious_patterns)
                        record_timer('daemons.conveyor.finisher.handle_requests', (time.time() - ts) * 1000 / (len(chunk) if len(chunk) else 1))
                        record_counter('daemons.conveyor.finisher.handle_requests', len(chunk))
                    except:
                        logging.warn(str(traceback.format_exc()))
                if reqs:
                    logging.debug(prepend_str + 'Finish to update %s finished requests for activity %s in %s seconds' % (len(reqs), activity, time.time() - stime1))

        except (DatabaseException, DatabaseError) as error:
            if isinstance(error.args[0], tuple) and (re.match('.*ORA-00054.*', error.args[0][0]) or ('ERROR 1205 (HY000)' in error.args[0][0])):
                logging.warn(prepend_str + 'Lock detected when handling request - skipping: %s' % (str(error)))
            else:
                logging.error(prepend_str + '%s' % (traceback.format_exc()))
        except:
            logging.critical(prepend_str + '%s' % (traceback.format_exc()))
        end_time = time.time()
        time_diff = end_time - start_time
        if time_diff < sleep_time:
            logging.info(prepend_str + 'Sleeping for a while :  %s seconds' % (sleep_time - time_diff))
            graceful_stop.wait(sleep_time - time_diff)

        if once:
            return

    logging.info(prepend_str + 'Graceful stop requests')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info(prepend_str + 'Graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1, sleep_time=60, activities=None, bulk=100, db_bulk=1000):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one finisher iteration only')
        finisher(once=once, activities=activities, bulk=bulk, db_bulk=db_bulk)

    else:

        logging.info('starting finisher threads')
        threads = [threading.Thread(target=finisher, kwargs={'process': process,
                                                             'total_processes': total_processes,
                                                             'thread': i,
                                                             'total_threads': total_threads,
                                                             'sleep_time': sleep_time,
                                                             'activities': activities,
                                                             'db_bulk': db_bulk,
                                                             'bulk': bulk}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            threads = [t.join(timeout=3.14) for t in threads if t and t.isAlive()]


def __handle_requests(reqs, suspicious_patterns):
    """
    Used by finisher to handle terminated requests,

    :param reqs: List of requests.
    """

    undeterministic_rses = __get_undeterministic_rses()
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
                if req['request_type'] == RequestType.TRANSFER and req['dest_rse_id'] in undeterministic_rses:
                    if req['dest_rse_id'] not in rses_info:
                        dest_rse = get_rse_name(rse_id=req['dest_rse_id'])
                        rses_info[req['dest_rse_id']] = rsemanager.get_rse_info(dest_rse)
                    pfn = req['dest_url']
                    scheme = urlparse(pfn).scheme
                    dest_rse_id_scheme = '%s_%s' % (req['dest_rse_id'], scheme)
                    if dest_rse_id_scheme not in protocols:
                        protocols[dest_rse_id_scheme] = rsemanager.create_protocol(rses_info[req['dest_rse_id']], 'write', scheme)
                    path = protocols[dest_rse_id_scheme].parse_pfns([pfn])[pfn]['path']
                    replica['path'] = os.path.join(path, os.path.basename(pfn))

                # replica should not be added to replicas until all info are filled
                replicas[req['request_type']][req['rule_id']].append(replica)

            elif req['state'] == RequestState.FAILED:
                __check_suspicious_files(req, suspicious_patterns)
                if request_core.should_retry_request(req):
                    tss = time.time()
                    new_req = request_core.requeue_and_archive(req['request_id'])
                    record_timer('daemons.conveyor.common.update_request_state.request-requeue_and_archive', (time.time() - tss) * 1000)
                    if new_req:
                        # should_retry_request and requeue_and_archive are not in one session,
                        # another process can requeue_and_archive and this one will return None.
                        logging.warn('REQUEUED DID %s:%s REQUEST %s AS %s TRY %s' % (req['scope'],
                                                                                     req['name'],
                                                                                     req['request_id'],
                                                                                     new_req['request_id'],
                                                                                     new_req['retry_count']))
                else:
                    logging.warn('EXCEEDED DID %s:%s REQUEST %s' % (req['scope'], req['name'], req['request_id']))
                    replica['state'] = ReplicaState.UNAVAILABLE
                    replica['archived'] = False
                    replica['error_message'] = req['err_msg'] if req['err_msg'] else request_core.get_transfer_error(req['state'])
                    replicas[req['request_type']][req['rule_id']].append(replica)
            elif req['state'] == RequestState.SUBMITTING or req['state'] == RequestState.SUBMISSION_FAILED or req['state'] == RequestState.LOST:
                if req['updated_at'] > (datetime.datetime.utcnow() - datetime.timedelta(minutes=120)):
                    continue

                if request_core.should_retry_request(req):
                    tss = time.time()
                    new_req = request_core.requeue_and_archive(req['request_id'])
                    record_timer('daemons.conveyor.common.update_request_state.request-requeue_and_archive', (time.time() - tss) * 1000)
                    if new_req:
                        logging.warn('REQUEUED SUBMITTING DID %s:%s REQUEST %s AS %s TRY %s' % (req['scope'],
                                                                                                req['name'],
                                                                                                req['request_id'],
                                                                                                new_req['request_id'],
                                                                                                new_req['retry_count']))
                else:
                    logging.warn('EXCEEDED SUBMITTING DID %s:%s REQUEST %s' % (req['scope'], req['name'], req['request_id']))
                    replica['state'] = ReplicaState.UNAVAILABLE
                    replica['archived'] = False
                    replica['error_message'] = req['err_msg'] if req['err_msg'] else request_core.get_transfer_error(req['state'])
                    replicas[req['request_type']][req['rule_id']].append(replica)
            elif req['state'] == RequestState.NO_SOURCES or req['state'] == RequestState.ONLY_TAPE_SOURCES or req['state'] == RequestState.MISMATCH_SCHEME:
                if request_core.should_retry_request(req):
                    tss = time.time()
                    new_req = request_core.requeue_and_archive(req['request_id'])
                    record_timer('daemons.conveyor.common.update_request_state.request-requeue_and_archive', (time.time() - tss) * 1000)
                    if new_req:
                        # should_retry_request and requeue_and_archive are not in one session,
                        # another process can requeue_and_archive and this one will return None.
                        logging.warn('REQUEUED DID %s:%s REQUEST %s AS %s TRY %s' % (req['scope'],
                                                                                     req['name'],
                                                                                     req['request_id'],
                                                                                     new_req['request_id'],
                                                                                     new_req['retry_count']))
                else:
                    logging.warn('EXCEEDED DID %s:%s REQUEST %s' % (req['scope'], req['name'], req['request_id']))
                    replica['state'] = ReplicaState.UNAVAILABLE  # should be broken here
                    replica['archived'] = False
                    replica['error_message'] = req['err_msg'] if req['err_msg'] else request_core.get_transfer_error(req['state'])
                    replicas[req['request_type']][req['rule_id']].append(replica)

        except:
            logging.error("Something unexpected happened when handling request %s(%s:%s) at %s: %s" % (req['request_id'],
                                                                                                       req['scope'],
                                                                                                       req['name'],
                                                                                                       req['dest_rse_id'],
                                                                                                       traceback.format_exc()))

    __handle_terminated_replicas(replicas)


def __get_undeterministic_rses():
    """
    Get the undeterministic rses from the database

    :returns:  List of undeterministc rses
    """
    key = 'undeterministic_rses'
    result = region.get(key)
    if type(result) is NoValue:
        rses_list = list_rses(filters={'deterministic': False})
        result = [rse['id'] for rse in rses_list]
        try:
            region.set(key, result)
        except:
            logging.warning("Failed to set dogpile cache, error: %s" % (traceback.format_exc()))
    return result


def __check_suspicious_files(req, suspicious_patterns):
    """
    Check suspicious files when a transfer failed.

    :param req:                  Request object.
    :param suspicious_patterns:  A list of regexp pattern object.
    """
    if not suspicious_patterns:
        return
    is_suspicious = False

    try:
        logging.debug("Checking suspicious file for request: %s, transfer error: %s" % (req['request_id'], req['err_msg']))
        for pattern in suspicious_patterns:
            if pattern.match(req['err_msg']):
                is_suspicious = True
                break

        if is_suspicious:
            reason = 'Reported by conveyor'
            urls = request_core.get_sources(req['request_id'], rse_id=req['source_rse_id'])
            if urls:
                pfns = []
                for url in urls:
                    pfns.append(url['url'])
                if pfns:
                    logging.debug("Found suspicious urls: %s" % pfns)
                    replica_core.declare_bad_file_replicas(pfns, reason=reason, issuer='root', status=BadFilesStatus.SUSPICIOUS)
    except Exception as error:
        logging.warning("Failed to check suspicious file with request: %s - %s" % (req['request_id'], str(error)))
    return is_suspicious


def __handle_terminated_replicas(replicas):
    """
    Used by finisher to handle available and unavailable replicas.

    :param replicas: List of replicas.
    """

    for req_type in replicas:
        for rule_id in replicas[req_type]:
            try:
                __update_bulk_replicas(replicas[req_type][rule_id], req_type, rule_id)
            except (UnsupportedOperation, ReplicaNotFound):
                # one replica in the bulk cannot be found. register it one by one
                for replica in replicas[req_type][rule_id]:
                    try:
                        __update_replica(replica, req_type, rule_id)
                    except (DatabaseException, DatabaseError) as error:
                        if isinstance(error.args[0], tuple) and (re.match('.*ORA-00054.*', error.args[0][0]) or ('ERROR 1205 (HY000)' in error.args[0][0])):
                            logging.warn("Locks detected when handling replica %s:%s at RSE %s" % (replica['scope'], replica['name'], replica['rse_id']))
                        else:
                            logging.error("Could not finish handling replicas %s:%s at RSE %s (%s)" % (replica['scope'], replica['name'], replica['rse_id'], traceback.format_exc()))
                    except:
                        logging.error("Something unexpected happened when updating replica state for transfer %s:%s at %s (%s)" % (replica['scope'],
                                                                                                                                   replica['name'],
                                                                                                                                   replica['rse_id'],
                                                                                                                                   traceback.format_exc()))
            except (DatabaseException, DatabaseError) as error:
                if isinstance(error.args[0], tuple) and (re.match('.*ORA-00054.*', error.args[0][0]) or ('ERROR 1205 (HY000)' in error.args[0][0])):
                    logging.warn("Locks detected when handling replicas on %s rule %s, update updated time." % (req_type, rule_id))
                    try:
                        request_core.touch_requests_by_rule(rule_id)
                    except (DatabaseException, DatabaseError):
                        logging.error("Failed to touch requests by rule(%s): %s" % (rule_id, traceback.format_exc()))
                else:
                    logging.error("Could not finish handling replicas on %s rule %s: %s" % (req_type, rule_id, traceback.format_exc()))
            except:
                logging.error("Something unexpected happened when handling replicas on %s rule %s: %s" % (req_type, rule_id, traceback.format_exc()))


@transactional_session
def __update_bulk_replicas(replicas, req_type, rule_id, session=None):
    """
    Used by finisher to handle available and unavailable replicas blongs to same rule in bulk way.

    :param replicas:              List of replicas.
    :param req_type:              Request type: STAGEIN, STAGEOUT, TRANSFER.
    :param rule_id:               RULE id.
    :param session:               The database session to use.
    :returns commit_or_rollback:  Boolean.
    """
    try:
        replica_core.update_replicas_states(replicas, nowait=True, session=session)
    except ReplicaNotFound as error:
        logging.warn('Failed to bulk update replicas, will do it one by one: %s' % str(error))
        raise ReplicaNotFound(error)

    for replica in replicas:
        if not replica['archived']:
            request_core.archive_request(replica['request_id'], session=session)
        logging.info("HANDLED REQUEST %s DID %s:%s AT RSE %s STATE %s" % (replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state'])))
    return True


@transactional_session
def __update_replica(replica, req_type, rule_id, session=None):
    """
    Used by finisher to update a replica to a finished state.

    :param replica:               Replica as a dictionary.
    :param req_type:              Request type: STAGEIN, STAGEOUT, TRANSFER.
    :param rule_id:               RULE id.
    :param session:               The database session to use.
    :returns commit_or_rollback:  Boolean.
    """

    try:
        replica_core.update_replicas_states([replica], nowait=True, session=session)
        if not replica['archived']:
            request_core.archive_request(replica['request_id'], session=session)
        logging.info("HANDLED REQUEST %s DID %s:%s AT RSE %s STATE %s" % (replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state'])))
    except (UnsupportedOperation, ReplicaNotFound) as error:
        logging.warn("ERROR WHEN HANDLING REQUEST %s DID %s:%s AT RSE %s STATE %s: %s" % (replica['request_id'], replica['scope'], replica['name'], replica['rse_id'], str(replica['state']), str(error)))
        # replica cannot be found. register it and schedule it for deletion
        try:
            if replica['state'] == ReplicaState.AVAILABLE and replica['request_type'] != RequestType.STAGEIN:
                logging.info("Replica cannot be found. Adding a replica %s:%s AT RSE %s with tombstone=utcnow" % (replica['scope'], replica['name'], replica['rse_id']))
                rse = get_rse(rse=None, rse_id=replica['rse_id'], session=session)
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
