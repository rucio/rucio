# -*- coding: utf-8 -*-
# Copyright 2014-2022 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2020
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2020
# - Wen Guan <wen.guan@cern.ch>, 2014-2016
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2016
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016-2021
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Eric Vaandering <ewv@fnal.gov>, 2018-2020
# - dciangot <diego.ciangottini@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Matt Snyder <msnyder@bnl.gov>, 2019
# - Gabriele Fronze' <gfronze@cern.ch>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022
# - Nick Smith <nick.smith@cern.ch>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021

"""
Methods common to different conveyor submitter daemons.
"""

from __future__ import division

import datetime
import logging
import os
import socket
import threading
import time
from typing import TYPE_CHECKING

from rucio.common.config import config_get, config_get_int
from rucio.common.exception import (InvalidRSEExpression, TransferToolTimeout, TransferToolWrongAnswer, RequestNotFound,
                                    DuplicateFileTransferSubmission, VONotFound)
from rucio.common.logging import formatted_logger
from rucio.common.utils import PriorityQueue
from rucio.core import heartbeat, request as request_core, transfer as transfer_core
from rucio.core.monitor import record_counter, record_timer
from rucio.core.replica import add_replicas, tombstone_from_delay, update_replica_state
from rucio.core.request import set_request_state, queue_requests
from rucio.core.rse import list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.db.sqla import models
from rucio.db.sqla.constants import RequestState, RequestType, ReplicaState
from rucio.db.sqla.session import transactional_session
from rucio.rse import rsemanager as rsemgr

if TYPE_CHECKING:
    from typing import Callable, Dict, List, Optional, Set, Tuple, Type
    from rucio.core.request import RequestWithSources
    from rucio.core.transfer import DirectTransferDefinition
    from rucio.transfertool.transfertool import Transfertool, TransferToolBuilder
    from sqlalchemy.orm import Session


class HeartbeatHandler:
    """
    Simple contextmanager which sets a heartbeat and associated logger on entry and cleans up the heartbeat on exit.
    """

    def __init__(self, executable, renewal_interval, logger_prefix=None):
        """
        :param executable: the executable name which will be set in heartbeats
        :param renewal_interval: the interval at which the heartbeat will be renewed in the database.
        Calls to live() in-between intervals will re-use the locally cached heartbeat.
        :param logger_prefix: the prefix to be prepended to all log messages
        """
        self.executable = executable
        self.renewal_interval = renewal_interval
        self.older_than = renewal_interval * 10 if renewal_interval and renewal_interval > 0 else None  # 10 was chosen without any particular reason
        self.logger_prefix = logger_prefix or executable

        self.hostname = socket.getfqdn()
        self.pid = os.getpid()
        self.hb_thread = threading.current_thread()

        self.logger = None
        self.last_heart_beat = None
        self.last_time = None

    def __enter__(self):
        heartbeat.sanity_check(executable=self.executable, hostname=self.hostname)
        self.live()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.last_heart_beat:
            heartbeat.die(self.executable, self.hostname, self.pid, self.hb_thread)
            if self.logger:
                self.logger(logging.INFO, 'Heartbeat cleaned up')

    def live(self):
        """
        :return: a tuple: <the number of the current worker>, <total number of workers>, <decorated logger>
        """
        if not self.last_time or self.last_time < datetime.datetime.now() - datetime.timedelta(seconds=self.renewal_interval):
            if self.older_than:
                self.last_heart_beat = heartbeat.live(self.executable, self.hostname, self.pid, self.hb_thread, older_than=self.older_than)
            else:
                self.last_heart_beat = heartbeat.live(self.executable, self.hostname, self.pid, self.hb_thread)

            prefix = '%s[%i/%i]: ' % (self.logger_prefix, self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'])
            self.logger = formatted_logger(logging.log, prefix + '%s')

            if not self.last_time:
                self.logger(logging.DEBUG, 'First heartbeat set')
            else:
                self.logger(logging.DEBUG, 'Heartbeat renewed')
            self.last_time = datetime.datetime.now()

        return self.last_heart_beat['assign_thread'], self.last_heart_beat['nr_threads'], self.logger


def run_conveyor_daemon(once, graceful_stop, executable, logger_prefix, partition_wait_time, sleep_time, run_once_fnc, activities=None):

    with HeartbeatHandler(executable=executable, renewal_interval=sleep_time - 1, logger_prefix=logger_prefix) as heartbeat_handler:
        logger = heartbeat_handler.logger
        logger(logging.INFO, 'started')

        if partition_wait_time:
            graceful_stop.wait(partition_wait_time)

        activity_next_exe_time = PriorityQueue()
        for activity in activities or [None]:
            activity_next_exe_time[activity] = time.time()

        while not graceful_stop.is_set() and activity_next_exe_time:
            if once:
                activity = activity_next_exe_time.pop()
                time_to_sleep = 0
            else:
                activity = activity_next_exe_time.top()
                time_to_sleep = activity_next_exe_time[activity] - time.time()

            if time_to_sleep > 0:
                if activity:
                    logger(logging.DEBUG, 'Switching to activity %s and sleeping %s seconds', activity, time_to_sleep)
                else:
                    logger(logging.DEBUG, 'Sleeping %s seconds', time_to_sleep)
                graceful_stop.wait(time_to_sleep)
            else:
                if activity:
                    logger(logging.DEBUG, 'Switching to activity %s', activity)
                else:
                    logger(logging.DEBUG, 'Starting next iteration')

            _, _, logger = heartbeat_handler.live()

            must_sleep = True
            try:
                must_sleep = run_once_fnc(activity=activity, heartbeat_handler=heartbeat_handler)
            except Exception:
                logger(logging.CRITICAL, "Exception", exc_info=True)
                if once:
                    raise

            if not once:
                if must_sleep:
                    activity_next_exe_time[activity] = time.time() + sleep_time
                else:
                    activity_next_exe_time[activity] = time.time() + 1


@transactional_session
def next_transfers_to_submit(total_workers=0, worker_number=0, partition_hash_var=None, limit=None, activity=None, older_than=None, rses=None, schemes=None,
                             failover_schemes=None, filter_transfertool=None, transfertools_by_name=None, request_type=RequestType.TRANSFER,
                             ignore_availability=False, logger=logging.log, session=None):
    """
    Get next transfers to be submitted; grouped by transfertool which can submit them
    :param total_workers:         Number of total workers.
    :param worker_number:         Id of the executing worker.
    :param partition_hash_var     The hash variable used for partitioning thread work
    :param limit:                 Maximum number of requests to retrieve from database.
    :param activity:              Activity.
    :param older_than:            Get transfers older than.
    :param rses:                  Include RSES.
    :param schemes:               Include schemes.
    :param failover_schemes:      Failover schemes.
    :param transfertools_by_name: Dict: {transfertool_name_str: transfertool class}
    :param filter_transfertool:   The transfer tool to filter requests on.
    :param request_type           The type of requests to retrieve (Transfer/Stagein)
    :param ignore_availability:   Ignore blocklisted RSEs
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    :param session:               The database session in use.
    :returns:                     Dict: {TransferToolBuilder: <list of transfer paths (possibly multihop) to be submitted>}
    """
    candidate_paths, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source = transfer_core.get_transfer_paths(
        total_workers=total_workers,
        worker_number=worker_number,
        partition_hash_var=partition_hash_var,
        limit=limit,
        activity=activity,
        older_than=older_than,
        rses=rses,
        schemes=schemes,
        failover_schemes=failover_schemes,
        filter_transfertool=filter_transfertool,
        ignore_availability=ignore_availability,
        request_type=request_type,
        logger=logger,
        session=session,
    )

    # Assign paths to be executed by transfertools
    # if the chosen best path is a multihop, create intermediate replicas and the intermediate transfer requests
    paths_by_transfertool_builder, reqs_no_host, reqs_unsupported_transfertool = __assign_paths_to_transfertool_and_create_hops(
        candidate_paths,
        transfertools_by_name=transfertools_by_name,
        logger=logger,
        session=session,
    )

    if reqs_unsupported_transfertool:
        logger(logging.INFO, "Ignoring request because of unsupported transfertool: %s", reqs_unsupported_transfertool)
    reqs_no_source.update(reqs_no_host)
    if reqs_no_source:
        logger(logging.INFO, "Marking requests as no-sources: %s", reqs_no_source)
        request_core.set_requests_state_if_possible(reqs_no_source, RequestState.NO_SOURCES, logger=logger, session=session)
    if reqs_only_tape_source:
        logger(logging.INFO, "Marking requests as only-tape-sources: %s", reqs_only_tape_source)
        request_core.set_requests_state_if_possible(reqs_only_tape_source, RequestState.ONLY_TAPE_SOURCES, logger=logger, session=session)
    if reqs_scheme_mismatch:
        logger(logging.INFO, "Marking requests as scheme-mismatch: %s", reqs_scheme_mismatch)
        request_core.set_requests_state_if_possible(reqs_scheme_mismatch, RequestState.MISMATCH_SCHEME, logger=logger, session=session)

    return paths_by_transfertool_builder


def __parse_request_transfertools(
        rws: "RequestWithSources",
        logger: "Callable" = logging.log,
):
    """
    Parse a set of desired transfertool names from the database field request.transfertool
    """
    request_transfertools = set()
    try:
        if rws.transfertool:
            request_transfertools = {tt.strip() for tt in rws.transfertool.split(',')}
    except Exception:
        logger(logging.WARN, "Unable to parse requested transfertools: {}".format(request_transfertools))
        request_transfertools = None
    return request_transfertools


def __assign_paths_to_transfertool_and_create_hops(
        candidate_paths_by_request_id: "Dict[str: List[DirectTransferDefinition]]",
        transfertools_by_name: "Optional[Dict[str, Type[Transfertool]]]" = None,
        logger: "Callable" = logging.log,
        session: "Optional[Session]" = None,
) -> "Tuple[Dict[TransferToolBuilder, List[DirectTransferDefinition]], Set[str], Set[str]]":
    """
    for each request, pick the first path which can be submitted by one of the transfertools.
    If the chosen path is multihop, create all missing intermediate requests and replicas.
    """
    reqs_no_host = set()
    reqs_unsupported_transfertool = set()
    paths_by_transfertool_builder = {}
    default_tombstone_delay = config_get_int('transfers', 'multihop_tombstone_delay', default=transfer_core.DEFAULT_MULTIHOP_TOMBSTONE_DELAY, expiration_time=600)
    for request_id, candidate_paths in candidate_paths_by_request_id.items():
        # Get the rws object from any candidate path. It is the same for all candidate paths. For multihop, the initial request is the last hop
        rws = candidate_paths[0][-1].rws

        request_transfertools = __parse_request_transfertools(rws, logger)
        if request_transfertools is None:
            # Parsing failed
            reqs_no_host.add(request_id)
            continue
        if request_transfertools and transfertools_by_name and not request_transfertools.intersection(transfertools_by_name):
            # The request explicitly asks for a transfertool which this submitter doesn't support
            reqs_unsupported_transfertool.add(request_id)
            continue

        # Selects the first path which can be submitted by a supported transfertool and for which the creation of
        # intermediate hops (if it is a multihop) work correctly
        best_path = None
        builder_to_use = None
        must_skip_submission = False
        for transfer_path in candidate_paths:
            builder = None
            if transfertools_by_name:
                transfertools_to_try = set(transfertools_by_name)
                if request_transfertools:
                    transfertools_to_try = transfertools_to_try.intersection(request_transfertools)
                for transfertool in transfertools_to_try:
                    builder = transfertools_by_name[transfertool].submission_builder_for_path(transfer_path, logger=logger)
                    if builder:
                        break
            if builder or not transfertools_by_name:
                created, must_skip_submission = __create_missing_replicas_and_requests(
                    transfer_path, default_tombstone_delay, logger=logger, session=session
                )
                if created:
                    best_path = transfer_path
                    builder_to_use = builder
                if created or must_skip_submission:
                    break

        if not best_path:
            reqs_no_host.add(request_id)
            logger(logging.INFO, '%s: Cannot pick transfertool, or create intermediate requests' % request_id)
            continue

        transfer_core.ensure_db_sources(best_path, logger=logger, session=session)

        if len(best_path) > 1:
            logger(logging.INFO, '%s: Best path is multihop: %s' % (rws.request_id, transfer_core.transfer_path_str(best_path)))
        elif best_path is not candidate_paths[0] or len(best_path[0].sources) > 1:
            # Only print singlehop if it brings additional information:
            # - either it's not the first candidate path
            # - or it's a multi-source
            # in other cases, it doesn't bring any additional information to what is known from previous logs
            logger(logging.INFO, '%s: Best path is direct: %s' % (rws.request_id, transfer_core.transfer_path_str(best_path)))

        if must_skip_submission:
            logger(logging.INFO, '%s: Part of the transfer is already being handled. Skip for now.' % request_id)
            continue

        paths_by_transfertool_builder.setdefault(builder_to_use, []).append(best_path)
    return paths_by_transfertool_builder, reqs_no_host, reqs_unsupported_transfertool


@transactional_session
def __create_missing_replicas_and_requests(
        transfer_path: "List[DirectTransferDefinition]",
        default_tombstone_delay: int,
        logger: "Callable",
        session: "Optional[Session]" = None
) -> "Tuple[bool, bool]":
    """
    Create replicas and requests in the database for the intermediate hops
    """
    initial_request_id = transfer_path[-1].rws.request_id
    creation_successful = True
    must_skip_submission = False
    # Iterate the path in reverse order. The last hop is the initial request, so
    # next_hop.rws.request_id will always be initialized when handling the current hop.
    for i in reversed(range(len(transfer_path))):
        hop = transfer_path[i]
        rws = hop.rws
        if rws.request_id:
            continue

        tombstone_delay = rws.dest_rse.attributes.get('multihop_tombstone_delay', default_tombstone_delay)
        try:
            tombstone = tombstone_from_delay(tombstone_delay)
        except ValueError:
            logger(logging.ERROR, "%s: Cannot parse multihop tombstone delay %s", initial_request_id, tombstone_delay)
            creation_successful = False
            break

        files = [{'scope': rws.scope,
                  'name': rws.name,
                  'bytes': rws.byte_count,
                  'adler32': rws.adler32,
                  'md5': rws.md5,
                  'tombstone': tombstone,
                  'state': 'C'}]
        try:
            add_replicas(rse_id=rws.dest_rse.id,
                         files=files,
                         account=rws.account,
                         ignore_availability=False,
                         dataset_meta=None,
                         session=session)
            # Set replica state to Copying in case replica already existed in another state.
            # Can happen when a multihop transfer failed previously, and we are re-scheduling it now.
            update_replica_state(rse_id=rws.dest_rse.id, scope=rws.scope, name=rws.name, state=ReplicaState.COPYING, session=session)
        except Exception as error:
            logger(logging.ERROR, '%s: Problem adding replicas on %s : %s', initial_request_id, rws.dest_rse, str(error))

        rws.attributes['is_intermediate_hop'] = True
        # next_hop_request_id and initial_request_id are not used anymore in rucio >=1.28, but are needed
        # for running at the same time 1.27 and 1.28 on the same database.
        # TODO: remove following two rows
        rws.attributes['next_hop_request_id'] = transfer_path[i + 1].rws.request_id
        rws.attributes['initial_request_id'] = initial_request_id
        rws.attributes['source_replica_expression'] = hop.src.rse.name
        new_req = queue_requests(requests=[{'dest_rse_id': rws.dest_rse.id,
                                            'scope': rws.scope,
                                            'name': rws.name,
                                            'rule_id': '00000000000000000000000000000000',  # Dummy Rule ID used for multihop. TODO: Replace with actual rule_id once we can flag intermediate requests
                                            'attributes': rws.attributes,
                                            'request_type': rws.request_type,
                                            'retry_count': rws.retry_count,
                                            'account': rws.account,
                                            'requested_at': datetime.datetime.now()}], session=session)
        # If a request already exists, new_req will be an empty list.
        if new_req:
            db_req = new_req[0]
            # queue_request may put it in PREPARING state; we don't want that.
            # TODO: maybe better to not relly on queue_request here?
            set_request_state(db_req['id'], RequestState.QUEUED, session=session, logger=logger)
            logger(logging.DEBUG, '%s: New request created for the transfer between %s and %s : %s', initial_request_id, transfer_path[0].src, transfer_path[-1].dst, db_req['id'])
        else:
            db_req = request_core.get_request_by_did(rws.scope, rws.name, rws.dest_rse.id, session=session)
            # A transfer already exists for part of the path. Just construct the remaining
            # path, but don't submit the transfer. We must wait for the existing transfer to be
            # completed before continuing.
            must_skip_submission = True
            logger(logging.DEBUG, '%s: Reusing intermediate hop between %s and %s : %s', initial_request_id, transfer_path[0].src, transfer_path[-1].dst, db_req['id'])

        models.TransferHop(request_id=db_req['id'],
                           next_hop_request_id=transfer_path[i + 1].rws.request_id,
                           initial_request_id=initial_request_id,
                           ).save(session=session, flush=False)
        rws.request_id = db_req['id']
        rws.requested_at = db_req['requested_at']

    return creation_successful, must_skip_submission


def submit_transfer(transfertool_obj, transfers, job_params, submitter='submitter', timeout=None, logger=logging.log):
    """
    Submit a transfer or staging request

    :param transfertool_obj:      The transfertool object to be used for submission
    :param transfers:             Transfer objects to be submitted
    :param job_params:            Parameters to be used for all transfers in the given job.
    :param submitter:             Name of the submitting entity.
    :param timeout:               Timeout
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    """

    for transfer in transfers:
        try:
            transfer_core.mark_submitting(transfer, external_host=transfertool_obj.external_host, logger=logger)
        except RequestNotFound as error:
            logger(logging.ERROR, str(error))
            return
        except Exception:
            logger(logging.ERROR, 'Failed to prepare requests %s state to SUBMITTING. Mark it SUBMISSION_FAILED and abort submission.' % [str(t.rws) for t in transfers], exc_info=True)
            set_request_state(request_id=transfer.rws.request_id, state=RequestState.SUBMISSION_FAILED)
            return

    try:
        _submit_transfers(transfertool_obj, transfers, job_params, submitter, timeout, logger)
    except DuplicateFileTransferSubmission as error:
        logger(logging.WARNING, 'Failed to bulk submit a job because of duplicate file : %s', str(error))
        logger(logging.INFO, 'Submitting files one by one')
        for transfer in transfers:
            _submit_transfers(transfertool_obj, [transfer], job_params, submitter, timeout, logger)


def _submit_transfers(transfertool_obj, transfers, job_params, submitter='submitter', timeout=None, logger=logging.log):
    """
    helper function for submit_transfers. Performs the actual submission of one or more transfers.

    If the bulk submission of multiple transfers fails due to duplicate submissions, the exception
    is propagated to the caller context, which is then responsible for calling this function again for each
    of the transfers separately.
    """
    logger(logging.INFO, 'About to submit job to %s with timeout %s' % (transfertool_obj, timeout))
    # A eid is returned if the job is properly submitted otherwise an exception is raised
    is_bulk = len(transfers) > 1
    eid = None
    start_time = time.time()
    state_to_set = RequestState.SUBMISSION_FAILED
    try:
        record_counter('core.request.submit_transfer')
        eid = transfertool_obj.submit(transfers, job_params, timeout)
        state_to_set = RequestState.SUBMITTED
    except DuplicateFileTransferSubmission:
        if is_bulk:
            raise
    except (TransferToolTimeout, TransferToolWrongAnswer) as error:
        logger(logging.ERROR, 'Failed to submit a job with error %s', str(error), exc_info=True)
    except Exception as error:
        logger(logging.ERROR, 'Failed to submit a job with error %s', str(error), exc_info=True)
        # Keep the behavior from before the refactoring: in case of unexpected exception, only
        # update request state on individual transfers, and do nothing for bulks.
        # Don't know why it's like that.
        #
        # FIXME: shouldn't we always set the state to SUBMISSION_FAILED?
        if is_bulk:
            state_to_set = None

    if eid is not None:
        duration = time.time() - start_time
        logger(logging.INFO, 'Submit job %s to %s in %s seconds' % (eid, transfertool_obj, duration))
        record_timer('daemons.conveyor.{submitter}.submit_bulk_transfer.per_file', (time.time() - start_time) * 1000 / len(transfers) or 1, labels={'submitter': submitter})
        record_counter('daemons.conveyor.{submitter}.submit_bulk_transfer', delta=len(transfers), labels={'submitter': submitter})
        record_timer('daemons.conveyor.{submitter}.submit_bulk_transfer.files', len(transfers), labels={'submitter': submitter})

    if state_to_set:
        try:
            transfer_core.set_transfers_state(transfers, state=state_to_set, external_host=transfertool_obj.external_host,
                                              external_id=eid, submitted_at=datetime.datetime.utcnow(), logger=logger)
        except Exception:
            logger(logging.ERROR, 'Failed to register transfer state with error', exc_info=True)
            if eid is not None:
                # The job is still submitted in the file transfer service but the request is not updated.
                # Possibility to have a double submission during the next cycle. Try to cancel the external request.
                try:
                    logger(logging.INFO, 'Cancel transfer %s on %s', eid, transfertool_obj)
                    transfer_core.cancel_transfer(transfertool_obj, eid)
                except Exception:
                    logger(logging.ERROR, 'Failed to cancel transfers %s on %s with error' % (eid, transfertool_obj), exc_info=True)


def get_conveyor_rses(rses=None, include_rses=None, exclude_rses=None, vos=None, logger=logging.log):
    """
    Get a list of rses for conveyor

    :param rses:          List of rses (Single-VO only)
    :param include_rses:  RSEs to include
    :param exclude_rses:  RSEs to exclude
    :param vos:           VOs on which to look for RSEs. Only used in multi-VO mode.
                          If None, we either use all VOs if run from "def", or the current VO otherwise.
    :param logger:        Optional decorated logger that can be passed from the calling daemons or servers.
    :return:              List of working rses
    """
    multi_vo = config_get('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        if vos:
            logger(logging.WARNING, 'Ignoring argument vos, this is only applicable in a multi-VO setup.')
        vos = ['def']
    else:
        if vos:
            invalid = set(vos) - set([v['vo'] for v in list_vos()])
            if invalid:
                msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '', ', '.join([repr(v) for v in invalid]))
                raise VONotFound(msg)
        else:
            vos = [v['vo'] for v in list_vos()]
        logger(logging.INFO, 'This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    working_rses = []
    rses_list = []
    for vo in vos:
        rses_list.extend(list_rses(filters={'vo': vo}))
    if rses:
        working_rses = [rse for rse in rses_list if rse['rse'] in rses]

    if include_rses:
        for vo in vos:
            try:
                parsed_rses = parse_expression(include_rses, filter_={'vo': vo}, session=None)
            except InvalidRSEExpression:
                logger(logging.ERROR, "Invalid RSE exception %s to include RSEs", include_rses)
            else:
                for rse in parsed_rses:
                    if rse not in working_rses:
                        working_rses.append(rse)

    if not (rses or include_rses):
        working_rses = rses_list

    if exclude_rses:
        try:
            parsed_rses = parse_expression(exclude_rses, session=None)
        except InvalidRSEExpression as error:
            logger(logging.ERROR, "Invalid RSE exception %s to exclude RSEs: %s", exclude_rses, error)
        else:
            working_rses = [rse for rse in working_rses if rse not in parsed_rses]

    working_rses = [rsemgr.get_rse_info(rse_id=rse['id']) for rse in working_rses]
    return working_rses
