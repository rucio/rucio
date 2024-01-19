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
Methods common to different conveyor submitter daemons.
"""

import datetime
import functools
import itertools
import logging
import re
from typing import TYPE_CHECKING

from rucio.common.config import config_get_bool
from rucio.common.exception import (InvalidRSEExpression, TransferToolTimeout, TransferToolWrongAnswer, RequestNotFound,
                                    DuplicateFileTransferSubmission, VONotFound, DatabaseException)
from rucio.common.stopwatch import Stopwatch
from rucio.core import request as request_core, transfer as transfer_core
from rucio.core.monitor import MetricManager
from rucio.core.replica import add_replicas, tombstone_from_delay, update_replica_state
from rucio.core.request import transition_request_state, queue_requests
from rucio.core.rse import list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.transfer import build_transfer_paths
from rucio.core.vo import list_vos
from rucio.db.sqla import models
from rucio.db.sqla.constants import RequestState, ReplicaState
from rucio.db.sqla.session import transactional_session
from rucio.rse import rsemanager as rsemgr

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from typing import Optional, Mapping
    from rucio.common.types import InternalAccount
    from rucio.core.request import DirectTransfer, RequestWithSources
    from rucio.core.topology import Topology
    from rucio.core.transfer import ProtocolFactory
    from rucio.transfertool.transfertool import TransferToolBuilder
    from sqlalchemy.orm import Session

METRICS = MetricManager(module=__name__)


def pick_and_prepare_submission_path(
        requests_with_sources: "Mapping[str, RequestWithSources]",
        topology: "Topology",
        protocol_factory: "ProtocolFactory",
        default_tombstone_delay: int = transfer_core.DEFAULT_MULTIHOP_TOMBSTONE_DELAY,
        admin_accounts: "Optional[set[InternalAccount]]" = None,
        schemes: "Optional[list[str]]" = None,
        failover_schemes: "Optional[list[str]]" = None,
        max_sources: int = 4,
        transfertools: "Optional[list[str]]" = None,
        logger=logging.log
) -> "dict[TransferToolBuilder, list[list[DirectTransfer]]]":
    """
    For each transfer, pick a (sub)path; and a transfertool to be used to submit that (sub)path
    """

    # for each source, compute the (possibly multihop) path between it and the transfer destination
    _build_paths_fnc = functools.partial(
        build_transfer_paths,
        topology=topology,
        protocol_factory=protocol_factory,
        schemes=schemes,
        failover_schemes=failover_schemes,
        max_sources=max_sources,
        admin_accounts=admin_accounts,
        transfertools=transfertools,
        logger=logger,
    )

    # Assign paths to be executed by transfertools
    # if the chosen best path is a multihop, create intermediate replicas and the intermediate transfer requests
    _assign_path_fnc = functools.partial(
        assign_paths_to_transfertool_and_create_hops,
        default_tombstone_delay=default_tombstone_delay,
        transfertools=transfertools,
        logger=logger,
    )

    # For requests which had source_rse_id set in the database, start by verifying that it's possible to
    # use this source to submit it. If it's possible, use it, otherwise, fallback to searching all
    # possible sources for the request
    requests_to_load_partially = {}
    requests_to_load_fully = {}
    for request_id, rws in requests_with_sources.items():
        if rws.requested_source and datetime.datetime.utcnow() - datetime.timedelta(hours=6) < rws.requested_at:
            requests_to_load_partially[request_id] = rws
        else:
            requests_to_load_fully[request_id] = rws

    paths_by_transfertool_builder_partial = {}
    if requests_to_load_partially:
        candidate_paths, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source, reqs_unsupported_transfertool = _build_paths_fnc(
            requests_with_sources=list(requests_to_load_partially.values()),
            requested_source_only=True,
        )
        paths_by_transfertool_builder_partial, reqs_no_host = _assign_path_fnc(
            candidate_paths_by_request_id=candidate_paths,
        )
        for request_id in itertools.chain(reqs_no_host, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source, reqs_unsupported_transfertool):
            rws = requests_to_load_partially[request_id]
            logger(logging.INFO, "%s: source_rse_id was set to %s, but cannot be used. Fall-back to full source scan.", request_id, str(rws.requested_source))
            requests_to_load_fully[request_id] = rws

    candidate_paths, reqs_no_source, reqs_scheme_mismatch, reqs_only_tape_source, reqs_unsupported_transfertool = _build_paths_fnc(
        requests_with_sources=list(requests_to_load_fully.values())
    )
    paths_by_transfertool_builder, reqs_no_host = _assign_path_fnc(
        candidate_paths_by_request_id=candidate_paths
    )
    # Merge the two dicts with submission work into one
    for tt_builder, paths in paths_by_transfertool_builder_partial.items():
        paths_by_transfertool_builder.setdefault(tt_builder, []).extend(paths)

    if reqs_unsupported_transfertool:
        logger(logging.INFO, "Ignoring request because of unsupported transfertool: %s", reqs_unsupported_transfertool)
    reqs_no_source.update(reqs_no_host)
    if reqs_no_source:
        logger(logging.INFO, "Marking requests as no-sources: %s", reqs_no_source)
        request_core.transition_requests_state_if_possible(reqs_no_source, RequestState.NO_SOURCES, logger=logger)
    if reqs_only_tape_source:
        logger(logging.INFO, "Marking requests as only-tape-sources: %s", reqs_only_tape_source)
        request_core.transition_requests_state_if_possible(reqs_only_tape_source, RequestState.ONLY_TAPE_SOURCES, logger=logger)
    if reqs_scheme_mismatch:
        logger(logging.INFO, "Marking requests as scheme-mismatch: %s", reqs_scheme_mismatch)
        request_core.transition_requests_state_if_possible(reqs_scheme_mismatch, RequestState.MISMATCH_SCHEME, logger=logger)

    return paths_by_transfertool_builder


def __assign_to_transfertool(
        transfer_path: "list[DirectTransfer]",
        transfertools: "Optional[list[str]]",
        logger: "Callable",
) -> "list[tuple[list[DirectTransfer], Optional[TransferToolBuilder]]]":
    """
    Iterate over a multihop path and assign sub-paths to transfertools in chucks from left to right.

    Assignment is done in a greedy way. At each step, the first transfertool which can submit any non-empty prefix
    is selected. No backtracking is done to find better alternatives.

    For example, for a path A->B->C->D->E, A->B->C may be assigned to transfertool1; while C->D->E to transfertool2.
    This even if transfertool2 could submit the full path in one step without splitting it.
    """
    if transfertools is None:
        return [(transfer_path, None)]

    remaining_hops = transfer_path
    tt_builder_for_hops = []
    while remaining_hops:
        tt_builder = None
        assigned_hops = []
        for tt_name in transfertools:
            transfertool_cls = transfer_core.TRANSFERTOOL_CLASSES_BY_NAME.get(tt_name)
            if not transfertool_cls:
                continue
            assigned_hops, tt_builder = transfertool_cls.submission_builder_for_path(remaining_hops, logger=logger)
            if assigned_hops:
                break

        if not assigned_hops:
            break

        remaining_hops = remaining_hops[len(assigned_hops):]
        tt_builder_for_hops.append((assigned_hops, tt_builder))

    if remaining_hops:
        # We cannot submit the whole path
        return []

    return tt_builder_for_hops


def assign_paths_to_transfertool_and_create_hops(
        candidate_paths_by_request_id: "dict[str: list[DirectTransfer]]",
        default_tombstone_delay: int,
        transfertools: "Optional[list[str]]" = None,
        logger: "Callable" = logging.log,
) -> "tuple[dict[TransferToolBuilder, list[list[DirectTransfer]]], set[str]]":
    """
    for each request, pick the first path which can be submitted by one of the transfertools.
    If the chosen path is multihop, create all missing intermediate requests and replicas.
    """
    reqs_no_host = set()
    paths_by_transfertool_builder = {}
    for request_id, candidate_paths in candidate_paths_by_request_id.items():
        try:
            hops_to_submit, builder_to_use = __assign_paths_to_transfertool_and_create_hops(
                request_id,
                candidate_paths,
                default_tombstone_delay=default_tombstone_delay,
                transfertools=transfertools,
                logger=logger,
            )
        except DatabaseException as e:
            if re.match('.*SOURCES_(REQ_ID|REPLICA|RSES|DEST_RSES)_FK.*', str(e.args[0])):
                logger(logging.WARNING, '%s: Cannot sync DB sources. Skip the transfer for now.', request_id)
                continue
            raise

        if hops_to_submit is None:
            reqs_no_host.add(request_id)
            continue

        if not hops_to_submit:
            continue

        paths_by_transfertool_builder.setdefault(builder_to_use, []).append(hops_to_submit)
    return paths_by_transfertool_builder, reqs_no_host


@transactional_session
def __assign_paths_to_transfertool_and_create_hops(
        request_id: str,
        candidate_paths: "Sequence[list[DirectTransfer]]",
        default_tombstone_delay: int,
        transfertools: "Optional[list[str]]" = None,
        *,
        logger: "Callable" = logging.log,
        session: "Session",
) -> "tuple[Optional[list[DirectTransfer]], Optional[TransferToolBuilder]]":
    """
    Out of a sequence of candidate paths for the given request, pick the first path which can
    be submitted by one of the transfertools.
    If the chosen path is multihop, create all missing intermediate requests and replicas.
    """
    # Get the rws object from any candidate path. It is the same for all candidate paths. For multihop, the initial request is the last hop
    rws = candidate_paths[0][-1].rws

    # Selects the first path which can be submitted using a chain of supported transfertools
    # and for which the creation of intermediate hops (if it is a multihop) works correctly
    best_path = []
    builder_to_use = None
    hops_to_submit = []
    must_skip_submission = False

    tt_assignments = [(transfer_path, __assign_to_transfertool(transfer_path, transfertools, logger=logger))
                      for transfer_path in candidate_paths]
    # Prioritize the paths which need less transfertool transitions.
    # Ideally, the entire path should be submitted to a single transfertool
    for transfer_path, tt_assignment in sorted(tt_assignments, key=lambda t: len(t[1])):
        if not tt_assignment:
            logger(logging.INFO, '%s: None of the transfertools can submit the request: %s', request_id, transfertools)
            continue

        # Set the 'transfertool' field on the intermediate hops which should be created in the database
        for sub_path, tt_builder in tt_assignment:
            if tt_builder:
                for hop in sub_path:
                    if hop is not transfer_path[-1]:
                        hop.rws.transfertool = tt_builder.transfertool_class.external_name
        created, must_skip_submission = __create_missing_replicas_and_requests(
            transfer_path, default_tombstone_delay, logger=logger, session=session
        )
        if created:
            best_path = transfer_path
            # Only the first sub-path will be submitted to the corresponding transfertool,
            # the rest of the hops will wait for first hops to be transferred
            hops_to_submit, builder_to_use = tt_assignment[0]
        if created or must_skip_submission:
            break

    if builder_to_use is None and hops_to_submit is None:
        logger(logging.INFO, '%s: Cannot pick transfertool, or create intermediate requests' % request_id)
        return hops_to_submit, builder_to_use

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
        hops_to_submit = []
        return hops_to_submit, builder_to_use

    if len(hops_to_submit) < len(best_path):
        logger(logging.INFO, '%s: Only first %d hops will be submitted by %s', request_id, len(hops_to_submit), builder_to_use)

    return hops_to_submit, builder_to_use


@transactional_session
def __create_missing_replicas_and_requests(
        transfer_path: "list[DirectTransfer]",
        default_tombstone_delay: int,
        *,
        logger: "Callable",
        session: "Session"
) -> tuple[bool, bool]:
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
        rws.attributes['source_replica_expression'] = hop.src.rse.name
        req_to_queue = {'dest_rse_id': rws.dest_rse.id,
                        'source_rse_id': hop.src.rse.id,
                        'state': RequestState.QUEUED,
                        'scope': rws.scope,
                        'name': rws.name,
                        'rule_id': '00000000000000000000000000000000',  # Dummy Rule ID used for multihop. TODO: Replace with actual rule_id once we can flag intermediate requests
                        'attributes': rws.attributes,
                        'request_type': rws.request_type,
                        'retry_count': rws.retry_count,
                        'account': rws.account,
                        'requested_at': datetime.datetime.utcnow()}
        if rws.transfertool:
            req_to_queue['transfertool'] = rws.transfertool
        new_req = queue_requests(requests=[req_to_queue], session=session)
        # If a request already exists, new_req will be an empty list.
        if new_req:
            db_req = new_req[0]
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


def submit_transfer(transfertool_obj, transfers, job_params, timeout=None, logger=logging.log):
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
            transition_request_state(request_id=transfer.rws.request_id, state=RequestState.SUBMISSION_FAILED)
            return

    try:
        _submit_transfers(transfertool_obj, transfers, job_params, timeout, logger)
    except DuplicateFileTransferSubmission as error:
        logger(logging.WARNING, 'Failed to bulk submit a job because of duplicate file : %s', str(error))
        logger(logging.INFO, 'Submitting files one by one')
        for transfer in transfers:
            _submit_transfers(transfertool_obj, [transfer], job_params, timeout, logger)


def _submit_transfers(transfertool_obj, transfers, job_params, timeout=None, logger=logging.log):
    """
    helper function for submit_transfers. Performs the actual submission of one or more transfers.

    If the bulk submission of multiple transfers fails due to duplicate submissions, the exception
    is propagated to the caller context, which is then responsible for calling this function again for each
    of the transfers separately.
    """
    logger(logging.DEBUG, 'About to submit job to %s with timeout %s' % (transfertool_obj, timeout))
    # A eid is returned if the job is properly submitted otherwise an exception is raised
    is_bulk = len(transfers) > 1
    eid = None
    stopwatch = Stopwatch()
    state_to_set = RequestState.SUBMISSION_FAILED
    try:
        METRICS.counter('submit_transfer').inc()
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
        stopwatch.stop()
        logger(logging.DEBUG, 'Submit job %s to %s in %s seconds' % (eid, transfertool_obj, stopwatch.elapsed))
        METRICS.timer('submit_bulk_transfer_per_file').observe(stopwatch.elapsed / (len(transfers) or 1))
        METRICS.counter('submit_bulk_transfer').inc(len(transfers))

    if state_to_set:
        try:
            transfer_core.set_transfers_state(
                transfers,
                state=state_to_set,
                external_host=transfertool_obj.external_host,
                external_id=eid,
                submitted_at=datetime.datetime.utcnow(),
                transfertool=transfertool_obj.external_name,
                logger=logger
            )
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
    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
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
