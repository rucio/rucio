# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Nick Smith <nick.smith@cern.ch>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021

"""
Methods common to different conveyor submitter daemons.
"""

from __future__ import division

import datetime
import functools
import logging
import time
from json import loads

from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import (InvalidRSEExpression, TransferToolTimeout, TransferToolWrongAnswer, RequestNotFound,
                                    ConfigNotFound, DuplicateFileTransferSubmission, VONotFound)
from rucio.common.utils import chunks
from rucio.core import request, transfer as transfer_core
from rucio.core.config import get
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.db.sqla.session import read_session
from rucio.db.sqla.constants import RequestState
from rucio.rse import rsemanager as rsemgr

TRANSFER_TOOL = config_get('conveyor', 'transfertool', False, None)


def submit_transfer(external_host, transfers, job_params, submitter='submitter', timeout=None, logger=logging.log, transfertool=TRANSFER_TOOL):
    """
    Submit a transfer or staging request

    :param external_host:         FTS server to submit to.
    :param job:                   Job dictionary.
    :param submitter:             Name of the submitting entity.
    :param timeout:               Timeout
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    """

    try:
        transfer_core.mark_submitting_and_prepare_sources_for_transfers(transfers, external_host=external_host, logger=logger)
    except RequestNotFound as error:
        logger(logging.ERROR, str(error))
        return
    except Exception:
        logger(logging.ERROR, 'Failed to prepare requests %s state to SUBMITTING (Will not submit jobs but return directly) with error' % [str(t.rws) for t in transfers], exc_info=True)
        return

    try:
        _submit_transfers(external_host, transfers, job_params, submitter, timeout, logger, transfertool)
    except DuplicateFileTransferSubmission as error:
        logger(logging.WARNING, 'Failed to bulk submit a job because of duplicate file : %s', str(error))
        logger(logging.INFO, 'Submitting files one by one')
        for transfer in transfers:
            _submit_transfers(external_host, [transfer], job_params, submitter, timeout, logger, transfertool)


def _submit_transfers(external_host, transfers, job_params, submitter='submitter', timeout=None, logger=logging.log, transfertool=TRANSFER_TOOL):
    """
    helper function for submit_transfers. Performs the actual submission of one or more transfers.

    If the bulk submission of multiple transfers fails due to duplicate submissions, the exception
    is propagated to the caller context, which is then responsible for calling this function again for each
    of the transfers separately.
    """
    logger(logging.INFO, 'About to submit job to %s with timeout %s' % (external_host, timeout))
    # A eid is returned if the job is properly submitted otherwise an exception is raised
    is_bulk = len(transfers) > 1
    eid = None
    start_time = time.time()
    state_to_set = RequestState.SUBMISSION_FAILED
    try:
        eid = transfer_core.submit_bulk_transfers(external_host, transfers=transfers, transfertool=transfertool, job_params=job_params, timeout=timeout)
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
        logger(logging.INFO, 'Submit job %s to %s in %s seconds' % (eid, external_host, duration))
        record_timer('daemons.conveyor.%s.submit_bulk_transfer.per_file' % submitter, (time.time() - start_time) * 1000 / len(transfers) or 1)
        record_counter('daemons.conveyor.%s.submit_bulk_transfer' % submitter, len(transfers))
        record_timer('daemons.conveyor.%s.submit_bulk_transfer.files' % submitter, len(transfers))

    if state_to_set:
        try:
            transfer_core.set_transfers_state(transfers, state=state_to_set, external_host=external_host,
                                              external_id=eid, submitted_at=datetime.datetime.utcnow(), logger=logger)
        except Exception:
            logger(logging.ERROR, 'Failed to register transfer state with error', exc_info=True)
            if eid is not None:
                # The job is still submitted in the file transfer service but the request is not updated.
                # Possibility to have a double submission during the next cycle. Try to cancel the external request.
                try:
                    logger(logging.INFO, 'Cancel transfer %s on %s', eid, external_host)
                    request.cancel_request_external_id(eid, external_host)
                except Exception:
                    logger(logging.ERROR, 'Failed to cancel transfers %s on %s with error' % (eid, external_host), exc_info=True)


def bulk_group_transfers_for_globus(transfer_paths, policy, group_bulk=200):
    """
    Group transfers in bulk based on certain criterias

    :param transfer_paths:  List of transfers to group.
    :param policy:     Policy to use to group.
    :param group_bulk: Bulk sizes.
    :return:           List of grouped transfers
    """
    if policy == 'single':
        group_bulk = 1

    grouped_jobs = []
    for chunk in chunks(transfer_paths, group_bulk):
        # Globus doesn't support multihop. Get the first hop only.
        transfers = [transfer_path[0] for transfer_path in chunk]

        grouped_jobs.append({
            'transfers': transfers,
            # Job params are not used by globus trasnfertool, but are needed for further common fts/globus code
            'job_params': {}
        })

    return grouped_jobs


def job_params_for_fts_transfer(transfer, bring_online, default_lifetime, archive_timeout_override, max_time_in_queue, logger):
    """
    Prepare the job parameters which will be passed to FTS transfertool
    """

    overwrite, bring_online_local = True, None
    if transfer.src.rse.is_tape_or_staging_required():
        bring_online_local = bring_online
    if transfer.dst.rse.is_tape():
        overwrite = False

    # Get dest space token
    dest_protocol = transfer.protocol_factory.protocol(transfer.dst.rse, transfer.dst.scheme, transfer.operation_dest)
    dest_spacetoken = None
    if dest_protocol.attributes and 'extended_attributes' in dest_protocol.attributes and \
            dest_protocol.attributes['extended_attributes'] and 'space_token' in dest_protocol.attributes['extended_attributes']:
        dest_spacetoken = dest_protocol.attributes['extended_attributes']['space_token']
    src_spacetoken = None

    strict_copy = transfer.dst.rse.attributes.get('strict_copy', False)
    archive_timeout = transfer.dst.rse.attributes.get('archive_timeout', None)

    verify_checksum, checksums_to_use = transfer_core.checksum_validation_strategy(transfer.src.rse.attributes, transfer.dst.rse.attributes, logger=logger)
    transfer['checksums_to_use'] = checksums_to_use

    job_params = {'account': transfer.rws.account,
                  'use_oidc': transfer_core.oidc_supported(transfer),
                  'verify_checksum': verify_checksum,
                  'copy_pin_lifetime': transfer.rws.attributes.get('lifetime', default_lifetime),
                  'bring_online': bring_online_local,
                  'job_metadata': {
                      'issuer': 'rucio',
                      'multi_sources': True if len(transfer.legacy_sources) > 1 else False,
                  },
                  'overwrite': overwrite,
                  'priority': 3}

    if transfer.get('multihop', False):
        job_params['multihop'] = True
    if strict_copy:
        job_params['strict_copy'] = strict_copy
    if dest_spacetoken:
        job_params['spacetoken'] = dest_spacetoken
    if src_spacetoken:
        job_params['source_spacetoken'] = src_spacetoken
    if transfer.use_ipv4:
        job_params['ipv4'] = True
        job_params['ipv6'] = False

    if archive_timeout and transfer.dst.rse.is_tape():
        try:
            archive_timeout = int(archive_timeout)
            if archive_timeout_override is None:
                job_params['archive_timeout'] = archive_timeout
            elif archive_timeout_override != 0:
                job_params['archive_timeout'] = archive_timeout_override
            logger(logging.DEBUG, 'Added archive timeout to transfer.')
        except ValueError:
            logger(logging.WARNING, 'Could not set archive_timeout for %s. Must be integer.', transfer)
            pass
    if max_time_in_queue:
        if transfer.rws.activity in max_time_in_queue:
            job_params['max_time_in_queue'] = max_time_in_queue[transfer.rws.activity]
        elif 'default' in max_time_in_queue:
            job_params['max_time_in_queue'] = max_time_in_queue['default']
    return job_params


@read_session
def bulk_group_transfers_for_fts(transfers, policy='rule', group_bulk=200, source_strategy=None, max_time_in_queue=None, session=None,
                                 logger=logging.log, archive_timeout_override=None, bring_online=None, default_lifetime=None):
    """
    Group transfers in bulk based on certain criterias

    :param transfers:                List of transfers to group.
    :param plicy:                    Policy to use to group.
    :param group_bulk:               Bulk sizes.
    :param source_strategy:          Strategy to group sources
    :param max_time_in_queue:        Maximum time in queue
    :param archive_timeout_override: Override the archive_timeout parameter for any transfers with it set (0 to unset)
    :param logger:                   Optional decorated logger that can be passed from the calling daemons or servers.
    :return:                         List of grouped transfers.
    """

    grouped_transfers = {}
    grouped_jobs = []

    try:
        default_source_strategy = get(section='conveyor', option='default-source-strategy')
    except ConfigNotFound:
        default_source_strategy = 'orderly'

    try:
        activity_source_strategy = get(section='conveyor', option='activity-source-strategy')
        activity_source_strategy = loads(activity_source_strategy)
    except ConfigNotFound:
        activity_source_strategy = {}
    except ValueError:
        logger(logging.WARNING, 'activity_source_strategy not properly defined')
        activity_source_strategy = {}

    for transfer_path in transfers:
        for i, transfer in enumerate(transfer_path):
            if len(transfer_path) > 1:
                transfer['multihop'] = True
            transfer['selection_strategy'] = source_strategy if source_strategy else activity_source_strategy.get(str(transfer.rws.activity), default_source_strategy)

    _build_job_params = functools.partial(job_params_for_fts_transfer,
                                          bring_online=bring_online,
                                          default_lifetime=default_lifetime,
                                          archive_timeout_override=archive_timeout_override,
                                          max_time_in_queue=max_time_in_queue,
                                          logger=logger)
    for transfer_path in transfers:
        if len(transfer_path) > 1:
            # for multihop transfers, all the path is submitted as a separate job
            job_params = _build_job_params(transfer_path[-1])
            for transfer in transfer_path[:-1]:
                # Only allow overwrite if all transfers in multihop allow it
                job_params['overwrite'] = _build_job_params(transfer)['overwrite'] and job_params['overwrite']

            group_key = 'multihop_%s' % transfer_path[-1].rws.request_id
            grouped_transfers[group_key] = {'transfers': transfer_path, 'job_params': job_params}
        elif len(transfer_path[0].legacy_sources) > 1:
            # for multi-source transfers, no bulk submission.
            transfer = transfer_path[0]
            grouped_jobs.append({'transfers': [transfer], 'job_params': _build_job_params(transfer)})
        else:
            # it's a single-hop, single-source, transfer. Hence, a candidate for bulk submission.
            transfer = transfer_path[0]
            job_params = _build_job_params(transfer)

            # we cannot group transfers together if their job_key differ
            job_key = '%s,%s,%s,%s,%s,%s,%s,%s' % (job_params['verify_checksum'], job_params.get('spacetoken', None),
                                                   job_params['copy_pin_lifetime'],
                                                   job_params['bring_online'], job_params['job_metadata'],
                                                   job_params.get('source_spacetoken', None),
                                                   job_params['overwrite'], job_params['priority'])
            if 'max_time_in_queue' in job_params:
                job_key = job_key + ',%s' % job_params['max_time_in_queue']

            # Additionally, we don't want to group transfers together if their policy_key differ
            policy_key = ''
            if policy == 'rule':
                policy_key = '%s' % transfer.rws.rule_id
            if policy == 'dest':
                policy_key = '%s' % transfer.dst.rse.name
            if policy == 'src_dest':
                policy_key = '%s,%s' % (transfer.src.rse.name, transfer.dst.rse.name)
            if policy == 'rule_src_dest':
                policy_key = '%s,%s,%s' % (transfer.rws.rule_id, transfer.src.rse.name, transfer.dst.rse.name)
            if policy == 'activity_dest':
                policy_key = '%s %s' % (transfer.rws.activity, transfer.dst.rse.name)
                policy_key = "_".join(policy_key.split(' '))
            if policy == 'activity_src_dest':
                policy_key = '%s %s %s' % (transfer.rws.activity, transfer.src.rse.name, transfer.dst.rse.name)
                policy_key = "_".join(policy_key.split(' '))
                # maybe here we need to hash the key if it's too long

            group_key = "%s_%s" % (job_key, policy_key)
            if group_key not in grouped_transfers:
                grouped_transfers[group_key] = {'transfers': [], 'job_params': job_params}
            grouped_transfers[group_key]['transfers'].append(transfer)

    # split transfer groups to have at most group_bulk elements in each one
    for group in grouped_transfers.values():
        job_params = group['job_params']
        for transfers in chunks(group['transfers'], group_bulk):
            grouped_jobs.append({'transfers': transfers, 'job_params': job_params})

    return grouped_jobs


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
                parsed_rses = parse_expression(include_rses, filter={'vo': vo}, session=None)
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
