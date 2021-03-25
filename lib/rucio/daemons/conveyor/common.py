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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016
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

"""
Methods common to different conveyor submitter daemons.
"""

from __future__ import division
from json import loads

import datetime
import logging
import time

from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import (InvalidRSEExpression, TransferToolTimeout, TransferToolWrongAnswer, RequestNotFound,
                                    ConfigNotFound, DuplicateFileTransferSubmission, VONotFound)
from rucio.common.utils import chunks, set_checksum_value
from rucio.core import request, transfer as transfer_core
from rucio.core.config import get
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import list_rses, get_rse_supported_checksums
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.db.sqla.session import read_session
from rucio.db.sqla.constants import RequestState
from rucio.rse import rsemanager as rsemgr

USER_ACTIVITY = config_get('conveyor', 'user_activities', False, ['user', 'user_test'])
USER_TRANSFERS = config_get('conveyor', 'user_transfers', False, None)
TRANSFER_TOOL = config_get('conveyor', 'transfertool', False, None)


def submit_transfer(external_host, job, submitter='submitter', timeout=None, user_transfer_job=False, logger=logging.log, transfertool=TRANSFER_TOOL):
    """
    Submit a transfer or staging request

    :param external_host:         FTS server to submit to.
    :param job:                   Job dictionary.
    :param submitter:             Name of the submitting entity.
    :param timeout:               Timeout
    :param user_transfer_job:     Parameter for transfer with user credentials
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    """

    # Prepare submitting
    xfers_ret = {}

    try:
        for t_file in job['files']:
            file_metadata = t_file['metadata']
            request_id = file_metadata['request_id']
            log_str = 'PREPARING REQUEST %s DID %s:%s TO SUBMITTING STATE PREVIOUS %s FROM %s TO %s USING %s ' % (file_metadata['request_id'],
                                                                                                                  file_metadata['scope'],
                                                                                                                  file_metadata['name'],
                                                                                                                  file_metadata['previous_attempt_id'] if 'previous_attempt_id' in file_metadata else None,
                                                                                                                  t_file['sources'],
                                                                                                                  t_file['destinations'],
                                                                                                                  external_host)
            xfers_ret[request_id] = {'state': RequestState.SUBMITTING, 'external_host': external_host, 'external_id': None, 'dest_url': t_file['destinations'][0]}
            logger(logging.INFO, "%s", log_str)
            xfers_ret[request_id]['file'] = t_file
        logger(logging.DEBUG, 'Start to prepare transfer')
        transfer_core.prepare_sources_for_transfers(xfers_ret)
        logger(logging.DEBUG, 'Finished to prepare transfer')
    except RequestNotFound as error:
        logger(logging.ERROR, str(error))
        return
    except Exception:
        logger(logging.ERROR, 'Failed to prepare requests %s state to SUBMITTING (Will not submit jobs but return directly) with error: %s' % (list(xfers_ret.keys())), exc_info=True)
        return

    # Prepare the dictionary for xfers results
    xfers_ret = {}
    for t_file in job['files']:
        file_metadata = t_file['metadata']
        request_id = file_metadata['request_id']
        xfers_ret[request_id] = {'scope': file_metadata['scope'],
                                 'name': file_metadata['name'],
                                 'external_host': external_host,
                                 'external_id': None,
                                 'request_type': t_file.get('request_type', None),
                                 'dst_rse': file_metadata.get('dst_rse', None),
                                 'src_rse': file_metadata.get('src_rse', None),
                                 'src_rse_id': file_metadata['src_rse_id'],
                                 'metadata': file_metadata}

    # Submit the job
    try:
        start_time = time.time()
        logger(logging.INFO, 'About to submit job to %s with timeout %s' % (external_host, timeout))
        # A eid is returned if the job is properly submitted otherwise an exception is raised
        eid = transfer_core.submit_bulk_transfers(external_host,
                                                  files=job['files'],
                                                  transfertool=transfertool,
                                                  job_params=job['job_params'],
                                                  timeout=timeout,
                                                  user_transfer_job=user_transfer_job)
        duration = time.time() - start_time
        logger(logging.INFO, 'Submit job %s to %s in %s seconds' % (eid, external_host, duration))
        record_timer('daemons.conveyor.%s.submit_bulk_transfer.per_file' % submitter, (time.time() - start_time) * 1000 / len(job['files']))
        record_counter('daemons.conveyor.%s.submit_bulk_transfer' % submitter, len(job['files']))
        record_timer('daemons.conveyor.%s.submit_bulk_transfer.files' % submitter, len(job['files']))

        # Update all the requests to SUBMITTED and cancel the transfer job in case the update failed
        try:
            for t_file in job['files']:
                file_metadata = t_file['metadata']
                request_id = file_metadata['request_id']
                xfers_ret[request_id]['state'] = RequestState.SUBMITTED
                xfers_ret[request_id]['external_id'] = eid
                logger(logging.INFO, 'COPYING REQUEST %s DID %s:%s USING %s with state(%s) with eid(%s)' % (file_metadata['request_id'], file_metadata['scope'], file_metadata['name'], external_host, RequestState.SUBMITTED, eid))
            logger(logging.DEBUG, 'Start to bulk register transfer state for eid %s' % eid)
            transfer_core.set_transfers_state(xfers_ret, datetime.datetime.utcnow())
            logger(logging.DEBUG, 'Finished to register transfer state',)
        except Exception:
            logger(logging.ERROR, 'Failed to register transfer state with error', exc_info=True)
            try:
                logger(logging.INFO, 'Cancel transfer %s on %s', eid, external_host)
                request.cancel_request_external_id(eid, external_host)
            except Exception:
                # The job is still submitted in the file transfer service but the request is not updated. Possibility to have a double submission during the next cycle
                logger(logging.ERROR, 'Failed to cancel transfers %s on %s with error' % (eid, external_host), exc_info=True)

    # This exception is raised if one job is already submitted for one file
    except DuplicateFileTransferSubmission as error:
        logger(logging.WARNING, 'Failed to submit a job because of duplicate file : %s', str(error))
        logger(logging.INFO, 'Submitting files one by one')

        try:
            # In this loop we submit the jobs and update the requests state one by one
            single_xfers_ret = {}
            for t_file in job['files']:
                single_xfers_ret = {}
                single_xfers_ret[request_id] = xfers_ret[request_id]
                file_metadata = t_file['metadata']
                request_id = file_metadata['request_id']
                start_time = time.time()
                logger(logging.INFO, 'About to submit job to %s with timeout %s', external_host, timeout)
                eid = transfer_core.submit_bulk_transfers(external_host,
                                                          files=[t_file],
                                                          transfertool=transfertool,
                                                          job_params=job['job_params'],
                                                          timeout=timeout,
                                                          user_transfer_job=user_transfer_job)
                duration = time.time() - start_time
                logger(logging.INFO, 'Submit job %s to %s in %s seconds' % (eid, external_host, duration))
                record_timer('daemons.conveyor.%s.submit_bulk_transfer.per_file' % submitter, (time.time() - start_time) * 1000)
                record_counter('daemons.conveyor.%s.submit_bulk_transfer' % submitter, 1)
                record_timer('daemons.conveyor.%s.submit_bulk_transfer.files' % submitter, 1)
                single_xfers_ret[request_id]['state'] = RequestState.SUBMITTED
                single_xfers_ret[request_id]['external_id'] = eid
                logger(logging.INFO, 'COPYING REQUEST %s DID %s:%s USING %s with state(%s) with eid(%s)' % (file_metadata['request_id'], file_metadata['scope'], file_metadata['name'], external_host, RequestState.SUBMITTED, eid))
                try:
                    logger(logging.DEBUG, 'Start to register transfer state')
                    transfer_core.set_transfers_state(single_xfers_ret, datetime.datetime.utcnow())
                    logger(logging.DEBUG, 'Finished to register transfer state')
                except Exception:
                    logger(logging.ERROR, 'Failed to register transfer state with error', exc_info=True)
                    try:
                        logger(logging.INFO, 'Cancel transfer %s on %s', eid, external_host)
                        request.cancel_request_external_id(eid, external_host)
                    except Exception:
                        logger(logging.ERROR, 'Failed to cancel transfers %s on %s with error' % (eid, external_host), exc_info=True)

        except (DuplicateFileTransferSubmission, TransferToolTimeout, TransferToolWrongAnswer, Exception) as error:
            request_id = single_xfers_ret.keys()[0]
            single_xfers_ret[request_id]['state'] = RequestState.SUBMISSION_FAILED
            logger(logging.ERROR, 'Cannot submit the job for request %s : %s', request_id, str(error))
            try:
                logger(logging.DEBUG, 'Update the transfer state to fail')
                transfer_core.set_transfers_state(single_xfers_ret, datetime.datetime.utcnow())
                logger(logging.DEBUG, 'Finished to register transfer state')
            except Exception:
                logger(logging.ERROR, 'Failed to register transfer state with error', exc_info=True)
                # No need to cancel the job here

    # The following exceptions are raised if the job failed to be submitted
    except (TransferToolTimeout, TransferToolWrongAnswer) as error:
        logger(logging.ERROR, str(error))
        try:
            for t_file in job['files']:
                file_metadata = t_file['metadata']
                request_id = file_metadata['request_id']
                xfers_ret[request_id]['state'] = RequestState.SUBMISSION_FAILED
            logger(logging.DEBUG, 'Start to register transfer state')
            transfer_core.set_transfers_state(xfers_ret, datetime.datetime.utcnow())
            logger(logging.DEBUG, 'Finished to register transfer state')
        except Exception:
            logger(logging.ERROR, 'Failed to register transfer state with error', exc_info=True)
            # No need to cancel the job here

    except Exception as error:
        logger(logging.ERROR, 'Failed to submit a job with error %s', str(error), exc_info=True)


@read_session
def bulk_group_transfer(transfers, policy='rule', group_bulk=200, source_strategy=None, max_time_in_queue=None, session=None, logger=logging.log, group_by_scope=False):
    """
    Group transfers in bulk based on certain criterias

    :param transfers:             List of transfers to group.
    :param plicy:                 Policy to use to group.
    :param group_bulk:            Bulk sizes.
    :param source_strategy:       Strategy to group sources
    :param max_time_in_queue:     Maximum time in queue
    :param logger:                Optional decorated logger that can be passed from the calling daemons or servers.
    :return:                      List of grouped transfers.
    """

    grouped_transfers = {}
    grouped_jobs = {}

    # Use empty string, but any string is OK, it is internal to this function only
    _catch_all_scopes_str = ''

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

    for request_id in transfers:
        transfer = transfers[request_id]
        verify_checksum = transfer['file_metadata'].get('verify_checksum', 'both')

        dest_rse_id = transfer['file_metadata']['dest_rse_id']
        source_rse_id = transfer['file_metadata']['src_rse_id']

        dest_supported_checksums = get_rse_supported_checksums(rse_id=dest_rse_id, session=session)
        source_supported_checksums = get_rse_supported_checksums(rse_id=source_rse_id, session=session)
        common_checksum_names = set(source_supported_checksums).intersection(dest_supported_checksums)

        if source_supported_checksums == ['none']:
            if dest_supported_checksums == ['none']:
                # both endpoints support none
                verify_checksum = 'none'
            else:
                # src supports none but dst does
                verify_checksum = 'destination'
        else:
            if dest_supported_checksums == ['none']:
                # source supports some but destination does not
                verify_checksum = 'source'
            else:
                if len(common_checksum_names) == 0:
                    # source and dst support some bot none in common (dst priority)
                    verify_checksum = 'destination'
                else:
                    # Don't override the value in the file_metadata
                    pass

        t_file = {'sources': transfer['sources'],
                  'destinations': transfer['dest_urls'],
                  'metadata': transfer['file_metadata'],
                  'filesize': int(transfer['file_metadata']['filesize']),
                  'checksum': None,
                  'verify_checksum': verify_checksum,
                  'selection_strategy': source_strategy if source_strategy else activity_source_strategy.get(str(transfer['file_metadata']['activity']), default_source_strategy),
                  'request_type': transfer['file_metadata'].get('request_type', None),
                  'activity': str(transfer['file_metadata']['activity'])}

        if verify_checksum != 'none':
            if verify_checksum == 'both':
                set_checksum_value(t_file, common_checksum_names)
            if verify_checksum == 'source':
                set_checksum_value(t_file, source_supported_checksums)
            if verify_checksum == 'destination':
                set_checksum_value(t_file, dest_supported_checksums)

        multihop = transfer.get('multihop', False)
        strict_copy = transfer.get('strict_copy', False)
        use_ipv4 = transfer.get('use_ipv4', False)

        external_host = transfer['external_host']
        scope = t_file['metadata']['scope']
        activity = t_file['activity']
        if group_by_scope:
            scope_str = scope.internal
        else:
            # Use a catch-all scope which will be removed at the end
            scope_str = _catch_all_scopes_str

        if external_host not in grouped_transfers:
            grouped_transfers[external_host] = {}
            grouped_jobs[external_host] = {}
            if scope_str not in grouped_transfers[external_host]:
                grouped_transfers[external_host][scope_str] = {}
                grouped_jobs[external_host][scope_str] = []

        current_transfers_group = grouped_transfers[external_host][scope_str]
        current_jobs_group = grouped_jobs[external_host][scope_str]

        job_params = {'account': transfer['account'],
                      'use_oidc': transfer.get('use_oidc', False),
                      'verify_checksum': verify_checksum,
                      'copy_pin_lifetime': transfer['copy_pin_lifetime'] if transfer['copy_pin_lifetime'] else -1,
                      'bring_online': transfer['bring_online'] if transfer['bring_online'] else None,
                      'job_metadata': {'issuer': 'rucio'},  # finaly job_meta will like this. currently job_meta will equal file_meta to include request_id and etc.
                      'overwrite': transfer['overwrite'],
                      'priority': 3}
        if transfer.get('archive_timeout', None):
            job_params['archive_timeout'] = transfer['archive_timeout']
        if multihop:
            job_params['multihop'] = True
        if strict_copy:
            job_params['strict_copy'] = True
        if use_ipv4:
            job_params['ipv4'] = True
            job_params['ipv6'] = False

        # Don't put optional & missing keys in the parameters
        if transfer['dest_spacetoken']:
            job_params.update({'spacetoken': transfer['dest_spacetoken']})
        if transfer['src_spacetoken']:
            job_params.update({'source_spacetoken': transfer['src_spacetoken']})

        if max_time_in_queue:
            if transfer['file_metadata']['activity'] in max_time_in_queue:
                job_params['max_time_in_queue'] = max_time_in_queue[transfer['file_metadata']['activity']]
            elif 'default' in max_time_in_queue:
                job_params['max_time_in_queue'] = max_time_in_queue['default']

        # for multiple source replicas, no bulk submission
        if len(transfer['sources']) > 1:
            job_params['job_metadata']['multi_sources'] = True
            current_jobs_group.append({'files': [t_file], 'job_params': job_params})
        else:
            job_params['job_metadata']['multi_sources'] = False
            job_key = '%s,%s,%s,%s,%s,%s,%s,%s' % (job_params['verify_checksum'], job_params.get('spacetoken', None),
                                                   job_params['copy_pin_lifetime'],
                                                   job_params['bring_online'], job_params['job_metadata'],
                                                   job_params.get('source_spacetoken', None),
                                                   job_params['overwrite'], job_params['priority'])
            if 'max_time_in_queue' in job_params:
                job_key = job_key + ',%s' % job_params['max_time_in_queue']

            if multihop:
                job_key = 'multihop_%s' % (transfer['initial_request_id'])

            if job_key not in current_transfers_group:
                current_transfers_group[job_key] = {}

            if multihop:
                policy_key = 'multihop_%s' % (transfer['initial_request_id'])
            else:
                if policy == 'rule':
                    policy_key = '%s' % (transfer['rule_id'])
                if policy == 'dest':
                    policy_key = '%s' % (t_file['metadata']['dst_rse'])
                if policy == 'src_dest':
                    policy_key = '%s,%s' % (t_file['metadata']['src_rse'], t_file['metadata']['dst_rse'])
                if policy == 'rule_src_dest':
                    policy_key = '%s,%s,%s' % (transfer['rule_id'], t_file['metadata']['src_rse'], t_file['metadata']['dst_rse'])
                if policy == 'activity_dest':
                    policy_key = '%s %s' % (activity, t_file['metadata']['dst_rse'])
                    policy_key = "_".join(policy_key.split(' '))
                if policy == 'activity_src_dest':
                    policy_key = '%s %s %s' % (activity, t_file['metadata']['src_rse'], t_file['metadata']['dst_rse'])
                    policy_key = "_".join(policy_key.split(' '))
                    # maybe here we need to hash the key if it's too long

            if policy_key not in current_transfers_group[job_key]:
                current_transfers_group[job_key][policy_key] = {'files': [], 'job_params': job_params}
            current_transfers_policy = current_transfers_group[job_key][policy_key]
            if multihop:
                # The parent transfer should be the first of the list
                # TODO : Only work for a single hop now, need to be able to handle multiple hops
                if transfer['parent_request']:  # This is the child
                    current_transfers_policy['files'].append(t_file)
                else:
                    current_transfers_policy['files'].insert(0, t_file)
            else:
                current_transfers_policy['files'].append(t_file)

    # for jobs with different job_key, we cannot put in one job.
    for external_host in grouped_transfers:
        for scope_key in grouped_transfers[external_host]:
            for job_key in grouped_transfers[external_host][scope_key]:
                # for all policy groups in job_key, the job_params is the same.
                for policy_key in grouped_transfers[external_host][scope_key][job_key]:
                    job_params = grouped_transfers[external_host][scope_key][job_key][policy_key]['job_params']
                    for xfers_files in chunks(grouped_transfers[external_host][scope_key][job_key][policy_key]['files'], group_bulk):
                        # for the last small piece, just submit it.
                        grouped_jobs[external_host][scope_key].append({'files': xfers_files, 'job_params': job_params})

    if not group_by_scope:
        for external_host in grouped_jobs:
            grouped_jobs[external_host] = grouped_jobs[external_host][_catch_all_scopes_str]

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
