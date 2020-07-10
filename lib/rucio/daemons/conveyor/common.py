# Copyright 2014-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Vincent Garonne <vgaronne@gmail.com>, 2014-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2017
# - Wen Guan <wguan.icedew@gmail.com>, 2014-2016
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2016
# - Thomas Beermann <thomas.beermann@cern.ch>, 2016
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Eric Vaandering <ericvaandering@gmail.com>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Gabriele Fronze' <gfronze@cern.ch>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
#
# PY3K COMPATIBLE

"""
Methods common to different conveyor submitter daemons.
"""

from __future__ import division
from json import loads

import datetime
import logging
import time
import traceback

from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import InvalidRSEExpression, TransferToolTimeout, TransferToolWrongAnswer, RequestNotFound, ConfigNotFound, DuplicateFileTransferSubmission
from rucio.common.utils import chunks, set_checksum_value
from rucio.core import request, transfer as transfer_core
from rucio.core.config import get
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import list_rses, get_rse_supported_checksums
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla.session import read_session
from rucio.db.sqla.constants import RequestState
from rucio.rse import rsemanager as rsemgr

USER_ACTIVITY = config_get('conveyor', 'user_activities', False, ['user', 'user_test'])
USER_TRANSFERS = config_get('conveyor', 'user_transfers', False, None)
TRANSFER_TOOL = config_get('conveyor', 'transfertool', False, None)


def submit_transfer(external_host, job, submitter='submitter', logging_prepend_str='', timeout=None, user_transfer_job=False):
    """
    Submit a transfer or staging request

    :param external_host:         FTS server to submit to.
    :param job:                   Job dictionary.
    :param submitter:             Name of the submitting entity.
    :param logging_prepend_str:   String to prepend to the logging
    :param timeout:               Timeout
    :param user_transfer_job:     Parameter for transfer with user credentials
    """

    prepend_str = ''
    if logging_prepend_str:
        prepend_str = logging_prepend_str

    # Prepare submitting
    xfers_ret = {}

    try:
        for t_file in job['files']:
            file_metadata = t_file['metadata']
            request_id = file_metadata['request_id']
            log_str = prepend_str + 'PREPARING REQUEST %s DID %s:%s TO SUBMITTING STATE PREVIOUS %s FROM %s TO %s USING %s ' % (file_metadata['request_id'],
                                                                                                                                file_metadata['scope'],
                                                                                                                                file_metadata['name'],
                                                                                                                                file_metadata['previous_attempt_id'] if 'previous_attempt_id' in file_metadata else None,
                                                                                                                                t_file['sources'],
                                                                                                                                t_file['destinations'],
                                                                                                                                external_host)
            xfers_ret[request_id] = {'state': RequestState.SUBMITTING, 'external_host': external_host, 'external_id': None, 'dest_url': t_file['destinations'][0]}
            logging.info("%s", log_str)
            xfers_ret[request_id]['file'] = t_file
        logging.debug('%s Start to prepare transfer', prepend_str)
        transfer_core.prepare_sources_for_transfers(xfers_ret)
        logging.debug('%s Finished to prepare transfer', prepend_str)
    except RequestNotFound as error:
        logging.error(prepend_str + str(error))
        return
    except Exception:
        logging.error(prepend_str + 'Failed to prepare requests %s state to SUBMITTING (Will not submit jobs but return directly) with error: %s' % (list(xfers_ret.keys()), traceback.format_exc()))
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
        logging.info(prepend_str + 'About to submit job to %s with timeout %s' % (external_host, timeout))
        # A eid is returned if the job is properly submitted otherwise an exception is raised
        eid = transfer_core.submit_bulk_transfers(external_host,
                                                  files=job['files'],
                                                  transfertool=TRANSFER_TOOL,
                                                  job_params=job['job_params'],
                                                  timeout=timeout,
                                                  user_transfer_job=user_transfer_job)
        duration = time.time() - start_time
        logging.info(prepend_str + 'Submit job %s to %s in %s seconds' % (eid, external_host, duration))
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
                logging.info(prepend_str + 'COPYING REQUEST %s DID %s:%s USING %s with state(%s) with eid(%s)' % (file_metadata['request_id'], file_metadata['scope'], file_metadata['name'], external_host, RequestState.SUBMITTED, eid))
            logging.debug(prepend_str + 'Start to bulk register transfer state for eid %s' % eid)
            transfer_core.set_transfers_state(xfers_ret, datetime.datetime.utcnow())
            logging.debug('%s Finished to register transfer state', prepend_str)
        except Exception:
            logging.error('%s Failed to register transfer state with error: %s', prepend_str, traceback.format_exc())
            try:
                logging.info('%s Cancel transfer %s on %s', prepend_str, eid, external_host)
                request.cancel_request_external_id(eid, external_host)
            except Exception:
                # The job is still submitted in the file transfer service but the request is not updated. Possibility to have a double submission during the next cycle
                logging.error(prepend_str + 'Failed to cancel transfers %s on %s with error: %s' % (eid, external_host, traceback.format_exc()))

    # This exception is raised if one job is already submitted for one file
    except DuplicateFileTransferSubmission as error:
        logging.warn('%s Failed to submit a job because of duplicate file : %s', prepend_str, str(error))
        logging.info('%s Submitting files one by one', prepend_str)

        try:
            # In this loop we submit the jobs and update the requests state one by one
            single_xfers_ret = {}
            for t_file in job['files']:
                single_xfers_ret = {}
                single_xfers_ret[request_id] = xfers_ret[request_id]
                file_metadata = t_file['metadata']
                request_id = file_metadata['request_id']
                start_time = time.time()
                logging.info('%s About to submit job to %s with timeout %s', prepend_str, external_host, timeout)
                eid = transfer_core.submit_bulk_transfers(external_host,
                                                          files=[t_file],
                                                          transfertool=TRANSFER_TOOL,
                                                          job_params=job['job_params'],
                                                          timeout=timeout,
                                                          user_transfer_job=user_transfer_job)
                duration = time.time() - start_time
                logging.info(prepend_str + 'Submit job %s to %s in %s seconds' % (eid, external_host, duration))
                record_timer('daemons.conveyor.%s.submit_bulk_transfer.per_file' % submitter, (time.time() - start_time) * 1000)
                record_counter('daemons.conveyor.%s.submit_bulk_transfer' % submitter, 1)
                record_timer('daemons.conveyor.%s.submit_bulk_transfer.files' % submitter, 1)
                single_xfers_ret[request_id]['state'] = RequestState.SUBMITTED
                single_xfers_ret[request_id]['external_id'] = eid
                logging.info(prepend_str + 'COPYING REQUEST %s DID %s:%s USING %s with state(%s) with eid(%s)' % (file_metadata['request_id'], file_metadata['scope'], file_metadata['name'], external_host, RequestState.SUBMITTED, eid))
                try:
                    logging.debug('%s Start to register transfer state', prepend_str)
                    transfer_core.set_transfers_state(single_xfers_ret, datetime.datetime.utcnow())
                    logging.debug('%s Finished to register transfer state', prepend_str)
                except Exception:
                    logging.error('%s Failed to register transfer state with error: %s', prepend_str, traceback.format_exc())
                    try:
                        logging.info('%s Cancel transfer %s on %s', prepend_str, eid, external_host)
                        request.cancel_request_external_id(eid, external_host)
                    except Exception:
                        logging.error(prepend_str + 'Failed to cancel transfers %s on %s with error: %s' % (eid, external_host, traceback.format_exc()))

        except (DuplicateFileTransferSubmission, TransferToolTimeout, TransferToolWrongAnswer, Exception) as error:
            request_id = single_xfers_ret.keys()[0]
            single_xfers_ret[request_id]['state'] = RequestState.SUBMISSION_FAILED
            logging.error('%s Cannot submit the job for request %s : %s', prepend_str, request_id, str(error))
            try:
                logging.debug('%s Update the transfer state to fail', prepend_str)
                transfer_core.set_transfers_state(single_xfers_ret, datetime.datetime.utcnow())
                logging.debug('%s Finished to register transfer state', prepend_str)
            except Exception:
                logging.error('%s Failed to register transfer state with error: %s', prepend_str, traceback.format_exc())
                # No need to cancel the job here

    # The following exceptions are raised if the job failed to be submitted
    except (TransferToolTimeout, TransferToolWrongAnswer) as error:
        logging.error(prepend_str + str(error))
        try:
            for t_file in job['files']:
                file_metadata = t_file['metadata']
                request_id = file_metadata['request_id']
                xfers_ret[request_id]['state'] = RequestState.SUBMISSION_FAILED
            logging.debug('%s Start to register transfer state', prepend_str)
            transfer_core.set_transfers_state(xfers_ret, datetime.datetime.utcnow())
            logging.debug('%s Finished to register transfer state', prepend_str)
        except Exception:
            logging.error('%s Failed to register transfer state with error: %s', prepend_str, traceback.format_exc())
            # No need to cancel the job here

    except Exception as error:
        logging.error('%s Failed to submit a job with error %s: %s', prepend_str, str(error), traceback.format_exc())


@read_session
def bulk_group_transfer(transfers, policy='rule', group_bulk=200, source_strategy=None, max_time_in_queue=None, session=None):
    """
    Group transfers in bulk based on certain criterias

    :param transfers:             List of transfers to group.
    :param plicy:                 Policy to use to group.
    :param group_bulk:            Bulk sizes.
    :param source_strategy:       Strategy to group sources
    :param max_time_in_queue:     Maximum time in queue
    :return:                      List of grouped transfers.
    """

    grouped_transfers = {}
    grouped_jobs = {}

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
        logging.warning('activity_source_strategy not properly defined')
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

        external_host = transfer['external_host']
        scope = t_file['metadata']['scope']
        scope_str = scope.internal
        activity = t_file['activity']

        if external_host not in grouped_transfers:
            grouped_transfers[external_host] = {}
            if USER_TRANSFERS not in ['cms'] or activity not in USER_ACTIVITY:
                grouped_jobs[external_host] = []
            elif activity in USER_ACTIVITY:
                grouped_jobs[external_host] = {}
                if scope_str not in grouped_transfers[external_host]:
                    grouped_transfers[external_host][scope_str] = {}
                    grouped_jobs[external_host][scope_str] = []

        job_params = {'account': transfer['account'],
                      'use_oidc': transfer.get('use_oidc', False),
                      'verify_checksum': verify_checksum,
                      'copy_pin_lifetime': transfer['copy_pin_lifetime'] if transfer['copy_pin_lifetime'] else -1,
                      'bring_online': transfer['bring_online'] if transfer['bring_online'] else None,
                      'job_metadata': {'issuer': 'rucio'},  # finaly job_meta will like this. currently job_meta will equal file_meta to include request_id and etc.
                      'overwrite': transfer['overwrite'],
                      'priority': 3,
                      's3alternate': True}
        if multihop:
            job_params['multihop'] = True
        if strict_copy:
            job_params['strict_copy'] = True

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
            if USER_TRANSFERS not in ['cms'] or activity not in USER_ACTIVITY:
                grouped_jobs[external_host].append({'files': [t_file], 'job_params': job_params})
            elif activity in USER_ACTIVITY:
                grouped_jobs[external_host][scope_str].append({'files': [t_file], 'job_params': job_params})
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

            if job_key not in grouped_transfers[external_host]:
                if USER_TRANSFERS not in ['cms'] or activity not in USER_ACTIVITY:
                    grouped_transfers[external_host][job_key] = {}
                elif activity in USER_ACTIVITY:
                    grouped_transfers[external_host][scope_str][job_key] = {}

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

            if USER_TRANSFERS not in ['cms'] or activity not in USER_ACTIVITY:
                if policy_key not in grouped_transfers[external_host][job_key]:
                    grouped_transfers[external_host][job_key][policy_key] = {'files': [t_file], 'job_params': job_params}
                else:
                    if multihop:
                        # The parent transfer should be the first of the list
                        # TODO : Only work for a single hop now, need to be able to handle multiple hops
                        if transfer['parent_request']:  # This is the child
                            grouped_transfers[external_host][job_key][policy_key]['files'].append(t_file)
                        else:
                            grouped_transfers[external_host][job_key][policy_key]['files'].insert(0, t_file)
                    else:
                        grouped_transfers[external_host][job_key][policy_key]['files'].append(t_file)
            elif activity in USER_ACTIVITY:
                if policy_key not in grouped_transfers[external_host][scope_str][job_key]:
                    grouped_transfers[external_host][scope_str][job_key][policy_key] = {'files': [t_file], 'job_params': job_params}
                else:
                    if multihop:
                        # The parent transfer should be the first of the list
                        # TODO : Only work for a single hop now, need to be able to handle multiple hops
                        if transfer['parent_request']:  # This is the child
                            grouped_transfers[external_host][scope_str][job_key][policy_key]['files'].append(t_file)
                        else:
                            grouped_transfers[external_host][scope_str][job_key][policy_key]['files'].insert(0, t_file)

    # for jobs with different job_key, we cannot put in one job.
    for external_host in grouped_transfers:
        if USER_TRANSFERS not in ['cms'] or activity not in USER_ACTIVITY:
            for job_key in grouped_transfers[external_host]:
                # for all policy groups in job_key, the job_params is the same.
                for policy_key in grouped_transfers[external_host][job_key]:
                    job_params = grouped_transfers[external_host][job_key][policy_key]['job_params']
                    for xfers_files in chunks(grouped_transfers[external_host][job_key][policy_key]['files'], group_bulk):
                        # for the last small piece, just submit it.
                        grouped_jobs[external_host].append({'files': xfers_files, 'job_params': job_params})
        elif activity in USER_ACTIVITY:
            for scope_key in grouped_transfers[external_host]:
                for job_key in grouped_transfers[external_host][scope_key]:
                    # for all policy groups in job_key, the job_params is the same.
                    for policy_key in grouped_transfers[external_host][scope_key][job_key]:
                        job_params = grouped_transfers[external_host][scope_key][job_key][policy_key]['job_params']
                        for xfers_files in chunks(grouped_transfers[external_host][scope_key][job_key][policy_key]['files'], group_bulk):
                            # for the last small piece, just submit it.
                            grouped_jobs[external_host][scope_key].append({'files': xfers_files, 'job_params': job_params})

    return grouped_jobs


def get_conveyor_rses(rses=None, include_rses=None, exclude_rses=None):
    """
    Get a list of rses for conveyor

    :param rses:          List of rses (Single-VO only)
    :param include_rses:  RSEs to include
    :param exclude_rses:  RSEs to exclude
    :return:              List of working rses
    """
    working_rses = []
    rses_list = list_rses()
    if rses:
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            logging.warning('Ignoring argument rses, this is only available in a single-vo setup. Please try an RSE Expression with include_rses if it is required.')
        else:
            working_rses = [rse for rse in rses_list if rse['rse'] in rses]

    if include_rses:
        try:
            parsed_rses = parse_expression(include_rses, session=None)
        except InvalidRSEExpression as error:
            logging.error("Invalid RSE exception %s to include RSEs", include_rses)
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
            logging.error("Invalid RSE exception %s to exclude RSEs: %s", exclude_rses, error)
        else:
            working_rses = [rse for rse in working_rses if rse not in parsed_rses]

    working_rses = [rsemgr.get_rse_info(rse['id']) for rse in working_rses]
    return working_rses
