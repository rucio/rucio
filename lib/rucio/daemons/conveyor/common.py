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

from rucio.common.config import config_get
from rucio.common.exception import InvalidRSEExpression, TransferToolTimeout, TransferToolWrongAnswer, RequestNotFound, ConfigNotFound
from rucio.common.utils import chunks
from rucio.core import request, transfer as transfer_core
from rucio.core.config import get
from rucio.core.monitor import record_counter, record_timer
from rucio.core.rse import list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla.constants import RequestState
from rucio.rse import rsemanager as rsemgr

USER_ACTIVITY = config_get('conveyor', 'user_activities', False, ['user', 'user_test'])
USER_TRANSFERS = config_get('conveyor', 'user_transfers', False, None)


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

    # prepare submitting
    xfers_ret = {}

    try:
        for file in job['files']:
            file_metadata = file['metadata']
            request_id = file_metadata['request_id']
            log_str = prepend_str + 'PREPARING REQUEST %s DID %s:%s TO SUBMITTING STATE PREVIOUS %s FROM %s TO %s USING %s ' % (file_metadata['request_id'],
                                                                                                                                file_metadata['scope'],
                                                                                                                                file_metadata['name'],
                                                                                                                                file_metadata['previous_attempt_id'] if 'previous_attempt_id' in file_metadata else None,
                                                                                                                                file['sources'],
                                                                                                                                file['destinations'],
                                                                                                                                external_host)
            xfers_ret[request_id] = {'state': RequestState.SUBMITTING, 'external_host': external_host, 'external_id': None, 'dest_url': file['destinations'][0]}
            logging.info("%s" % (log_str))
            xfers_ret[request_id]['file'] = file
        logging.debug(prepend_str + 'Start to prepare transfer')
        transfer_core.prepare_sources_for_transfers(xfers_ret)
        logging.debug(prepend_str + 'Finished to prepare transfer')
    except RequestNotFound as error:
        logging.error(prepend_str + str(error))
        return
    except Exception:
        logging.error(prepend_str + 'Failed to prepare requests %s state to SUBMITTING (Will not submit jobs but return directly) with error: %s' % (list(xfers_ret.keys()), traceback.format_exc()))
        return

    # submit the job
    eid = None
    try:
        start_time = time.time()
        logging.info(prepend_str + 'About to submit job to %s with timeout %s' % (external_host, timeout))
        eid = transfer_core.submit_bulk_transfers(external_host,
                                                  files=job['files'],
                                                  transfertool='fts3',
                                                  job_params=job['job_params'],
                                                  timeout=timeout,
                                                  user_transfer_job=user_transfer_job)
        duration = time.time() - start_time
        logging.info(prepend_str + 'Submit job %s to %s in %s seconds' % (eid, external_host, duration))
        record_timer('daemons.conveyor.%s.submit_bulk_transfer.per_file' % submitter, (time.time() - start_time) * 1000 / len(job['files']))
        record_counter('daemons.conveyor.%s.submit_bulk_transfer' % submitter, len(job['files']))
        record_timer('daemons.conveyor.%s.submit_bulk_transfer.files' % submitter, len(job['files']))
    except (TransferToolTimeout, TransferToolWrongAnswer) as error:
        logging.error(prepend_str + str(error))

    except Exception as error:
        logging.error(prepend_str + 'Failed to submit a job with error %s: %s' % (str(error), traceback.format_exc()))

    # register transfer
    xfers_ret = {}
    try:
        for file in job['files']:
            file_metadata = file['metadata']
            request_id = file_metadata['request_id']
            log_str = prepend_str + 'COPYING REQUEST %s DID %s:%s USING %s' % (file_metadata['request_id'], file_metadata['scope'], file_metadata['name'], external_host)
            if eid:
                xfers_ret[request_id] = {'scope': file_metadata['scope'],
                                         'name': file_metadata['name'],
                                         'state': RequestState.SUBMITTED,
                                         'external_host': external_host,
                                         'external_id': eid,
                                         'request_type': file.get('request_type', None),
                                         'dst_rse': file_metadata.get('dst_rse', None),
                                         'src_rse': file_metadata.get('src_rse', None),
                                         'src_rse_id': file_metadata['src_rse_id'],
                                         'metadata': file_metadata}
                log_str += ' with state(%s) with eid(%s)' % (RequestState.SUBMITTED, eid)
                logging.info("%s" % (log_str))
            else:
                xfers_ret[request_id] = {'scope': file_metadata['scope'],
                                         'name': file_metadata['name'],
                                         'state': RequestState.SUBMISSION_FAILED,
                                         'external_host': external_host,
                                         'external_id': None,
                                         'request_type': file.get('request_type', None),
                                         'dst_rse': file_metadata.get('dst_rse', None),
                                         'src_rse': file_metadata.get('src_rse', None),
                                         'src_rse_id': file_metadata['src_rse_id'],
                                         'metadata': file_metadata}
                log_str += ' with state(%s) with eid(%s)' % (RequestState.SUBMISSION_FAILED, None)
                logging.warn("%s" % (log_str))
        logging.debug(prepend_str + 'Start to register transfer state')
        transfer_core.set_transfers_state(xfers_ret, datetime.datetime.utcnow())
        logging.debug(prepend_str + 'Finished to register transfer state')
    except Exception:
        logging.error(prepend_str + 'Failed to register transfer state with error: %s' % (traceback.format_exc()))
        try:
            if eid:
                logging.info(prepend_str + 'Cancel transfer %s on %s' % (eid, external_host))
                request.cancel_request_external_id(eid, external_host)
        except Exception:
            logging.error(prepend_str + 'Failed to cancel transfers %s on %s with error: %s' % (eid, external_host, traceback.format_exc()))


def bulk_group_transfer(transfers, policy='rule', group_bulk=200, source_strategy=None, max_time_in_queue=None):
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
        file = {'sources': transfer['sources'],
                'destinations': transfer['dest_urls'],
                'metadata': transfer['file_metadata'],
                'filesize': int(transfer['file_metadata']['filesize']),
                'checksum': None,
                'verify_checksum': verify_checksum,
                'selection_strategy': source_strategy if source_strategy else activity_source_strategy.get(str(transfer['file_metadata']['activity']), default_source_strategy),
                'request_type': transfer['file_metadata'].get('request_type', None),
                'activity': str(transfer['file_metadata']['activity'])}
        if verify_checksum != 'none':
            if 'md5' in list(file['metadata'].keys()) and file['metadata']['md5']:
                file['checksum'] = 'MD5:%s' % str(file['metadata']['md5'])
            if 'adler32' in list(file['metadata'].keys()) and file['metadata']['adler32']:
                file['checksum'] = 'ADLER32:%s' % str(file['metadata']['adler32'])

        external_host = transfer['external_host']
        scope = file['metadata']['scope']
        activity = file['activity']

        if external_host not in grouped_transfers:
            grouped_transfers[external_host] = {}
            if USER_TRANSFERS not in ['cms'] or activity not in USER_ACTIVITY:
                grouped_jobs[external_host] = []
            elif activity in USER_ACTIVITY:
                grouped_jobs[external_host] = {}
                if scope not in grouped_transfers[external_host]:
                    grouped_transfers[external_host][scope] = {}
                    grouped_jobs[external_host][scope] = []

        job_params = {'verify_checksum': verify_checksum,
                      'copy_pin_lifetime': transfer['copy_pin_lifetime'] if transfer['copy_pin_lifetime'] else -1,
                      'bring_online': transfer['bring_online'] if transfer['bring_online'] else None,
                      'job_metadata': {'issuer': 'rucio'},  # finaly job_meta will like this. currently job_meta will equal file_meta to include request_id and etc.
                      'overwrite': transfer['overwrite'],
                      'priority': 3,
                      's3alternate': True}

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
                grouped_jobs[external_host].append({'files': [file], 'job_params': job_params})
            elif activity in USER_ACTIVITY:
                grouped_jobs[external_host][scope].append({'files': [file], 'job_params': job_params})
        else:
            job_params['job_metadata']['multi_sources'] = False
            job_key = '%s,%s,%s,%s,%s,%s,%s,%s' % (job_params['verify_checksum'], job_params.get('spacetoken', None),
                                                   job_params['copy_pin_lifetime'],
                                                   job_params['bring_online'], job_params['job_metadata'],
                                                   job_params.get('source_spacetoken', None),
                                                   job_params['overwrite'], job_params['priority'])
            if 'max_time_in_queue' in job_params:
                job_key = job_key + ',%s' % job_params['max_time_in_queue']

            if job_key not in grouped_transfers[external_host]:
                if USER_TRANSFERS not in ['cms'] or activity not in USER_ACTIVITY:
                    grouped_transfers[external_host][job_key] = {}
                elif activity in USER_ACTIVITY:
                    grouped_transfers[external_host][scope][job_key] = {}

            if policy == 'rule':
                policy_key = '%s' % (transfer['rule_id'])
            if policy == 'dest':
                policy_key = '%s' % (file['metadata']['dst_rse'])
            if policy == 'src_dest':
                policy_key = '%s,%s' % (file['metadata']['src_rse'], file['metadata']['dst_rse'])
            if policy == 'rule_src_dest':
                policy_key = '%s,%s,%s' % (transfer['rule_id'], file['metadata']['src_rse'], file['metadata']['dst_rse'])
            if policy == 'activity_dest':
                policy_key = '%s %s' % (activity, file['metadata']['dst_rse'])
                policy_key = "_".join(policy_key.split(' '))
            if policy == 'activity_src_dest':
                policy_key = '%s %s %s' % (activity, file['metadata']['src_rse'], file['metadata']['dst_rse'])
                policy_key = "_".join(policy_key.split(' '))
            # maybe here we need to hash the key if it's too long

            if USER_TRANSFERS not in ['cms'] or activity not in USER_ACTIVITY:
                if policy_key not in grouped_transfers[external_host][job_key]:
                    grouped_transfers[external_host][job_key][policy_key] = {'files': [file], 'job_params': job_params}
                else:
                    grouped_transfers[external_host][job_key][policy_key]['files'].append(file)
            elif activity in USER_ACTIVITY:
                if policy_key not in grouped_transfers[external_host][scope][job_key]:
                    grouped_transfers[external_host][scope][job_key][policy_key] = {'files': [file], 'job_params': job_params}
                else:
                    grouped_transfers[external_host][scope][job_key][policy_key]['files'].append(file)

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

    :param rses:          List of rses
    :param include_rses:  RSEs to include
    :param exclude_rses:  RSEs to exclude
    :return:              List of working rses
    """
    working_rses = []
    rses_list = list_rses()
    if rses:
        working_rses = [rse for rse in rses_list if rse['rse'] in rses]

    if include_rses:
        try:
            parsed_rses = parse_expression(include_rses, session=None)
        except InvalidRSEExpression as error:
            logging.error("Invalid RSE exception %s to include RSEs" % (include_rses))
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
            logging.error("Invalid RSE exception %s to exclude RSEs: %s" % (exclude_rses, error))
        else:
            working_rses = [rse for rse in working_rses if rse not in parsed_rses]

    working_rses = [rsemgr.get_rse_info(rse['rse']) for rse in working_rses]
    return working_rses
