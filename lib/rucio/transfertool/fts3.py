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

import datetime
import json
import functools
import logging
import traceback
import uuid
from typing import Any, Callable, Dict, Tuple, TYPE_CHECKING
from urllib.parse import urlparse

import requests
from configparser import NoOptionError, NoSectionError
from json import loads
from requests.adapters import ReadTimeout
from requests.packages.urllib3 import disable_warnings  # pylint: disable=import-error

from dogpile.cache.api import NoValue

from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get, config_get_bool
from rucio.common.constants import FTS_JOB_TYPE, FTS_STATE, FTS_COMPLETE_STATE
from rucio.common.exception import TransferToolTimeout, TransferToolWrongAnswer, DuplicateFileTransferSubmission
from rucio.common.stopwatch import Stopwatch
from rucio.common.utils import APIEncoder, chunks, PREFERRED_CHECKSUM
from rucio.core.request import get_source_rse, get_transfer_error
from rucio.core.rse import get_rse_supported_checksums_from_attributes
from rucio.core.oidc import get_token_for_account_operation
from rucio.core.monitor import MetricManager
from rucio.transfertool.transfertool import Transfertool, TransferToolBuilder, TransferStatusReport
from rucio.db.sqla.constants import RequestState

if TYPE_CHECKING:
    from rucio.core.transfer import DirectTransferDefinition
    from rucio.core.rse import RseData

logging.getLogger("requests").setLevel(logging.CRITICAL)
disable_warnings()

REGION_SHORT = make_region_memcached(expiration_time=900)
METRICS = MetricManager(module=__name__)

SUBMISSION_COUNTER = METRICS.counter(name='{host}.submission.{state}',
                                     documentation='Number of transfers submitted', labelnames=('state', 'host'))
CANCEL_COUNTER = METRICS.counter(name='{host}.cancel.{state}',
                                 documentation='Number of cancelled transfers', labelnames=('state', 'host'))
UPDATE_PRIORITY_COUNTER = METRICS.counter(name='{host}.update_priority.{state}',
                                          documentation='Number of priority updates', labelnames=('state', 'host'))
QUERY_COUNTER = METRICS.counter(name='{host}.query.{state}',
                                documentation='Number of queried transfers', labelnames=('state', 'host'))
WHOAMI_COUNTER = METRICS.counter(name='{host}.whoami.{state}',
                                 documentation='Number of whoami requests', labelnames=('state', 'host'))
VERSION_COUNTER = METRICS.counter(name='{host}.version.{state}',
                                  documentation='Number of version requests', labelnames=('state', 'host'))
BULK_QUERY_COUNTER = METRICS.counter(name='{host}.bulk_query.{state}',
                                     documentation='Number of bulk queries', labelnames=('state', 'host'))
QUERY_DETAILS_COUNTER = METRICS.counter(name='{host}.query_details.{state}',
                                        documentation='Number of detailed status queries', labelnames=('state', 'host'))

ALLOW_USER_OIDC_TOKENS = config_get_bool('conveyor', 'allow_user_oidc_tokens', False, False)
REQUEST_OIDC_SCOPE = config_get('conveyor', 'request_oidc_scope', False, 'fts:submit-transfer')
REQUEST_OIDC_AUDIENCE = config_get('conveyor', 'request_oidc_audience', False, 'fts:example')
REWRITE_HTTPS_TO_DAVS = config_get_bool('transfers', 'rewrite_https_to_davs', default=False)

# https://fts3-docs.web.cern.ch/fts3-docs/docs/state_machine.html
FINAL_FTS_JOB_STATES = (FTS_STATE.FAILED, FTS_STATE.CANCELED, FTS_STATE.FINISHED, FTS_STATE.FINISHEDDIRTY)
FINAL_FTS_FILE_STATES = (FTS_STATE.FAILED, FTS_STATE.CANCELED, FTS_STATE.FINISHED, FTS_STATE.NOT_USED)


def _configured_source_strategy(activity: str, logger: Callable[..., Any]) -> str:
    """
    Retrieve from the configuration the source selection strategy for the given activity
    """
    try:
        default_source_strategy = config_get(section='conveyor', option='default-source-strategy')
    except (NoOptionError, NoSectionError, RuntimeError):
        default_source_strategy = 'orderly'

    try:
        activity_source_strategy = config_get(section='conveyor', option='activity-source-strategy')
        activity_source_strategy = loads(activity_source_strategy)
    except (NoOptionError, NoSectionError, RuntimeError):
        activity_source_strategy = {}
    except ValueError:
        logger(logging.WARNING, 'activity_source_strategy not properly defined')
        activity_source_strategy = {}

    return activity_source_strategy.get(str(activity), default_source_strategy)


def oidc_supported(transfer_hop) -> bool:
    """
    checking OIDC AuthN/Z support per destination and source RSEs;

    for oidc_support to be activated, all sources and the destination must explicitly support it
    """
    # assumes use of boolean 'oidc_support' RSE attribute
    if not transfer_hop.dst.rse.attributes.get('oidc_support', False):
        return False

    for source in transfer_hop.sources:
        if not source.rse.attributes.get('oidc_support', False):
            return False
    return True


def _checksum_validation_strategy(
    transfer: "DirectTransferDefinition",
    logger: Callable[..., Any],
) -> Tuple[str, str]:
    """
    Compute the checksum validation strategy (none, source, destination or both) and the checksum
    to use (in the format accepted by FTS) from the attributes of the source and destination RSE.
    """
    src_attributes = transfer.src.rse.attributes
    if src_attributes.get('verify_checksum', True):
        src_checksums = set(get_rse_supported_checksums_from_attributes(src_attributes))
    else:
        src_checksums = set()

    dst_attributes = transfer.dst.rse.attributes
    if dst_attributes.get('verify_checksum', True):
        dst_checksums = set(get_rse_supported_checksums_from_attributes(dst_attributes))
    else:
        dst_checksums = set()

    intersection = src_checksums.intersection(dst_checksums)

    if intersection:
        strategy, possible_checksums = 'both', intersection
    elif dst_checksums:
        # The prioritization of destination over source here is desired, not random
        logger(logging.INFO, 'No common checksum method. Verifying destination only.')
        strategy, possible_checksums = 'target', dst_checksums
    elif src_checksums:
        logger(logging.INFO, 'No common checksum method. Verifying source only.')
        strategy, possible_checksums = 'source', src_checksums
    else:
        logger(logging.INFO, 'No common checksum method. Not verifying source nor destination.')
        strategy, possible_checksums = 'none', set()

    checksum_to_use = None
    for checksum_name in possible_checksums:
        checksum_value = getattr(transfer.rws, checksum_name, '')
        if not checksum_value:
            continue

        checksum_to_use = '%s:%s' % (checksum_name.upper(), checksum_value)
        if checksum_name == PREFERRED_CHECKSUM:
            break

    return strategy, checksum_to_use


def job_params_for_fts_transfer(transfer, bring_online, default_lifetime, archive_timeout_override, max_time_in_queue, logger, multihop=False):
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

    verify_checksum, _checksum_to_use = _checksum_validation_strategy(transfer, logger=logger)

    job_params = {'account': transfer.rws.account,
                  'verify_checksum': verify_checksum,
                  'copy_pin_lifetime': transfer.rws.attributes.get('lifetime', default_lifetime),
                  'bring_online': bring_online_local,
                  'job_metadata': {
                      'issuer': 'rucio',
                      'multi_sources': True if len(transfer.legacy_sources) > 1 else False,
                  },
                  'overwrite': transfer.rws.attributes.get('overwrite', overwrite),
                  'priority': transfer.rws.priority}

    if multihop:
        job_params['multihop'] = True
        job_params['job_metadata']['multihop'] = True
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
            # FTS only supports dst_file metadata if archive_timeout is set
            job_params['dst_file_report'] = True
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


def bulk_group_transfers(transfer_paths, policy='rule', group_bulk=200, source_strategy=None, max_time_in_queue=None,
                         logger=logging.log, archive_timeout_override=None, bring_online=None, default_lifetime=None):
    """
    Group transfers in bulk based on certain criterias

    :param transfer_paths:           List of transfer paths to group. Each path is a list of single-hop transfers.
    :param policy:                   Policy to use to group.
    :param group_bulk:               Bulk sizes.
    :param source_strategy:          Strategy to group sources
    :param max_time_in_queue:        Maximum time in queue
    :param archive_timeout_override: Override the archive_timeout parameter for any transfers with it set (0 to unset)
    :param logger:                   Optional decorated logger that can be passed from the calling daemons or servers.
    :return:                         List of grouped transfers.
    """

    grouped_transfers = {}
    grouped_jobs = []

    _build_job_params = functools.partial(job_params_for_fts_transfer,
                                          bring_online=bring_online,
                                          default_lifetime=default_lifetime,
                                          archive_timeout_override=archive_timeout_override,
                                          max_time_in_queue=max_time_in_queue,
                                          logger=logger)
    for transfer_path in transfer_paths:
        if len(transfer_path) > 1:
            # for multihop transfers, all the path is submitted as a separate job
            job_params = _build_job_params(transfer_path[-1], multihop=True)

            overwrite_hop = True
            for transfer in transfer_path[:-1]:
                hop_params = _build_job_params(transfer, multihop=True)
                # Only allow overwrite if all transfers in multihop allow it
                job_params['overwrite'] = hop_params['overwrite'] and job_params['overwrite']
                # Allow overwrite_hop if all intermediate hops allow it (ignoring the last hop)
                overwrite_hop = hop_params['overwrite'] and overwrite_hop
                # Activate bring_online if it was requested by first hop (it is a multihop starting at a tape)
                # We don't allow multihop via a tape, so bring_online should not be set on any other hop
                if transfer is transfer_path[0] and hop_params['bring_online']:
                    job_params['bring_online'] = hop_params['bring_online']
            if not job_params['overwrite'] and overwrite_hop:
                job_params['overwrite_hop'] = overwrite_hop

            group_key = 'multihop_%s' % transfer_path[-1].rws.request_id
            grouped_transfers[group_key] = {'transfers': transfer_path[0:group_bulk], 'job_params': job_params}
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
        for transfer_paths in chunks(group['transfers'], group_bulk):
            grouped_jobs.append({'transfers': transfer_paths, 'job_params': job_params})

    return grouped_jobs


class Fts3TransferStatusReport(TransferStatusReport):

    supported_db_fields = [
        'state',
        'external_id',
        'started_at',
        'transferred_at',
        'staging_started_at',
        'staging_finished_at',
        'source_rse_id',
        'err_msg',
        'attributes',
    ]

    def __init__(self, external_host, request_id, request=None):
        super().__init__(request_id, request=request)
        self.external_host = external_host

        # Initialized in child class constructors:
        self._transfer_id = None
        self._file_metadata = {}
        self._multi_sources = None
        self._src_url = None
        self._dst_url = None
        # Initialized in child class initialize():
        self._reason = None
        self._src_rse = None
        self._fts_address = self.external_host
        # Supported db fields bellow:
        self.state = None
        self.external_id = None
        self.started_at = None
        self.transferred_at = None
        self.staging_started_at = None
        self.staging_finished_at = None
        self.source_rse_id = None
        self.err_msg = None
        self.attributes = None

    def __str__(self):
        return f'Transfer {self._transfer_id} of {self._file_metadata["scope"]}:{self._file_metadata["name"]} ' \
               f'{self._file_metadata["src_rse"]} --({self._file_metadata["request_id"]})-> {self._file_metadata["dst_rse"]}'

    def initialize(self, session, logger=logging.log):
        raise NotImplementedError(f"{self.__class__.__name__} is abstract and shouldn't be used directly")

    def get_monitor_msg_fields(self, session, logger=logging.log):
        self.ensure_initialized(session, logger)
        fields = {
            'transfer_link': self._transfer_link(),
            'reason': self._reason,
            'src-type': self._file_metadata.get('src_type'),
            'src-rse': self._src_rse,
            'src-url': self._src_url,
            'dst-type': self._file_metadata.get('src_type'),
            'dst-rse': self._file_metadata.get('dst_rse'),
            'dst-url': self._dst_url,
            'started_at': self.started_at,
            'transferred_at': self.transferred_at,
        }
        return fields

    def _transfer_link(self):
        return '%s/fts3/ftsmon/#/job/%s' % (self._fts_address.replace('8446', '8449'), self._transfer_id)

    def _find_attribute_updates(self, request, new_state, reason, overwrite_corrupted_files):
        attributes = None
        if new_state == RequestState.FAILED and 'Destination file exists and overwrite is not enabled' in (reason or ''):
            dst_file = self._file_metadata.get('dst_file', {})
            if self._dst_file_set_and_file_corrupted(request, dst_file):
                if overwrite_corrupted_files:
                    attributes = request['attributes']
                    attributes['overwrite'] = True
        return attributes

    def _find_used_source_rse(self, session, logger):
        """
        For multi-source transfers, FTS has a choice between multiple sources.
        Find which of the possible sources FTS actually used for the transfer.
        """
        meta_rse_name = self._file_metadata.get('src_rse', None)
        meta_rse_id = self._file_metadata.get('src_rse_id', None)
        request_id = self._file_metadata.get('request_id', None)

        if self._multi_sources and self._src_url:
            rse_name, rse_id = get_source_rse(request_id, self._src_url, session=session)
            if rse_name and rse_name != meta_rse_name:
                logger(logging.DEBUG, 'Correct RSE: %s for source surl: %s' % (rse_name, self._src_url))
                return rse_name, rse_id

        return meta_rse_name, meta_rse_id

    @staticmethod
    def _dst_file_set_and_file_corrupted(request, dst_file):
        """
        Returns True if the `dst_file` dict returned by fts was filled and its content allows to
        affirm that the file is corrupted.
        """
        if (request and dst_file and (
                dst_file.get('file_size') is not None and dst_file['file_size'] != request.get('bytes')
                or dst_file.get('checksum_type', '').lower() == 'adler32' and dst_file.get('checksum_value') != request.get('adler32')
                or dst_file.get('checksum_type', '').lower() == 'md5' and dst_file.get('checksum_value') != request.get('md5'))):
            return True
        return False

    @staticmethod
    def _dst_file_set_and_file_correct(request, dst_file):
        """
        Returns True if the `dst_file` dict returned by fts was filled and its content allows to
        affirm that the file is correct.
        """
        if (request and dst_file
                and dst_file.get('file_size')
                and dst_file.get('file_size') == request.get('bytes')
                and (dst_file.get('checksum_type', '').lower() == 'adler32' and dst_file.get('checksum_value') == request.get('adler32')
                     or dst_file.get('checksum_type', '').lower() == 'md5' and dst_file.get('checksum_value') == request.get('md5'))):
            return True
        return False

    @classmethod
    def _is_recoverable_fts_overwrite_error(cls, request: Dict[str, Any], reason: str,
                                            file_metadata: Dict[str, Any]) -> bool:
        """
        Verify the special case when FTS cannot copy a file because destination exists and overwrite is disabled,
        but the destination file is actually correct.

        This can happen when some transitory error happened during a previous submission attempt.
        Hence, the transfer is correctly executed by FTS, but rucio doesn't know about it.

        Returns true when the request must be marked as successful even if it was reported failed by FTS.
        """
        if not request or not file_metadata:
            return False
        dst_file = file_metadata.get('dst_file', {})
        dst_type = file_metadata.get('dst_type', None)
        METRICS.counter('overwrite.check.{rsetype}.{rse}').labels(rse=file_metadata["dst_rse"], rsetype=dst_type).inc()

        if 'Destination file exists and overwrite is not enabled' in (reason or ''):
            if cls._dst_file_set_and_file_correct(request, dst_file):
                if dst_type == 'DISK' or dst_file.get('file_on_tape'):
                    METRICS.counter('overwrite.ok.{rsetype}.{rse}').labels(rse=file_metadata["dst_rse"], rsetype=dst_type).inc()
                    return True

        METRICS.counter('overwrite.fail.{rsetype}.{rse}').labels(rse=file_metadata["dst_rse"], rsetype=dst_type).inc()
        return False


class FTS3CompletionMessageTransferStatusReport(Fts3TransferStatusReport):
    """
    Parses FTS Completion messages received via the message queue
    """
    def __init__(self, external_host, request_id, fts_message):
        super().__init__(external_host=external_host, request_id=request_id)

        self.fts_message = fts_message

        self._transfer_id = fts_message.get('tr_id').split("__")[-1]

        self._file_metadata = fts_message['file_metadata']
        self._multi_sources = str(fts_message.get('job_metadata', {}).get('multi_sources', '')).lower() == str('true')
        self._src_url = fts_message.get('src_url', None)
        self._dst_url = fts_message.get('dst_url', None)

    def initialize(self, session, logger=logging.log):

        fts_message = self.fts_message
        request_id = self.request_id

        reason = fts_message.get('t__error_message', None)
        # job_state = fts_message.get('t_final_transfer_state', None)
        new_state = None
        if str(fts_message['t_final_transfer_state']) == FTS_COMPLETE_STATE.OK:  # pylint:disable=no-member
            new_state = RequestState.DONE
        elif str(fts_message['t_final_transfer_state']) == FTS_COMPLETE_STATE.ERROR:
            request = self.request(session)
            if self._is_recoverable_fts_overwrite_error(request, reason, self._file_metadata):  # pylint:disable=no-member
                new_state = RequestState.DONE
            else:
                new_state = RequestState.FAILED

        transfer_id = self._transfer_id
        if new_state:
            request = self.request(session)
            if not request:
                logger(logging.WARNING, '%s: no request with this id in the database. Skipping. external_id: %s (%s). new_state: %s', request_id, transfer_id, self.external_host, new_state)
                return
            if request and request['external_id'] == transfer_id and request['state'] != new_state:
                src_rse_name, src_rse_id = self._find_used_source_rse(session, logger)

                self._reason = reason
                self._src_rse = src_rse_name
                self._fts_address = request['external_host'] or self._fts_address

                self.state = new_state
                self.external_id = transfer_id
                self.started_at = datetime.datetime.utcfromtimestamp(float(fts_message.get('tr_timestamp_start', 0)) / 1000)
                self.transferred_at = datetime.datetime.utcfromtimestamp(float(fts_message.get('tr_timestamp_complete', 0)) / 1000)
                self.staging_started_at = None
                self.staging_finished_at = None
                self.source_rse_id = src_rse_id
                self.err_msg = get_transfer_error(self.state, reason)
                if self.err_msg and self._file_metadata.get('src_type') == "TAPE":
                    self.err_msg = '[TAPE SOURCE] ' + self.err_msg
                self.attributes = self._find_attribute_updates(
                    request=request,
                    new_state=new_state,
                    reason=reason,
                    overwrite_corrupted_files=config_get_bool('transfers', 'overwrite_corrupted_files', default=False, session=session),
                )
            elif request['external_id'] != transfer_id:
                logger(logging.WARNING, "Response %s with transfer id %s is different from the request transfer id %s, will not update" % (request_id, transfer_id, request['external_id']))
            else:
                logger(logging.DEBUG, "Request %s is already in %s state, will not update" % (request_id, new_state))
        else:
            logger(logging.DEBUG, "No state change computed for %s. Skipping request update." % request_id)


class FTS3ApiTransferStatusReport(Fts3TransferStatusReport):
    """
    Parses FTS api response
    """
    def __init__(self, external_host, request_id, job_response, file_response, request=None):
        super().__init__(external_host=external_host, request_id=request_id, request=request)

        self.job_response = job_response
        self.file_response = file_response

        self._transfer_id = job_response.get('job_id')

        self._file_metadata = file_response['file_metadata']
        self._multi_sources = str(job_response['job_metadata'].get('multi_sources', '')).lower() == str('true')
        self._src_url = file_response.get('source_surl', None)
        self._dst_url = file_response.get('dest_surl', None)
        self.logger = logging.log

    def initialize(self, session, logger=logging.log):

        self.logger = logger
        job_response = self.job_response
        file_response = self.file_response
        request_id = self.request_id

        file_state = file_response['file_state']
        reason = file_response.get('reason', None)

        new_state = None
        job_state = job_response.get('job_state', None)
        multi_hop = job_response.get('job_type') == FTS_JOB_TYPE.MULTI_HOP
        job_state_is_final = job_state in FINAL_FTS_JOB_STATES
        file_state_is_final = file_state in FINAL_FTS_FILE_STATES
        if file_state_is_final:
            if file_state == FTS_STATE.FINISHED:
                new_state = RequestState.DONE
            elif file_state == FTS_STATE.FAILED and job_state == FTS_STATE.FAILED or \
                    file_state == FTS_STATE.FAILED and not self._multi_sources:  # for multi-source transfers we must wait for the job to be in a final state
                if self._is_recoverable_fts_overwrite_error(self.request(session), reason, self._file_metadata):
                    new_state = RequestState.DONE
                else:
                    new_state = RequestState.FAILED
            elif job_state_is_final and file_state == FTS_STATE.CANCELED:
                new_state = RequestState.FAILED
            elif job_state_is_final and file_state == FTS_STATE.NOT_USED:
                if job_state == FTS_STATE.FINISHED:
                    # it is a multi-source transfer. This source wasn't used, but another one was successful
                    new_state = RequestState.DONE
                else:
                    # failed multi-source or multi-hop (you cannot have unused sources in a successful multi-hop)
                    new_state = RequestState.FAILED
                    if not reason and multi_hop:
                        reason = 'Unused hop in multi-hop'

        transfer_id = self._transfer_id
        if new_state:
            request = self.request(session)
            if not request:
                logger(logging.WARNING, '%s: no request with this id in the database. Skipping. external_id: %s (%s). new_state: %s', request_id, transfer_id, self.external_host, new_state)
                return
            if request['external_id'] == transfer_id and request['state'] != new_state:
                src_rse_name, src_rse_id = self._find_used_source_rse(session, logger)

                self._reason = reason
                self._src_rse = src_rse_name

                self.state = new_state
                self.external_id = transfer_id
                self.started_at = datetime.datetime.strptime(file_response['start_time'], '%Y-%m-%dT%H:%M:%S') if file_response['start_time'] else None
                self.transferred_at = datetime.datetime.strptime(file_response['finish_time'], '%Y-%m-%dT%H:%M:%S') if file_response['finish_time'] else None
                self.staging_started_at = datetime.datetime.strptime(file_response['staging_start'], '%Y-%m-%dT%H:%M:%S') if file_response['staging_start'] else None
                self.staging_finished_at = datetime.datetime.strptime(file_response['staging_finished'], '%Y-%m-%dT%H:%M:%S') if file_response['staging_finished'] else None
                self.source_rse_id = src_rse_id
                self.err_msg = get_transfer_error(self.state, reason)
                if self.err_msg and self._file_metadata.get('src_type') == "TAPE":
                    self.err_msg = '[TAPE SOURCE] ' + self.err_msg
                self.attributes = self._find_attribute_updates(
                    request=request,
                    new_state=new_state,
                    reason=reason,
                    overwrite_corrupted_files=config_get_bool('transfers', 'overwrite_corrupted_files', default=False, session=session),
                )
            elif request['external_id'] != transfer_id:
                logger(logging.WARNING, "Response %s with transfer id %s is different from the request transfer id %s, will not update" % (request_id, transfer_id, request['external_id']))
            else:
                logger(logging.DEBUG, "Request %s is already in %s state, will not update" % (request_id, new_state))


class FTS3Transfertool(Transfertool):
    """
    FTS3 implementation of a Rucio transfertool
    """

    external_name = 'fts3'
    required_rse_attrs = ('fts', )

    def __init__(self, external_host, oidc_account=None, vo=None, group_bulk=1, group_policy='rule', source_strategy=None,
                 max_time_in_queue=None, bring_online=43200, default_lifetime=172800, archive_timeout_override=None,
                 logger=logging.log):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        :param oidc_account:    optional oidc account to use for submission
        """
        super().__init__(external_host, logger)

        self.group_policy = group_policy
        self.group_bulk = group_bulk
        self.source_strategy = source_strategy
        self.max_time_in_queue = max_time_in_queue or {}
        self.bring_online = bring_online
        self.default_lifetime = default_lifetime
        self.archive_timeout_override = archive_timeout_override

        usercert = config_get('conveyor', 'usercert', False, None)
        if vo:
            usercert = config_get('vo_certs', vo, False, usercert)

        # token for OAuth 2.0 OIDC authorization scheme (working only with dCache + davs/https protocols as of Sep 2019)
        self.token = None
        if oidc_account:
            getadmintoken = False
            if ALLOW_USER_OIDC_TOKENS is False:
                getadmintoken = True
            self.logger(logging.DEBUG, 'Attempting to get a token for account %s. Admin token option set to %s' % (oidc_account, getadmintoken))
            # find the appropriate OIDC token and exchange it (for user accounts) if necessary
            token_dict = get_token_for_account_operation(oidc_account, req_audience=REQUEST_OIDC_AUDIENCE, req_scope=REQUEST_OIDC_SCOPE, admin=getadmintoken)
            if token_dict is not None:
                self.logger(logging.DEBUG, 'Access token has been granted.')
                if 'token' in token_dict:
                    self.logger(logging.DEBUG, 'Access token used as transfer token.')
                    self.token = token_dict['token']

        self.deterministic_id = config_get_bool('conveyor', 'use_deterministic_id', False, False)
        self.headers = {'Content-Type': 'application/json'}
        if self.external_host.startswith('https://'):
            if self.token:
                self.cert = None
                self.verify = False
                self.headers['Authorization'] = 'Bearer ' + self.token
            else:
                self.cert = (usercert, usercert)
                self.verify = False
        else:
            self.cert = None
            self.verify = True  # True is the default setting of a requests.* method

    @classmethod
    def _pick_fts_servers(cls, source_rse: "RseData", dest_rse: "RseData"):
        """
        Pick fts servers to use for submission between the two given rse
        """
        source_servers = source_rse.attributes.get('fts', None)
        dest_servers = dest_rse.attributes.get('fts', None)
        if source_servers is None or dest_servers is None:
            return None

        servers_to_use = dest_servers
        if source_rse.attributes.get('sign_url', None) == 'gcs':
            servers_to_use = source_servers

        return servers_to_use.split(',')

    @classmethod
    def can_perform_transfer(cls, source_rse: "RseData", dest_rse: "RseData"):
        if cls._pick_fts_servers(source_rse, dest_rse):
            return True
        return False

    @classmethod
    def submission_builder_for_path(cls, transfer_path, logger=logging.log):
        vo = None
        if config_get_bool('common', 'multi_vo', False, None):
            vo = transfer_path[-1].rws.scope.vo

        sub_path = []
        fts_hosts = []
        for hop in transfer_path:
            hosts = cls._pick_fts_servers(hop.src.rse, hop.dst.rse)
            if hosts:
                fts_hosts = hosts
                sub_path.append(hop)
            else:
                break

        if len(sub_path) < len(transfer_path):
            logger(logging.INFO, 'FTS3Transfertool can only submit {} hops from {}'.format(len(sub_path), [str(hop) for hop in transfer_path]))

        if sub_path:
            oidc_account = None
            if all(oidc_supported(t) for t in sub_path):
                logger(logging.DEBUG, 'OAuth2/OIDC available for transfer {}'.format([str(hop) for hop in sub_path]))
                oidc_account = transfer_path[-1].rws.account
            return sub_path, TransferToolBuilder(cls, external_host=fts_hosts[0], oidc_account=oidc_account, vo=vo)
        else:
            return [], None

    def group_into_submit_jobs(self, transfer_paths):
        jobs = bulk_group_transfers(
            transfer_paths,
            policy=self.group_policy,
            group_bulk=self.group_bulk,
            source_strategy=self.source_strategy,
            max_time_in_queue=self.max_time_in_queue,
            bring_online=self.bring_online,
            default_lifetime=self.default_lifetime,
            archive_timeout_override=self.archive_timeout_override,
            logger=self.logger,
        )
        return jobs

    def __file_from_transfer(self, transfer):
        rws = transfer.rws
        _verify_checksum, checksum_to_use = _checksum_validation_strategy(transfer, logger=self.logger)
        t_file = {
            'sources': [s[1] for s in transfer.legacy_sources],
            'destinations': [transfer.dest_url],
            'metadata': {
                'request_id': rws.request_id,
                'scope': rws.scope,
                'name': rws.name,
                'activity': rws.activity,
                'request_type': rws.request_type,
                'src_type': "TAPE" if transfer.src.rse.is_tape_or_staging_required() else 'DISK',
                'dst_type': "TAPE" if transfer.dst.rse.is_tape() else 'DISK',
                'src_rse': transfer.src.rse.name,
                'dst_rse': transfer.dst.rse.name,
                'src_rse_id': transfer.src.rse.id,
                'dest_rse_id': transfer.dst.rse.id,
                'filesize': rws.byte_count,
                'md5': rws.md5,
                'adler32': rws.adler32
            },
            'filesize': rws.byte_count,
            'checksum': checksum_to_use,
            'selection_strategy': self.source_strategy if self.source_strategy else _configured_source_strategy(transfer.rws.activity, logger=self.logger),
            'activity': rws.activity
        }
        return t_file

    def submit(self, transfers, job_params, timeout=None):
        """
        Submit transfers to FTS3 via JSON.

        :param files:        List of dictionaries describing the file transfers.
        :param job_params:   Dictionary containing key/value pairs, for all transfers.
        :param timeout:      Timeout in seconds.
        :returns:            FTS transfer identifier.
        """
        files = []
        for transfer in transfers:
            if isinstance(transfer, dict):
                # Compatibility with scripts form /tools which directly use transfertools and pass a dict to it instead of transfer definitions
                # TODO: ensure that those scripts are still used and get rid of this compatibility otherwise
                files.append(transfer)
                continue

            files.append(self.__file_from_transfer(transfer))

        # FTS3 expects 'davs' as the scheme identifier instead of https
        for transfer_file in files:
            if not transfer_file['sources'] or transfer_file['sources'] == []:
                raise Exception('No sources defined')

            # TODO: remove the following logic in rucio 1.31
            if REWRITE_HTTPS_TO_DAVS:
                new_src_urls = []
                new_dst_urls = []
                for url in transfer_file['sources']:
                    if url.startswith('https'):
                        new_src_urls.append(':'.join(['davs'] + url.split(':')[1:]))
                    else:
                        new_src_urls.append(url)
                for url in transfer_file['destinations']:
                    if url.startswith('https'):
                        new_dst_urls.append(':'.join(['davs'] + url.split(':')[1:]))
                    else:
                        new_dst_urls.append(url)

                transfer_file['sources'] = new_src_urls
                transfer_file['destinations'] = new_dst_urls

        transfer_id = None
        expected_transfer_id = None
        if self.deterministic_id:
            job_params = job_params.copy()
            job_params["id_generator"] = "deterministic"
            job_params["sid"] = files[0]['metadata']['request_id']
            expected_transfer_id = self.__get_deterministic_id(job_params["sid"])
            self.logger(logging.DEBUG, "Submit bulk transfers in deterministic mode, sid %s, expected transfer id: %s", job_params["sid"], expected_transfer_id)

        # bulk submission
        params_dict = {'files': files, 'params': job_params}
        params_str = json.dumps(params_dict, cls=APIEncoder)

        post_result = None
        stopwatch = Stopwatch()
        try:
            post_result = requests.post('%s/jobs' % self.external_host,
                                        verify=self.verify,
                                        cert=self.cert,
                                        data=params_str,
                                        headers=self.headers,
                                        timeout=timeout)
            labels = {'host': self.__extract_host(self.external_host)}
            METRICS.timer('submit_transfer.{host}').labels(**labels).observe(stopwatch.elapsed / (len(files) or 1))
        except ReadTimeout as error:
            raise TransferToolTimeout(error)
        except json.JSONDecodeError as error:
            raise TransferToolWrongAnswer(error)
        except Exception as error:
            self.logger(logging.WARNING, 'Could not submit transfer to %s - %s' % (self.external_host, str(error)))

        if post_result and post_result.status_code == 200:
            SUBMISSION_COUNTER.labels(state='success', host=self.__extract_host(self.external_host)).inc(len(files))
            transfer_id = str(post_result.json()['job_id'])
        elif post_result and post_result.status_code == 409:
            SUBMISSION_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc(len(files))
            raise DuplicateFileTransferSubmission()
        else:
            if expected_transfer_id:
                transfer_id = expected_transfer_id
                self.logger(logging.WARNING, "Failed to submit transfer to %s, will use expected transfer id %s, error: %s", self.external_host, transfer_id, post_result.text if post_result is not None else post_result)
            else:
                self.logger(logging.WARNING, "Failed to submit transfer to %s, error: %s", self.external_host, post_result.text if post_result is not None else post_result)
            SUBMISSION_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc(len(files))

        if not transfer_id:
            raise TransferToolWrongAnswer('No transfer id returned by %s' % self.external_host)
        METRICS.timer('submit_transfers_fts3').observe(stopwatch.elapsed / (len(transfers) or 1))
        return transfer_id

    def cancel(self, transfer_ids, timeout=None):
        """
        Cancel transfers that have been submitted to FTS3.

        :param transfer_ids: FTS transfer identifiers as list of strings.
        :param timeout:      Timeout in seconds.
        :returns:            True if cancellation was successful.
        """

        if len(transfer_ids) > 1:
            raise NotImplementedError('Bulk cancelling not implemented')
        transfer_id = transfer_ids[0]

        job = None

        job = requests.delete('%s/jobs/%s' % (self.external_host, transfer_id),
                              verify=self.verify,
                              cert=self.cert,
                              headers=self.headers,
                              timeout=timeout)

        if job and job.status_code == 200:
            CANCEL_COUNTER.labels(state='success', host=self.__extract_host(self.external_host)).inc()
            return job.json()

        CANCEL_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc()
        raise Exception('Could not cancel transfer: %s', job.content)

    def update_priority(self, transfer_id, priority, timeout=None):
        """
        Update the priority of a transfer that has been submitted to FTS via JSON.

        :param transfer_id: FTS transfer identifier as a string.
        :param priority:    FTS job priority as an integer from 1 to 5.
        :param timeout:     Timeout in seconds.
        :returns:           True if update was successful.
        """

        job = None
        params_dict = {"params": {"priority": priority}}
        params_str = json.dumps(params_dict, cls=APIEncoder)

        job = requests.post('%s/jobs/%s' % (self.external_host, transfer_id),
                            verify=self.verify,
                            data=params_str,
                            cert=self.cert,
                            headers=self.headers,
                            timeout=timeout)  # TODO set to 3 in conveyor

        if job and job.status_code == 200:
            UPDATE_PRIORITY_COUNTER.labels(state='success', host=self.__extract_host(self.external_host)).inc()
            return job.json()

        UPDATE_PRIORITY_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc()
        raise Exception('Could not update priority of transfer: %s', job.content)

    def query(self, transfer_ids, details=False, timeout=None):
        """
        Query the status of a transfer in FTS3 via JSON.

        :param transfer_ids: FTS transfer identifiers as list of strings.
        :param details:      Switch if detailed information should be listed.
        :param timeout:      Timeout in seconds.
        :returns:            Transfer status information as a list of dictionaries.
        """

        if len(transfer_ids) > 1:
            raise NotImplementedError('FTS3 transfertool query not bulk ready')

        transfer_id = transfer_ids[0]
        if details:
            return self.__query_details(transfer_id=transfer_id)

        job = None

        job = requests.get('%s/jobs/%s' % (self.external_host, transfer_id),
                           verify=self.verify,
                           cert=self.cert,
                           headers=self.headers,
                           timeout=timeout)  # TODO Set to 5 in conveyor
        if job and job.status_code == 200:
            QUERY_COUNTER.labels(state='success', host=self.__extract_host(self.external_host)).inc()
            return [job.json()]

        QUERY_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc()
        raise Exception('Could not retrieve transfer information: %s', job.content)

    # Public methods, not part of the common interface specification (FTS3 specific)

    def whoami(self):
        """
        Returns credential information from the FTS3 server.

        :returns: Credentials as stored by the FTS3 server as a dictionary.
        """

        get_result = None

        get_result = requests.get('%s/whoami' % self.external_host,
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers=self.headers)

        if get_result and get_result.status_code == 200:
            WHOAMI_COUNTER.labels(state='success', host=self.__extract_host(self.external_host)).inc()
            return get_result.json()

        WHOAMI_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc()
        raise Exception('Could not retrieve credentials: %s', get_result.content)

    def version(self):
        """
        Returns FTS3 server information.

        :returns: FTS3 server information as a dictionary.
        """

        get_result = None

        get_result = requests.get('%s/' % self.external_host,
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers=self.headers)

        if get_result and get_result.status_code == 200:
            VERSION_COUNTER.labels(state='success', host=self.__extract_host(self.external_host)).inc()
            return get_result.json()

        VERSION_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc()
        raise Exception('Could not retrieve version: %s', get_result.content)

    def bulk_query(self, requests_by_eid, timeout=None):
        """
        Query the status of a bulk of transfers in FTS3 via JSON.

        :param requests_by_eid: dictionary {external_id1: {request_id1: request1, ...}, ...} of request to be queried
        :returns: Transfer status information as a dictionary.
        """

        responses = {}
        fts_session = requests.Session()
        xfer_ids = ','.join(requests_by_eid)
        jobs = fts_session.get('%s/jobs/%s?files=file_state,dest_surl,finish_time,start_time,staging_start,staging_finished,reason,source_surl,file_metadata' % (self.external_host, xfer_ids),
                               verify=self.verify,
                               cert=self.cert,
                               headers=self.headers,
                               timeout=timeout)

        if jobs is None:
            BULK_QUERY_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc()
            for transfer_id in requests_by_eid:
                responses[transfer_id] = Exception('Transfer information returns None: %s' % jobs)
        elif jobs.status_code in (200, 207, 404):
            try:
                BULK_QUERY_COUNTER.labels(state='success', host=self.__extract_host(self.external_host)).inc()
                jobs_response = jobs.json()
                responses = self.__bulk_query_responses(jobs_response, requests_by_eid)
            except ReadTimeout as error:
                raise TransferToolTimeout(error)
            except json.JSONDecodeError as error:
                raise TransferToolWrongAnswer(error)
            except Exception as error:
                raise Exception("Failed to parse the job response: %s, error: %s" % (str(jobs), str(error)))
        else:
            BULK_QUERY_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc()
            for transfer_id in requests_by_eid:
                responses[transfer_id] = Exception('Could not retrieve transfer information: %s', jobs.content)

        return responses

    def list_se_status(self):
        """
        Get the list of banned Storage Elements.

        :returns: Detailed dictionnary of banned Storage Elements.
        """

        try:
            result = requests.get('%s/ban/se' % self.external_host,
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers=self.headers,
                                  timeout=None)
        except Exception as error:
            raise Exception('Could not retrieve transfer information: %s', error)
        if result and result.status_code == 200:
            return result.json()
        raise Exception('Could not retrieve transfer information: %s', result.content)

    def get_se_config(self, storage_element):
        """
        Get the Json response for the configuration of a storage element.
        :returns: a Json result for the configuration of a storage element.
        :param storage_element: the storage element you want the configuration for.
        """

        try:
            result = requests.get('%s/config/se' % (self.external_host),
                                  verify=self.verify,
                                  cert=self.cert,
                                  headers=self.headers,
                                  timeout=None)
        except Exception:
            self.logger(logging.WARNING, 'Could not get config of %s on %s - %s', storage_element, self.external_host, str(traceback.format_exc()))
        if result and result.status_code == 200:
            C = result.json()
            config_se = C[storage_element]
            return config_se
        raise Exception('Could not get the configuration of %s , status code returned : %s', (storage_element, result.status_code if result else None))

    def set_se_config(self, storage_element, inbound_max_active=None, outbound_max_active=None, inbound_max_throughput=None, outbound_max_throughput=None, staging=None):
        """
        Set the configuration for a storage element. Used for alleviating transfer failures due to timeout.

        :param storage_element: The storage element to be configured
        :param inbound_max_active: the integer to set the inbound_max_active for the SE.
        :param outbound_max_active: the integer to set the outbound_max_active for the SE.
        :param inbound_max_throughput: the float to set the inbound_max_throughput for the SE.
        :param outbound_max_throughput: the float to set the outbound_max_throughput for the SE.
        :param staging: the integer to set the staging for the operation of a SE.
        :returns: JSON post response in case of success, otherwise raise Exception.
        """

        params_dict = {storage_element: {'operations': {}, 'se_info': {}}}
        if staging is not None:
            try:
                policy = config_get('policy', 'permission')
            except Exception:
                self.logger(logging.WARNING, 'Could not get policy from config')
            params_dict[storage_element]['operations'] = {policy: {'staging': staging}}
        # A lot of try-excepts to avoid dictionary overwrite's,
        # see https://stackoverflow.com/questions/27118687/updating-nested-dictionaries-when-data-has-existing-key/27118776
        if inbound_max_active is not None:
            try:
                params_dict[storage_element]['se_info']['inbound_max_active'] = inbound_max_active
            except KeyError:
                params_dict[storage_element]['se_info'] = {'inbound_max_active': inbound_max_active}
        if outbound_max_active is not None:
            try:
                params_dict[storage_element]['se_info']['outbound_max_active'] = outbound_max_active
            except KeyError:
                params_dict[storage_element]['se_info'] = {'outbound_max_active': outbound_max_active}
        if inbound_max_throughput is not None:
            try:
                params_dict[storage_element]['se_info']['inbound_max_throughput'] = inbound_max_throughput
            except KeyError:
                params_dict[storage_element]['se_info'] = {'inbound_max_throughput': inbound_max_throughput}
        if outbound_max_throughput is not None:
            try:
                params_dict[storage_element]['se_info']['outbound_max_throughput'] = outbound_max_throughput
            except KeyError:
                params_dict[storage_element]['se_info'] = {'outbound_max_throughput': outbound_max_throughput}

        params_str = json.dumps(params_dict, cls=APIEncoder)

        try:
            result = requests.post('%s/config/se' % (self.external_host),
                                   verify=self.verify,
                                   cert=self.cert,
                                   data=params_str,
                                   headers=self.headers,
                                   timeout=None)

        except Exception:
            self.logger(logging.WARNING, 'Could not set the config of %s on %s - %s', storage_element, self.external_host, str(traceback.format_exc()))
        if result and result.status_code == 200:
            configSe = result.json()
            return configSe
        raise Exception('Could not set the configuration of %s , status code returned : %s', (storage_element, result.status_code if result else None))

    def set_se_status(self, storage_element, message, ban=True, timeout=None):
        """
        Ban a Storage Element. Used when a site is in downtime.
        One can use a timeout in seconds. In that case the jobs will wait before being cancel.
        If no timeout is specified, the jobs are canceled immediately

        :param storage_element: The Storage Element that will be banned.
        :param message: The reason of the ban.
        :param ban: Boolean. If set to True, ban the SE, if set to False unban the SE.
        :param timeout: if None, send to FTS status 'cancel' else 'waiting' + the corresponding timeout.

        :returns: 0 in case of success, otherwise raise Exception
        """

        params_dict = {'storage': storage_element, 'message': message}
        status = 'CANCEL'
        if timeout:
            params_dict['timeout'] = timeout
            status = 'WAIT'
        params_dict['status'] = status
        params_str = json.dumps(params_dict, cls=APIEncoder)

        result = None
        if ban:
            try:
                result = requests.post('%s/ban/se' % self.external_host,
                                       verify=self.verify,
                                       cert=self.cert,
                                       data=params_str,
                                       headers=self.headers,
                                       timeout=None)
            except Exception:
                self.logger(logging.WARNING, 'Could not ban %s on %s - %s', storage_element, self.external_host, str(traceback.format_exc()))
            if result and result.status_code == 200:
                return 0
            raise Exception('Could not ban the storage %s , status code returned : %s', (storage_element, result.status_code if result else None))
        else:

            try:
                result = requests.delete('%s/ban/se?storage=%s' % (self.external_host, storage_element),
                                         verify=self.verify,
                                         cert=self.cert,
                                         data=params_str,
                                         headers=self.headers,
                                         timeout=None)
            except Exception:
                self.logger(logging.WARNING, 'Could not unban %s on %s - %s', storage_element, self.external_host, str(traceback.format_exc()))
            if result and result.status_code == 204:
                return 0
            raise Exception('Could not unban the storage %s , status code returned : %s', (storage_element, result.status_code if result else None))

    # Private methods unique to the FTS3 Transfertool

    @staticmethod
    def __extract_host(external_host):
        # graphite does not like the dots in the FQDN
        return urlparse(external_host).hostname.replace('.', '_')

    def __get_transfer_baseid_voname(self):
        """
        Get transfer VO name from the external host.

        :returns base id as a string and VO name as a string.
        """
        result = (None, None)
        try:
            key = 'voname:%s' % self.external_host
            result = REGION_SHORT.get(key)
            if isinstance(result, NoValue):
                self.logger(logging.DEBUG, "Refresh transfer baseid and voname for %s", self.external_host)

                get_result = None
                try:
                    get_result = requests.get('%s/whoami' % self.external_host,
                                              verify=self.verify,
                                              cert=self.cert,
                                              headers=self.headers,
                                              timeout=5)
                except ReadTimeout as error:
                    raise TransferToolTimeout(error)
                except json.JSONDecodeError as error:
                    raise TransferToolWrongAnswer(error)
                except Exception as error:
                    self.logger(logging.WARNING, 'Could not get baseid and voname from %s - %s' % (self.external_host, str(error)))

                if get_result and get_result.status_code == 200:
                    baseid = str(get_result.json()['base_id'])
                    voname = str(get_result.json()['vos'][0])
                    result = (baseid, voname)

                    REGION_SHORT.set(key, result)

                    self.logger(logging.DEBUG, "Get baseid %s and voname %s from %s", baseid, voname, self.external_host)
                else:
                    self.logger(logging.WARNING, "Failed to get baseid and voname from %s, error: %s", self.external_host, get_result.text if get_result is not None else get_result)
                    result = (None, None)
        except Exception as error:
            self.logger(logging.WARNING, "Failed to get baseid and voname from %s: %s" % (self.external_host, str(error)))
            result = (None, None)
        return result

    def __get_deterministic_id(self, sid):
        """
        Get deterministic FTS job id.

        :param sid: FTS seed id.
        :returns: FTS transfer identifier.
        """
        baseid, voname = self.__get_transfer_baseid_voname()
        if baseid is None or voname is None:
            return None
        root = uuid.UUID(baseid)
        atlas = uuid.uuid5(root, voname)
        jobid = uuid.uuid5(atlas, sid)
        return str(jobid)

    def __bulk_query_responses(self, jobs_response, requests_by_eid):
        if not isinstance(jobs_response, list):
            jobs_response = [jobs_response]

        responses = {}
        for job_response in jobs_response:
            transfer_id = job_response['job_id']
            if job_response['http_status'] == '200 Ok':
                files_response = job_response['files']
                multi_sources = job_response['job_metadata'].get('multi_sources', False)
                if multi_sources and job_response['job_state'] not in [FTS_STATE.FAILED,
                                                                       FTS_STATE.FINISHEDDIRTY,
                                                                       FTS_STATE.CANCELED,
                                                                       FTS_STATE.FINISHED]:
                    # multipe source replicas jobs is still running. should wait
                    responses[transfer_id] = {}
                    continue

                resps = {}
                for file_resp in files_response:
                    file_state = file_resp['file_state']
                    # for multiple source replicas jobs, the file_metadata(request_id) will be the same.
                    # The next used file will overwrite the current used one. Only the last used file will return.
                    if multi_sources and file_state == FTS_STATE.NOT_USED:
                        continue

                    request_id = file_resp['file_metadata']['request_id']
                    request = requests_by_eid.get(transfer_id, {}).get(request_id)
                    if request is not None:
                        resps[request_id] = FTS3ApiTransferStatusReport(self.external_host, request_id=request_id, request=request,
                                                                        job_response=job_response, file_response=file_resp)

                    # multiple source replicas jobs and we found the successful one, it's the final state.
                    if multi_sources and file_state == FTS_STATE.FINISHED:
                        break
                responses[transfer_id] = resps
            elif job_response['http_status'] == '404 Not Found':
                # Lost transfer
                responses[transfer_id] = None
            else:
                responses[transfer_id] = Exception('Could not retrieve transfer information(http_status: %s, http_message: %s)' % (job_response['http_status'],
                                                                                                                                   job_response['http_message'] if 'http_message' in job_response else None))
        return responses

    def __query_details(self, transfer_id):
        """
        Query the detailed status of a transfer in FTS3 via JSON.

        :param transfer_id: FTS transfer identifier as a string.
        :returns: Detailed transfer status information as a dictionary.
        """

        files = None

        files = requests.get('%s/jobs/%s/files' % (self.external_host, transfer_id),
                             verify=self.verify,
                             cert=self.cert,
                             headers=self.headers,
                             timeout=5)
        if files and (files.status_code == 200 or files.status_code == 207):
            QUERY_DETAILS_COUNTER.labels(state='success', host=self.__extract_host(self.external_host)).inc()
            return files.json()

        QUERY_DETAILS_COUNTER.labels(state='failure', host=self.__extract_host(self.external_host)).inc()
        return
