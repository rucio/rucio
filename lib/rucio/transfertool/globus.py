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

import logging

from rucio.common.utils import chunks
from rucio.transfertool.transfertool import Transfertool, TransferToolBuilder, TransferStatusReport
from rucio.db.sqla.constants import RequestState
from .globus_library import bulk_submit_xfer, submit_xfer, bulk_check_xfers


def bulk_group_transfers(transfer_paths, policy='single', group_bulk=200):
    """
    Group transfers in bulk based on certain criterias

    :param transfer_paths:  List of (potentially multihop) transfer paths to group. Each path is a list of single-hop transfers.
    :param policy:          Policy to use to group.
    :param group_bulk:      Bulk sizes.
    :return:                List of transfer groups
    """
    if policy == 'single':
        group_bulk = 1

    grouped_jobs = []
    for chunk in chunks(transfer_paths, group_bulk):
        # Globus doesn't support multihop. Get the first hop only.
        transfers = [transfer_path[0] for transfer_path in chunk]

        grouped_jobs.append({
            'transfers': transfers,
            # Job params are not used by globus transfertool, but are needed for further common fts/globus code
            'job_params': {}
        })

    return grouped_jobs


class GlobusTransferStatusReport(TransferStatusReport):

    supported_db_fields = [
        'state',
        'external_id',
    ]

    def __init__(self, request_id, external_id, globus_response):
        super().__init__(request_id)

        if globus_response == 'FAILED':
            new_state = RequestState.FAILED
        elif globus_response == 'SUCCEEDED':
            new_state = RequestState.DONE
        else:
            new_state = RequestState.SUBMITTED

        self.state = new_state
        self.external_id = None
        if new_state in [RequestState.FAILED, RequestState.DONE]:
            self.external_id = external_id

    def initialize(self, session, logger=logging.log):
        pass

    def get_monitor_msg_fields(self, session, logger=logging.log):
        return {'protocol': 'globus'}


class GlobusTransferTool(Transfertool):
    """
    Globus implementation of Transfertool abstract base class
    """

    external_name = 'globus'
    required_rse_attrs = ('globus_endpoint_id', )

    def __init__(self, external_host, logger=logging.log, group_bulk=200, group_policy='single'):
        """
        Initializes the transfertool

        :param external_host:   The external host where the transfertool API is running
        """
        if not external_host:
            external_host = 'Globus Online Transfertool'
        super().__init__(external_host, logger)
        self.group_bulk = group_bulk
        self.group_policy = group_policy
        # TODO: initialize vars from config file here

    @classmethod
    def submission_builder_for_path(cls, transfer_path, logger=logging.log):
        hop = transfer_path[0]
        if not cls.can_perform_transfer(hop.src.rse, hop.dst.rse):
            logger(logging.WARNING, "Source or destination globus_endpoint_id not set. Skipping {}".format(hop))
            return [], None

        return [hop], TransferToolBuilder(cls, external_host='Globus Online Transfertool')

    def group_into_submit_jobs(self, transfer_paths):
        jobs = bulk_group_transfers(transfer_paths, policy=self.group_policy, group_bulk=self.group_bulk)
        return jobs

    def submit_one(self, files, timeout=None):
        """
        Submit transfers to globus API

        :param files:        List of dictionaries describing the file transfers.
        :param job_params:   Dictionary containing key/value pairs, for all transfers.
        :param timeout:      Timeout in seconds.
        :returns:            Globus transfer identifier.
        """

        source_path = files[0]['sources'][0]
        self.logger(logging.INFO, 'source_path: %s' % source_path)

        source_endpoint_id = files[0]['metadata']['source_globus_endpoint_id']

        # TODO: use prefix from rse_protocol to properly construct destination url
        # parse and assemble dest_path for Globus endpoint
        dest_path = files[0]['destinations'][0]
        self.logger(logging.INFO, 'dest_path: %s' % dest_path)

        # TODO: rucio.common.utils.construct_url logic adds unnecessary '/other' into file path
        # s = dest_path.split('/') # s.remove('other') # dest_path = '/'.join(s)

        destination_endpoint_id = files[0]['metadata']['dest_globus_endpoint_id']
        job_label = files[0]['metadata']['request_id']

        task_id = submit_xfer(source_endpoint_id, destination_endpoint_id, source_path, dest_path, job_label, recursive=False, logger=self.logger)

        return task_id

    def submit(self, transfers, job_params, timeout=None):
        """
        Submit a bulk transfer to globus API

        :param transfers:    List of dictionaries describing the file transfers.
        :param job_params:   Not used by Globus Transfsertool
        :param timeout:      Timeout in seconds.
        :returns:            Globus transfer identifier.
        """

        # TODO: support passing a recursive parameter to Globus
        submitjob = [
            {
                # Some dict elements are not needed by globus transfertool, but are accessed by further common fts/globus code
                'sources': [s[1] for s in transfer.legacy_sources],
                'destinations': [transfer.dest_url],
                'metadata': {
                    'src_rse': transfer.src.rse.name,
                    'dst_rse': transfer.dst.rse.name,
                    'scope': str(transfer.rws.scope),
                    'name': transfer.rws.name,
                    'source_globus_endpoint_id': transfer.src.rse.attributes['globus_endpoint_id'],
                    'dest_globus_endpoint_id': transfer.dst.rse.attributes['globus_endpoint_id'],
                    'filesize': transfer.rws.byte_count,
                },
            }
            for transfer in transfers
        ]
        self.logger(logging.DEBUG, '... Starting globus xfer ...')
        self.logger(logging.DEBUG, 'job_files: %s' % submitjob)
        task_id = bulk_submit_xfer(submitjob, recursive=False, logger=self.logger)

        return task_id

    def bulk_query(self, requests_by_eid, timeout=None):
        """
        Query the status of a bulk of transfers in globus API

        :param requests_by_eid: dictionary {external_id1: {request_id1: request1, ...}, ...}
        :returns: Transfer status information as a dictionary.
        """

        job_responses = bulk_check_xfers(requests_by_eid, logger=self.logger)

        response = {}
        for transfer_id, requests in requests_by_eid.items():
            for request_id in requests:
                response.setdefault(transfer_id, {})[request_id] = GlobusTransferStatusReport(request_id, transfer_id, job_responses[transfer_id])
        return response

    def bulk_update(self, resps, request_ids):
        """
        bulk update request_state for globus transfers

        :param resps: dictionary containing task IDs and current status
        # TODO: do we need request IDs?
        :param request_ids original list of rucio request IDs

        counter = 0
        for task_id in resps:
            requests = get_requests_by_transfer(external_host=None, transfer_id=task_id, session=None)
            logging.debug('requests: %s' % requests)
            for request_id in requests:
                transfer_core.update_transfer_state(external_host=None, transfer_id=request_id, state=resps[task_id][file_state])
                counter += 1

        return counter
        """
        pass

    def cancel(self):
        pass

    def query(self, transfer_ids, details=False, timeout=None):
        """
        Query the status of a transfer in Globus Online.

        :param transfer_ids: transfer identifiers as list of strings.
        :param details:      Switch if detailed information should be listed.
        :param timeout:      Timeout in seconds.
        :returns:            Transfer status information as a list of dictionaries.
        """
        pass

    def update_priority(self):
        pass
