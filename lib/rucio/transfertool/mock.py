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

import itertools
import logging

from rucio.transfertool.transfertool import Transfertool, TransferToolBuilder
import uuid


class MockTransfertool(Transfertool):
    """
    Mock implementation of a Rucio transfertool

    This is not actually used anywhere at the moment
    """

    external_name = 'mock'
    required_rse_attrs = ()

    def __init__(self, external_host, logger=logging.log):
        super(MockTransfertool, self).__init__(external_host, logger)

    @classmethod
    def submission_builder_for_path(cls, transfer_path, logger=logging.log):
        return transfer_path, TransferToolBuilder(cls, external_host='Mock Transfertool')

    def group_into_submit_jobs(self, transfers):
        return [{'transfers': list(itertools.chain.from_iterable(transfers)), 'job_params': {}}]

    def submit(self, files, job_params, timeout=None):
        return str(uuid.uuid1())

    def query(self, transfer_ids, details=False, timeout=None):
        return [{'status': 'ok'}]

    def cancel(self, transfer_ids, timeout=None):
        return True

    def update_priority(self, transfer_id, priority, timeout=None):
        return True
