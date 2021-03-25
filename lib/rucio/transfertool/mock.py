# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Nick Smith <nick.smith@cern.ch>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from rucio.transfertool.transfertool import Transfertool
import uuid


class MockTransfertool(Transfertool):
    """
    Mock implementation of a Rucio transfertool

    This is not actually used anywhere at the moment
    """

    def __init__(self, external_host, token=None):
        super(MockTransfertool, self).__init__(external_host)

    def submit(self, files, job_params, timeout=None):
        return str(uuid.uuid1())

    def query(self, transfer_ids, details=False, timeout=None):
        return [{'status': 'ok'}]

    def cancel(self, transfer_ids, timeout=None):
        return True

    def update_priority(self, transfer_id, priority, timeout=None):
        return True
