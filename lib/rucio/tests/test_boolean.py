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

import unittest

from rucio.client.accountclient import AccountClient
from rucio.client.rseclient import RSEClient
from rucio.common.utils import generate_uuid
from rucio.tests.common import rse_name_generator


class TestBoolean(unittest.TestCase):

    def setUp(self):
        self.account_client = AccountClient()
        self.rse_client = RSEClient()

        self.account = generate_uuid()[:10]
        self.rse = rse_name_generator()

        self.account_client.add_account(self.account, 'SERVICE', 'ddmlab@cern.ch')
        self.rse_client.add_rse(self.rse)

    def tearDown(self):
        self.account_client.delete_account(self.account)
        self.rse_client.delete_rse(self.rse)

    def test_booleanstring_account_attribute(self):
        self.account_client.add_account_attribute(self.account, 'teststringtrue', 'true')
        self.account_client.add_account_attribute(self.account, 'testinttrue', '1')

        self.account_client.add_account_attribute(self.account, 'teststringfalse', 'false')
        self.account_client.add_account_attribute(self.account, 'testintfalse', '0')

        result = {}
        for account in self.account_client.list_account_attributes(self.account):
            for res in account:
                result[res['key']] = res['value']

        assert result['teststringtrue'] is True
        assert result['testinttrue'] == '1'
        assert result['teststringfalse'] is False
        assert result['testintfalse'] == '0'

    def test_booleanstring_rse_attribute(self):
        self.rse_client.add_rse_attribute(self.rse, 'teststringtrue', 'true')
        self.rse_client.add_rse_attribute(self.rse, 'testinttrue', '1')

        self.rse_client.add_rse_attribute(self.rse, 'teststringfalse', 'false')
        self.rse_client.add_rse_attribute(self.rse, 'testintfalse', '0')

        result = self.rse_client.list_rse_attributes(self.rse)

        assert result['teststringtrue'] is True
        assert result['testinttrue'] == '1'
        assert result['teststringfalse'] is False
        assert result['testintfalse'] == '0'
