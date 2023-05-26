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

class TestBoolean:

    def test_booleanstring_account_attribute(self, random_account, account_client):
        account = random_account.external
        account_client.add_account_attribute(account, 'teststringtrue', 'true')
        account_client.add_account_attribute(account, 'testinttrue', '1')

        account_client.add_account_attribute(account, 'teststringfalse', 'false')
        account_client.add_account_attribute(account, 'testintfalse', '0')

        result = {}
        for account in account_client.list_account_attributes(account):
            for res in account:
                result[res['key']] = res['value']

        assert result['teststringtrue'] is True
        assert result['testinttrue'] == '1'
        assert result['teststringfalse'] is False
        assert result['testintfalse'] == '0'

    def test_booleanstring_rse_attribute(self, rse_client, rse_factory):
        rse, _ = rse_factory.make_mock_rse()
        rse_client.add_rse_attribute(rse, 'teststringtrue', 'true')
        rse_client.add_rse_attribute(rse, 'testinttrue', '1')

        rse_client.add_rse_attribute(rse, 'teststringfalse', 'false')
        rse_client.add_rse_attribute(rse, 'testintfalse', '0')

        result = rse_client.list_rse_attributes(rse)

        assert result['teststringtrue'] is True
        assert result['testinttrue'] == '1'
        assert result['teststringfalse'] is False
        assert result['testintfalse'] == '0'
