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

from rucio.core.rse import update_rse, get_rse


class TestQoS:

    def test_update_and_remove_rse_qos_class(self, rse_factory):
        """ QoS (CORE): Update and remove QoS class for RSE """
        rse_name, rse_id = rse_factory.make_mock_rse()

        update_rse(rse_id, {'qos_class': 'fast_and_expensive'})
        rse = get_rse(rse_id)
        assert rse['qos_class'] == 'fast_and_expensive'

        update_rse(rse_id, {'qos_class': 'slow_but_cheap'})
        rse = get_rse(rse_id)
        assert rse['qos_class'] == 'slow_but_cheap'

        update_rse(rse_id, {'qos_class': None})
        rse = get_rse(rse_id)
        assert rse['qos_class'] is None

    def test_update_and_remove_rse_qos_class_client(self, rse_client, rse_factory):
        """ QoS (CLIENT): Update and remove QoS class for RSE """
        rse_name, rse_id = rse_factory.make_mock_rse()

        rse_client.update_rse(rse_name, {'qos_class': 'fast_and_expensive'})
        rse = rse_client.get_rse(rse_name)
        assert rse['qos_class'] == 'fast_and_expensive'

        rse_client.update_rse(rse_name, {'qos_class': 'slow_but_cheap'})
        rse = rse_client.get_rse(rse_name)
        assert rse['qos_class'] == 'slow_but_cheap'

        rse_client.update_rse(rse_name, {'qos_class': None})
        rse = rse_client.get_rse(rse_name)
        assert rse['qos_class'] is None

    def test_qos_policies(self, rse_client, rse_factory):
        """ QoS (CLIENT): Add QoS policy for RSE """
        rse_name, rse_id = rse_factory.make_mock_rse()

        rse_client.add_qos_policy(rse_name, 'FOO')
        policies = rse_client.list_qos_policies(rse_name)
        assert policies == ['FOO']

        rse_client.add_qos_policy(rse_name, 'BAR')
        policies = sorted(rse_client.list_qos_policies(rse_name))
        assert policies == ['BAR', 'FOO']

        rse_client.delete_qos_policy(rse_name, 'BAR')
        policies = rse_client.list_qos_policies(rse_name)
        assert policies == ['FOO']

        rse_client.delete_qos_policy(rse_name, 'FOO')
        policies = rse_client.list_qos_policies(rse_name)
        assert policies == []
