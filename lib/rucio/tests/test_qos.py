# Copyright 2020 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020
#
# PY3K COMPATIBLE

from rucio.client.rseclient import RSEClient
from rucio.common.config import config_get, config_get_bool
from rucio.core.rse import update_rse, get_rse
from rucio.tests.common import rse_name_generator

from nose.tools import assert_equal


class TestQoS(object):

    @classmethod
    def setupClass(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

        self.rse_client = RSEClient()
        self.tmp_rse_name = rse_name_generator()
        self.rse_client.add_rse(self.tmp_rse_name, vo=self.vo)
        self.tmp_rse = self.rse_client.get_rse(self.tmp_rse_name)['id']

    @classmethod
    def teardownClass(self):
        self.rse_client.delete_rse(self.tmp_rse_name)

    def test_update_and_remove_rse_qos_class(self):
        """ QoS (CORE): Update and remove QoS class for RSE """

        update_rse(self.tmp_rse, {'qos_class': 'fast_and_expensive'})
        rse = get_rse(self.tmp_rse)
        assert_equal(rse['qos_class'], 'fast_and_expensive')

        update_rse(self.tmp_rse, {'qos_class': 'slow_but_cheap'})
        rse = get_rse(self.tmp_rse)
        assert_equal(rse['qos_class'], 'slow_but_cheap')

        update_rse(self.tmp_rse, {'qos_class': None})
        rse = get_rse(self.tmp_rse)
        assert_equal(rse['qos_class'], None)

    def test_update_and_remove_rse_qos_class_client(self):
        """ QoS (CLIENT): Update and remove QoS class for RSE """

        self.rse_client.update_rse(self.tmp_rse_name, {'qos_class': 'fast_and_expensive'})
        rse = self.rse_client.get_rse(self.tmp_rse_name)
        assert_equal(rse['qos_class'], 'fast_and_expensive')

        self.rse_client.update_rse(self.tmp_rse_name, {'qos_class': 'slow_but_cheap'})
        rse = self.rse_client.get_rse(self.tmp_rse_name)
        assert_equal(rse['qos_class'], 'slow_but_cheap')

        self.rse_client.update_rse(self.tmp_rse_name, {'qos_class': None})
        rse = self.rse_client.get_rse(self.tmp_rse_name)
        assert_equal(rse['qos_class'], None)

    def test_qos_policies(self):
        """ QoS (CLIENT): Add QoS policy for RSE """

        self.rse_client.add_qos_policy(self.tmp_rse_name, 'FOO')
        policies = self.rse_client.list_qos_policies(self.tmp_rse_name)
        assert_equal(policies, ['FOO'])

        self.rse_client.add_qos_policy(self.tmp_rse_name, 'BAR')
        policies = sorted(self.rse_client.list_qos_policies(self.tmp_rse_name))
        assert_equal(policies, ['BAR', 'FOO'])

        self.rse_client.delete_qos_policy(self.tmp_rse_name, 'BAR')
        policies = self.rse_client.list_qos_policies(self.tmp_rse_name)
        assert_equal(policies, ['FOO'])

        self.rse_client.delete_qos_policy(self.tmp_rse_name, 'FOO')
        policies = self.rse_client.list_qos_policies(self.tmp_rse_name)
        assert_equal(policies, [])
