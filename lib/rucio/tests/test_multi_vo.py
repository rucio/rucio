# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

from nose.tools import assert_equal

from rucio.common.config import config_get_bool
from rucio.client.client import Client
from rucio.client.replicaclient import ReplicaClient
from rucio.client.uploadclient import UploadClient


class TestMultiVoClients(object):

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': 'tst'}
        else:
            self.vo = {}

    def test_get_vo_from_config(self):
        """ MULTI VO (CLIENT): Get vo from config file when starting clients """
        # Start clients with vo explicitly set to None
        replica_client = ReplicaClient(vo=None)
        client = Client(vo=None)
        upload_client = UploadClient(_client=client)

        # Check the vo has been got from the config file
        assert_equal(replica_client.vo, self.vo['vo'])
        assert_equal(upload_client.client.vo, self.vo['vo'])
