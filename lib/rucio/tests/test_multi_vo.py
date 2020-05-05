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

from nose.tools import assert_equal, assert_in, assert_raises, assert_true

from rucio.api import vo as vo_api
from rucio.api.identity import list_accounts_for_identity
from rucio.common.config import config_get_bool
from rucio.client.client import Client
from rucio.client.replicaclient import ReplicaClient
from rucio.client.uploadclient import UploadClient
from rucio.common.exception import AccessDenied, Duplicate
from rucio.common.utils import generate_uuid


class TestVOCoreAPI(object):

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': 'tst'}
            self.new_vo = generate_uuid()[:3]
        else:
            self.vo = {}

    def test_add_vo(self):
        """ MULTI VO (CORE): Test creation of VOs """
        with assert_raises(AccessDenied):
            vo_api.add_vo(self.new_vo, 'root', 'Add new VO with root', 'rucio@email.com', **self.vo)
        vo_api.add_vo(self.new_vo, 'super_root', 'Add new VO with super_root', 'rucio@email.com', 'def')
        with assert_raises(Duplicate):
            vo_api.add_vo(self.new_vo, 'super_root', 'Add existing VO', 'rucio@email.com', 'def')
        vo_list = [v['vo'] for v in vo_api.list_vos('super_root', 'def')]
        assert_in(self.new_vo, vo_list)

    def test_recover_root_identity(self):
        """ MULTI VO (CORE): Test adding a new identity for root using super_root """
        vo_api.add_vo(self.new_vo, 'super_root', 'Add new VO with super_root', 'rucio@email.com', 'def')
        with assert_raises(AccessDenied):
            vo_api.recover_vo_root_identity(root_vo=self.new_vo, identity_key='recovered@%s' % self.new_vo, id_type='userpass',
                                            email='rucio@email.com', issuer='root', password='password', vo=self.new_vo)
        vo_api.recover_vo_root_identity(root_vo=self.new_vo, identity_key='recovered@%s' % self.new_vo, id_type='userpass',
                                        email='rucio@email.com', issuer='super_root', password='password', vo='def')
        assert_in('root', list_accounts_for_identity(identity_key='recovered@%s' % self.new_vo, id_type='userpass'))

    def test_update_vo(self):
        """ MULTI VO (CORE): Test updating VOs """
        vo_api.add_vo(self.new_vo, 'super_root', 'Add new VO with super_root', 'rucio@email.com', 'def')
        parameters = {'vo': self.new_vo, 'description': 'Updated description', 'email': 'updated@email.com'}
        with assert_raises(AccessDenied):
            vo_api.update_vo(self.new_vo, parameters, 'root', **self.vo)
        vo_api.update_vo(self.new_vo, parameters, 'super_root', 'def')
        vo_update_success = False
        for v in vo_api.list_vos('super_root', 'def'):
            if v['vo'] == parameters['vo']:
                assert_equal(parameters['email'], v['email'])
                assert_equal(parameters['description'], v['description'])
                vo_update_success = True
        assert_true(vo_update_success)


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
