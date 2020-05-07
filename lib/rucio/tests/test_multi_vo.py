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

from nose.tools import assert_equal, assert_is_not_none, assert_raises

from rucio.api.rule import delete_replication_rule, get_replication_rule
from rucio.api import vo as vo_api
from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.did import add_did
from rucio.core.rule import add_rule
from rucio.client.client import Client
from rucio.client.replicaclient import ReplicaClient
from rucio.client.uploadclient import UploadClient
from rucio.common.exception import AccessDenied
from rucio.common.utils import generate_uuid
from rucio.db.sqla.constants import DIDType


class TestVOCoreAPI(object):

    def setup(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': 'tst'}
            self.new_vo = generate_uuid()[:3]
        else:
            self.vo = {}

    def test_access_rule(self):
        """ MULTI VO (CORE): Test accessing rules from a different VO """
        scope = InternalScope('mock', **self.vo)
        dataset = 'dataset_' + str(generate_uuid())
        account = InternalAccount('root', **self.vo)
        add_did(scope, dataset, DIDType.from_sym('DATASET'), account)
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=account, copies=1, rse_expression='MOCK', grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        vo_api.add_vo(self.new_vo, 'super_root', 'Add new VO with super_root', 'rucio@email.com', 'def')
        with assert_raises(AccessDenied):
            delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', vo=self.new_vo)
        delete_replication_rule(rule_id=rule_id, purge_replicas=False, issuer='root', **self.vo)
        rule_dict = get_replication_rule(rule_id=rule_id, issuer='root', **self.vo)
        assert_is_not_none(rule_dict['expires_at'])


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
