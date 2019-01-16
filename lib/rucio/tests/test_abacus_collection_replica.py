# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from nose.tools import assert_equal

import os

from rucio.db.sqla.constants import DIDType
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.ruleclient import RuleClient
from rucio.client.uploadclient import UploadClient
from rucio.common.utils import generate_uuid
from rucio.core.replica import delete_replicas
from rucio.core.rse import get_rse
from rucio.daemons.undertaker import undertaker
from rucio.daemons.abacus import collection_replica
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.tests.common import file_generator


class TestAbacusCollectionReplica():

    def setUp(self):
        self.account = 'root'
        self.scope = 'mock'
        self.rule_client = RuleClient()
        self.did_client = DIDClient()
        self.replica_client = ReplicaClient()
        self.upload_client = UploadClient()
        self.file_sizes = 2
        self.dataset = 'dataset_%s' % generate_uuid()
        self.rse = 'MOCK5'
        self.rse_id = get_rse(self.rse).id

    def tearDown(self):
        undertaker.run(once=True)
        cleaner.run(once=True)
        reaper.run(once=True, rses=[self.rse], greedy=True)

    def test_abacus_collection_replica(self):
        """ ABACUS (COLLECTION REPLICA): Test update of collection replica. """
        self.files = [{'did_scope': self.scope, 'did_name': 'file_' + generate_uuid(), 'path': file_generator(size=self.file_sizes), 'rse': self.rse, 'lifetime': -1} for i in range(0, 2)]
        self.did_client.add_did(self.scope, self.dataset, DIDType.DATASET, lifetime=-1)
        self.upload_client.upload(self.files)
        self.did_client.attach_dids(scope=self.scope, name=self.dataset, dids=[{'name': file['did_name'], 'scope': file['did_scope']} for file in self.files])
        self.rule_client.add_replication_rule([{'scope': self.scope, 'name': self.dataset}], 1, self.rse, lifetime=-1)
        [os.remove(file['path']) for file in self.files]

        # Check dataset replica after rule creation - initial data
        dataset_replica = [replica for replica in self.replica_client.list_dataset_replicas(self.scope, self.dataset)][0]
        assert_equal(dataset_replica['bytes'], 0)
        assert_equal(dataset_replica['length'], 0)
        assert_equal(dataset_replica['available_bytes'], 0)
        assert_equal(dataset_replica['available_length'], 0)
        assert_equal(str(dataset_replica['state']), 'UNAVAILABLE')

        # Run Abacus
        collection_replica.run(once=True)

        # Check dataset replica after abacus - abacus should update the collection_replica table from updated_col_rep
        dataset_replica = [replica for replica in self.replica_client.list_dataset_replicas(self.scope, self.dataset)][0]
        assert_equal(dataset_replica['bytes'], len(self.files) * self.file_sizes)
        assert_equal(dataset_replica['length'], len(self.files))
        assert_equal(dataset_replica['available_bytes'], len(self.files) * self.file_sizes)
        assert_equal(dataset_replica['available_length'], len(self.files))
        assert_equal(str(dataset_replica['state']), 'AVAILABLE')

        # Delete one file -> collection replica should be unavailable
        cleaner.run(once=True)
        delete_replicas(rse=self.rse, files=[{'name': self.files[0]['did_name'], 'scope': self.files[0]['did_scope']}])
        self.rule_client.add_replication_rule([{'scope': self.scope, 'name': self.dataset}], 1, self.rse, lifetime=-1)
        collection_replica.run(once=True)
        dataset_replica = [replica for replica in self.replica_client.list_dataset_replicas(self.scope, self.dataset)][0]
        assert_equal(dataset_replica['length'], len(self.files))
        assert_equal(dataset_replica['bytes'], len(self.files) * self.file_sizes)
        assert_equal(dataset_replica['available_length'], len(self.files) - 1)
        assert_equal(dataset_replica['available_bytes'], (len(self.files) - 1) * self.file_sizes)
        assert_equal(str(dataset_replica['state']), 'UNAVAILABLE')

        # Delete all files -> collection replica should be deleted
        cleaner.run(once=True)
        reaper.run(once=True, rses=[self.rse], greedy=True)
        self.rule_client.add_replication_rule([{'scope': self.scope, 'name': self.dataset}], 1, self.rse, lifetime=-1)
        collection_replica.run(once=True)
        dataset_replica = [replica for replica in self.replica_client.list_dataset_replicas(self.scope, self.dataset)]
        assert_equal(len(dataset_replica), 0)
