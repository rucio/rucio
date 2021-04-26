# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2020-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

import os
import unittest

import pytest

from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.ruleclient import RuleClient
from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get_bool
from rucio.common.types import InternalScope, InternalAccount
from rucio.common.utils import generate_uuid
from rucio.core.did import add_did
from rucio.core.replica import delete_replicas, get_cleaned_updated_collection_replicas
from rucio.core.rse import get_rse_id, add_rse
from rucio.daemons.abacus import collection_replica
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.daemons.undertaker import undertaker
from rucio.db.sqla import models, session
from rucio.db.sqla.constants import DIDType, ReplicaState
from rucio.tests.common import file_generator, rse_name_generator
from rucio.tests.common_server import get_vo


@pytest.mark.noparallel(reason='uses pre-defined RSE, fails when run in parallel')
class TestAbacusCollectionReplica(unittest.TestCase):
    account = 'root'
    scope = 'mock'
    rse = 'MOCK5'
    file_sizes = 2
    vo = {}

    @classmethod
    def setUpClass(cls):
        cls.dataset = 'dataset_%s' % generate_uuid()

        cls.rule_client = RuleClient()
        cls.did_client = DIDClient()
        cls.replica_client = ReplicaClient()
        cls.upload_client = UploadClient()

        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}

        cls.rse_id = get_rse_id(rse=cls.rse, **cls.vo)

    @classmethod
    def tearDownClass(cls):
        undertaker.run(once=True)
        cleaner.run(once=True)
        if cls.vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (cls.vo['vo'], cls.rse), greedy=True)
        else:
            reaper.run(once=True, include_rses=cls.rse, greedy=True)

    def test_abacus_collection_replica_cleanup(self):
        """ ABACUS (COLLECTION REPLICA): Test if the cleanup procedure works correctly. """
        collection_replica.run(once=True)
        db_session = session.get_session()
        rse1 = rse_name_generator()
        rse_id1 = add_rse(rse1, **self.vo)
        rse2 = rse_name_generator()
        rse_id2 = add_rse(rse2, **self.vo)

        scope = InternalScope('mock', **self.vo)
        dataset = 'dataset_%s' % generate_uuid()
        jdoe = InternalAccount('jdoe', **self.vo)
        add_did(scope, dataset, DIDType.DATASET, jdoe)

        models.CollectionReplica(scope=scope, name=dataset, rse_id=rse_id1, state=ReplicaState.AVAILABLE, bytes=1).save(session=db_session, flush=False)
        models.CollectionReplica(scope=scope, name=dataset, rse_id=rse_id2, state=ReplicaState.AVAILABLE, bytes=1).save(session=db_session, flush=False)

        models.UpdatedCollectionReplica(scope=scope, name=dataset, rse_id=rse_id1, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        models.UpdatedCollectionReplica(scope=scope, name=dataset, rse_id=rse_id1, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        models.UpdatedCollectionReplica(scope=scope, name=dataset, rse_id=rse_id2, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        models.UpdatedCollectionReplica(scope=scope, name=dataset, rse_id=rse_id2, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        models.UpdatedCollectionReplica(scope=scope, name=dataset, rse_id=None, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        db_session.commit()
        assert len(get_cleaned_updated_collection_replicas(1, 1)) == 3

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
        assert dataset_replica['bytes'] == 0
        assert dataset_replica['length'] == 0
        assert dataset_replica['available_bytes'] == 0
        assert dataset_replica['available_length'] == 0
        assert str(dataset_replica['state']) == 'UNAVAILABLE'

        # Run Abacus
        collection_replica.run(once=True)

        # Check dataset replica after abacus - abacus should update the collection_replica table from updated_col_rep
        dataset_replica = [replica for replica in self.replica_client.list_dataset_replicas(self.scope, self.dataset)][0]
        assert dataset_replica['bytes'] == len(self.files) * self.file_sizes
        assert dataset_replica['length'] == len(self.files)
        assert dataset_replica['available_bytes'] == len(self.files) * self.file_sizes
        assert dataset_replica['available_length'] == len(self.files)
        assert str(dataset_replica['state']) == 'AVAILABLE'

        # Delete one file -> collection replica should be unavailable
        cleaner.run(once=True)
        delete_replicas(rse_id=self.rse_id, files=[{'name': self.files[0]['did_name'], 'scope': InternalScope(self.files[0]['did_scope'], **self.vo)}])
        self.rule_client.add_replication_rule([{'scope': self.scope, 'name': self.dataset}], 1, self.rse, lifetime=-1)
        collection_replica.run(once=True)
        dataset_replica = [replica for replica in self.replica_client.list_dataset_replicas(self.scope, self.dataset)][0]
        assert dataset_replica['length'] == len(self.files)
        assert dataset_replica['bytes'] == len(self.files) * self.file_sizes
        assert dataset_replica['available_length'] == len(self.files) - 1
        assert dataset_replica['available_bytes'] == (len(self.files) - 1) * self.file_sizes
        assert str(dataset_replica['state']) == 'UNAVAILABLE'

        # Delete all files -> collection replica should be deleted
        from rucio.daemons.reaper.reaper import REGION
        REGION.invalidate()
        cleaner.run(once=True)
        if self.vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (self.vo['vo'], self.rse), greedy=True)
        else:
            reaper.run(once=True, include_rses=self.rse, greedy=True)
        self.rule_client.add_replication_rule([{'scope': self.scope, 'name': self.dataset}], 1, self.rse, lifetime=-1)
        collection_replica.run(once=True)
        dataset_replica = [replica for replica in self.replica_client.list_dataset_replicas(self.scope, self.dataset)]
        assert len(dataset_replica) == 0
