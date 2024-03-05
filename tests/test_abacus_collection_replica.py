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


import pytest

from rucio.common.exception import DataIdentifierNotFound
from rucio.common.schema import get_schema_value
from rucio.core.did import add_did, get_did
from rucio.core.replica import delete_replicas, get_cleaned_updated_collection_replicas
from rucio.daemons.abacus import collection_replica
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.daemons.undertaker import undertaker
from rucio.db.sqla import models, session
from rucio.db.sqla.constants import DIDType, ReplicaState
from rucio.tests.common import did_name_generator


@pytest.mark.noparallel(reason='uses daemons, fails when run in parallel')
class TestAbacusCollectionReplica():

    def test_abacus_collection_replica_cleanup(self, vo, mock_scope, rse_factory, did_client, jdoe_account):
        """ ABACUS (COLLECTION REPLICA): Test if the cleanup procedure works correctly. """
        collection_replica.run(once=True)
        db_session = session.get_session()
        rse1, rse_id1 = rse_factory.make_rse()
        rse2, rse_id2 = rse_factory.make_rse()

        dataset = did_name_generator('dataset')
        add_did(mock_scope, dataset, DIDType.DATASET, jdoe_account)

        models.CollectionReplica(scope=mock_scope, name=dataset, rse_id=rse_id1, did_type=DIDType.DATASET,
                                 state=ReplicaState.AVAILABLE, bytes=1, length=1).save(session=db_session, flush=False)
        models.CollectionReplica(scope=mock_scope, name=dataset, rse_id=rse_id2, did_type=DIDType.DATASET,
                                 state=ReplicaState.AVAILABLE, bytes=1, length=1).save(session=db_session, flush=False)

        models.UpdatedCollectionReplica(scope=mock_scope, name=dataset, rse_id=rse_id1, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        models.UpdatedCollectionReplica(scope=mock_scope, name=dataset, rse_id=rse_id1, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        models.UpdatedCollectionReplica(scope=mock_scope, name=dataset, rse_id=rse_id2, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        models.UpdatedCollectionReplica(scope=mock_scope, name=dataset, rse_id=rse_id2, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        models.UpdatedCollectionReplica(scope=mock_scope, name=dataset, rse_id=None, did_type=DIDType.DATASET).save(session=db_session, flush=False)
        db_session.commit()
        assert len(get_cleaned_updated_collection_replicas(1, 1)) == 3
        did_client.set_metadata(mock_scope.external, dataset, 'lifetime', -1)
        undertaker.run(once=True)
        cleaner.run(once=True)
        if vo:
            reaper.run(once=True, include_rses='vo=%s&(%s|%s)' % (str(vo), rse1, rse2), greedy=True)
        else:
            reaper.run(once=True, include_rses='(%s|%s)' % (rse1, rse2), greedy=True)

    def test_abacus_collection_replica(self, vo, mock_scope, rse_factory, did_factory, rucio_client):
        """ ABACUS (COLLECTION REPLICA): Test update of collection replica. """
        file_sizes = 2
        nfiles = 2
        dataset = did_name_generator('dataset')
        rse, rse_id = rse_factory.make_posix_rse()
        rucio_client.add_did(mock_scope.external, dataset, DIDType.DATASET, lifetime=-1)
        dids = did_factory.upload_test_dataset(rse_name=rse, scope=mock_scope.external, size=file_sizes, nb_files=nfiles)
        files = [{'scope': did['did_scope'], 'name': did['did_name']} for did in dids]
        dataset = dids[0]['dataset_name']
        activity = get_schema_value('ACTIVITY')['enum'][0]
        rucio_client.add_replication_rule([{'scope': mock_scope.external, 'name': dataset}], 1, rse, lifetime=-1, activity=activity)

        # Check dataset replica after rule creation - initial data
        dataset_replica = [replica for replica in rucio_client.list_dataset_replicas(mock_scope.external, dataset)][0]
        assert dataset_replica['bytes'] == 0
        assert dataset_replica['length'] == 0
        assert dataset_replica['available_bytes'] == 0
        assert dataset_replica['available_length'] == 0
        assert str(dataset_replica['state']) == 'UNAVAILABLE'

        # Run Abacus
        collection_replica.run(once=True)

        # Check dataset replica after abacus - abacus should update the collection_replica table from updated_col_rep
        dataset_replica = [replica for replica in rucio_client.list_dataset_replicas(mock_scope.external, dataset)][0]
        assert dataset_replica['bytes'] == len(files) * file_sizes
        assert dataset_replica['length'] == len(files)
        assert dataset_replica['available_bytes'] == len(files) * file_sizes
        assert dataset_replica['available_length'] == len(files)
        assert str(dataset_replica['state']) == 'AVAILABLE'

        # Delete one file -> collection replica should be unavailable
        cleaner.run(once=True)
        delete_replicas(rse_id=rse_id, files=[{'name': files[0]['name'], 'scope': mock_scope}])
        activity = get_schema_value('ACTIVITY')['enum'][0]
        rucio_client.add_replication_rule([{'scope': mock_scope.external, 'name': dataset}], 1, rse, lifetime=-1, activity=activity)
        collection_replica.run(once=True)
        dataset_replica = [replica for replica in rucio_client.list_dataset_replicas(mock_scope.external, dataset)][0]
        assert dataset_replica['length'] == len(files)
        assert dataset_replica['bytes'] == len(files) * file_sizes
        assert dataset_replica['available_length'] == len(files) - 1
        assert dataset_replica['available_bytes'] == (len(files) - 1) * file_sizes
        assert str(dataset_replica['state']) == 'UNAVAILABLE'

        # Delete all files -> collection replica should be deleted
        # Old behaviour (doesn't delete the DID)
        cleaner.run(once=True)
        reaper.REGION.invalidate()
        if vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (str(vo), rse), greedy=True)
        else:
            reaper.run(once=True, include_rses=rse, greedy=True)
        activity = get_schema_value('ACTIVITY')['enum'][0]
        rucio_client.add_replication_rule([{'scope': mock_scope.external, 'name': dataset}], 1, rse, lifetime=-1, activity=activity)
        collection_replica.run(once=True)
        dataset_replica = [replica for replica in rucio_client.list_dataset_replicas(mock_scope.external, dataset)]
        assert dataset_replica[0]['length'] == 0
        assert dataset_replica[0]['available_length'] == 0

    @pytest.mark.noparallel(reason='runs multiple daemons which may impact other tests run in parallel')
    @pytest.mark.parametrize("core_config_mock", [{"table_content": [
        ('reaper', 'remove_open_did', True)
    ]}], indirect=True)
    @pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
        'rucio.core.config.REGION', 'rucio.core.replica.REGION'
    ]}], indirect=True)
    def test_abacus_collection_replica_new(self, vo, mock_scope, rse_factory, rucio_client, did_factory, core_config_mock, caches_mock):
        """ ABACUS (COLLECTION REPLICA): Test update of collection replica. """
        file_sizes = 2
        nfiles = 2
        rse, rse_id = rse_factory.make_posix_rse()
        dids = did_factory.upload_test_dataset(rse_name=rse, scope=mock_scope.external, size=file_sizes, nb_files=nfiles)
        files = [{'scope': did['did_scope'], 'name': did['did_name']} for did in dids]
        dataset = dids[0]['dataset_name']
        rucio_client.set_metadata(mock_scope.external, dataset, 'lifetime', -1)
        activity = get_schema_value('ACTIVITY')['enum'][0]
        rucio_client.add_replication_rule([{'scope': mock_scope.external, 'name': dataset}], 1, rse, lifetime=-1, activity=activity)

        # Check dataset replica after rule creation - initial data
        dataset_replica = [replica for replica in rucio_client.list_dataset_replicas(mock_scope.external, dataset)][0]
        assert dataset_replica['bytes'] == 0
        assert dataset_replica['length'] == 0
        assert dataset_replica['available_bytes'] == 0
        assert dataset_replica['available_length'] == 0
        assert str(dataset_replica['state']) == 'UNAVAILABLE'

        # Run Abacus
        collection_replica.run(once=True)

        # Check dataset replica after abacus - abacus should update the collection_replica table from updated_col_rep
        dataset_replica = [replica for replica in rucio_client.list_dataset_replicas(mock_scope.external, dataset)][0]
        assert dataset_replica['bytes'] == len(files) * file_sizes
        assert dataset_replica['length'] == len(files)
        assert dataset_replica['available_bytes'] == len(files) * file_sizes
        assert dataset_replica['available_length'] == len(files)
        assert str(dataset_replica['state']) == 'AVAILABLE'

        # Delete one file -> collection replica should be unavailable
        cleaner.run(once=True)
        delete_replicas(rse_id=rse_id, files=[{'name': files[0]['name'], 'scope': mock_scope}])
        activity = get_schema_value('ACTIVITY')['enum'][0]
        rucio_client.add_replication_rule([{'scope': mock_scope.external, 'name': dataset}], 1, rse, lifetime=-1, activity=activity)
        collection_replica.run(once=True)
        dataset_replica = [replica for replica in rucio_client.list_dataset_replicas(mock_scope.external, dataset)][0]
        assert dataset_replica['length'] == len(files)
        assert dataset_replica['bytes'] == len(files) * file_sizes
        assert dataset_replica['available_length'] == len(files) - 1
        assert dataset_replica['available_bytes'] == (len(files) - 1) * file_sizes
        assert str(dataset_replica['state']) == 'UNAVAILABLE'

        # Delete all files -> collection replica should be deleted
        # New behaviour (dataset should be deleted)
        cleaner.run(once=True)
        delete_replicas(rse_id=rse_id, files=[{'name': files[1]['name'], 'scope': mock_scope}])
        with pytest.raises(DataIdentifierNotFound):
            get_did(scope=mock_scope, name=dataset)
