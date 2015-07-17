# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

from nose.tools import assert_equal

from rucio.core.replica import list_datasets_per_rse

from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.ruleclient import RuleClient
from rucio.common.utils import generate_uuid as uuid


class TestDatasetReplicaCLient:

    def test_list_dataset_replicas(self):
        """ REPLICA (CLIENT): List dataset replicas."""
        replica_client = ReplicaClient()
        rule_client = RuleClient()
        did_client = DIDClient()
        scope = 'mock'
        dataset = 'dataset_' + str(uuid())

        did_client.add_dataset(scope=scope, name=dataset)
        rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}],
                                         account='root', copies=1, rse_expression='MOCK',
                                         grouping='DATASET')
        replicas = [r for r in replica_client.list_dataset_replicas(scope=scope, name=dataset)]
        assert_equal(len(replicas), 1)

    def test_list_datasets_per_rse(self):
        """ REPLICA (CLIENT): List datasets in RSE."""
        rule_client = RuleClient()
        did_client = DIDClient()
        scope = 'mock'
        dataset = 'dataset_' + str(uuid())

        did_client.add_dataset(scope=scope, name=dataset)
        rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}],
                                         account='root', copies=1, rse_expression='MOCK',
                                         grouping='DATASET')
        replicas = [r for r in list_datasets_per_rse(rse='MOCK', filters={'scope': 'mock', 'name': 'data*'})]
        assert(replicas != [])
