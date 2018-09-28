# Copyright 2015-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018

from nose.tools import assert_equal

from rucio.core.replica import list_datasets_per_rse
from rucio.core.rse import add_rse, del_rse, add_protocol

from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.ruleclient import RuleClient
from rucio.common.utils import generate_uuid
from rucio.tests.common import rse_name_generator


class TestDatasetReplicaClient:

    def test_list_dataset_replicas(self):
        """ REPLICA (CLIENT): List dataset replicas."""
        replica_client = ReplicaClient()
        rule_client = RuleClient()
        did_client = DIDClient()
        scope = 'mock'
        dataset = 'dataset_' + str(generate_uuid())

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
        dataset = 'dataset_' + str(generate_uuid())

        did_client.add_dataset(scope=scope, name=dataset)
        rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}],
                                         account='root', copies=1, rse_expression='MOCK',
                                         grouping='DATASET')
        replicas = [r for r in list_datasets_per_rse(rse='MOCK', filters={'scope': 'mock', 'name': 'data*'})]
        assert(replicas != [])

    def test_list_dataset_replicas_archive(self):
        """ REPLICA (CLIENT): List dataset replicas with archives. """

        replica_client = ReplicaClient()
        did_client = DIDClient()
        rule_client = RuleClient()

        scope = 'mock'

        rse = 'APERTURE_%s' % rse_name_generator()
        add_rse(rse)
        add_protocol(rse, {'scheme': 'root',
                           'hostname': 'root.aperture.com',
                           'port': 1409,
                           'prefix': '//test/chamber/',
                           'impl': 'rucio.rse.protocols.xrootd.Default',
                           'domains': {
                               'lan': {'read': 1, 'write': 1, 'delete': 1},
                               'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        rse2 = 'BLACKMESA_%s' % rse_name_generator()
        add_rse(rse2)
        add_protocol(rse2, {'scheme': 'root',
                            'hostname': 'root.blackmesa.com',
                            'port': 1409,
                            'prefix': '//underground/facility',
                            'impl': 'rucio.rse.protocols.xrootd.Default',
                            'domains': {
                                'lan': {'read': 1, 'write': 1, 'delete': 1},
                                'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        # register archive
        archive = {'scope': scope, 'name': 'another.%s.zip' % generate_uuid(),
                   'type': 'FILE', 'bytes': 2596, 'adler32': 'deedbeaf'}
        replica_client.add_replicas(rse=rse, files=[archive])
        replica_client.add_replicas(rse=rse2, files=[archive])

        archived_files = [{'scope': scope, 'name': 'zippedfile-%i-%s' % (i, str(generate_uuid())), 'type': 'FILE',
                           'bytes': 4322, 'adler32': 'deaddead'} for i in xrange(2)]
        replica_client.add_replicas(rse=rse2, files=archived_files)
        did_client.add_files_to_archive(scope=scope, name=archive['name'], files=archived_files)

        dataset_name = 'find_me.' + str(generate_uuid())
        did_client.add_dataset(scope=scope, name=dataset_name)
        did_client.attach_dids(scope=scope, name=dataset_name, dids=archived_files)
        rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset_name}],
                                         account='root', copies=1, rse_expression=rse,
                                         grouping='DATASET')

        res = [r for r in replica_client.list_dataset_replicas(scope=scope,
                                                               name=dataset_name)]
        assert_equal(len(res), 1)
        assert_equal(res[0]['state'], 'UNAVAILABLE')

        res = [r for r in replica_client.list_dataset_replicas(scope=scope,
                                                               name=dataset_name,
                                                               deep=True)]

        assert_equal(len(res), 3)
        assert_equal(res[0]['state'], 'AVAILABLE')
        assert_equal(res[1]['state'], 'AVAILABLE')
        assert_equal(res[2]['state'], 'AVAILABLE')

        del_rse(rse)
