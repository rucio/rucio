# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2013


from nose.tools import assert_is_instance, assert_not_in

from rucio.client.didclient import DIDClient
from rucio.client.replicationruleclient import ReplicationRuleClient
from rucio.client.rseclient import RSEClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.utils import generate_uuid as uuid
from rucio.core.did import add_identifier, append_identifier
from rucio.core.lock import get_replica_locks
from rucio.core.rse import add_rse, add_rse_attribute, add_file_replica
from rucio.core.rule import add_replication_rule
from rucio.core.scope import add_scope


class TestReplicationRuleCore():

    def setup(self):
        #Add test scope
        self.tmp_scope = 'scope_%s' % uuid()[:20]
        add_scope(self.tmp_scope, 'root')

        #Add test RSE
        self.rse1 = str(uuid())
        self.rse2 = str(uuid())
        self.rse3 = str(uuid())
        self.rse4 = str(uuid())
        self.rse5 = str(uuid())
        self.rse1_id = add_rse(self.rse1)
        self.rse2_id = add_rse(self.rse2)
        self.rse3_id = add_rse(self.rse3)
        self.rse4_id = add_rse(self.rse4)
        self.rse5_id = add_rse(self.rse5)

        #Add Tags
        add_rse_attribute(self.rse1, "T1", True)
        add_rse_attribute(self.rse2, "T1", True)
        add_rse_attribute(self.rse3, "T1", True)
        add_rse_attribute(self.rse4, "T2", True)
        add_rse_attribute(self.rse5, "T1", True)

        #Add dataset
        self.tmp_dataset = 'dataset_' + str(uuid())
        add_identifier(self.tmp_scope, self.tmp_dataset, 'dataset', 'root')

        #Add files
        self.tmp_files = []
        for i in xrange(5):
            tmp_file = 'file_%s' % uuid()
            self.tmp_files.append(tmp_file)
            add_file_replica(rse=self.rse1, scope=self.tmp_scope, name=tmp_file, size=1000000, issuer='root')
            files = [{'scope': self.tmp_scope, 'name': tmp_file}, ]
            append_identifier(self.tmp_scope, self.tmp_dataset, files, 'root')

    def test_add_replication_rule(self):
        """ REPLICATION RULE (CORE): Add a replication rule """
        add_replication_rule(dids=[{'scope': self.tmp_scope, 'name': self.tmp_dataset}], account='root', copies=2, rse_expression='T1', grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
        #Add a second rule and check if the right locks are created
        add_replication_rule(dids=[{'scope': self.tmp_scope, 'name': self.tmp_dataset}], account='root', copies=2, rse_expression='T1|T2', grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
        for file in self.tmp_files:
            assert_not_in(self.rse4_id, get_replica_locks(scope=self.tmp_scope, name=file))


class TestReplicationRuleClients():

    def setup(self):
        self.did_client = DIDClient()
        self.rule_client = ReplicationRuleClient()
        self.rse_client = RSEClient()
        self.scope_client = ScopeClient()

    def test_add_replication_rule(self):
        """ REPLICATION RULE (CLIENT): Add a replication rule """

        # Add a scope
        tmp_scope = 'scope_%s' % uuid()[:22]
        self.scope_client.add_scope('root', tmp_scope)

        # Add a RSE
        tmp_rse = str(uuid())
        self.rse_client.add_rse(tmp_rse)

        # Add 10 Tiers1 RSEs
        for i in xrange(5):
            tmp_rse_t1 = str(uuid())
            self.rse_client.add_rse(tmp_rse_t1)
            self.rse_client.add_rse_attribute(rse=tmp_rse_t1, key='Tier', value='1')

        # Add datasets
        dsns = list()
        for i in xrange(5):
            tmp_dataset = 'dsn_' + str(uuid())
            # Add file replicas
            tmp_file = 'file_%s' % uuid()
            self.rse_client.add_file_replica(tmp_rse, tmp_scope, tmp_file, 1L, 1L)
            files = [{'scope': tmp_scope, 'name': tmp_file}, ]
            self.did_client.add_dataset(scope=tmp_scope, name=tmp_dataset)
            self.did_client.add_files_to_dataset(scope=tmp_scope, name=tmp_dataset, files=files)
            dsns.append({'scope': tmp_scope, 'name': tmp_dataset})

        ret = self.rule_client.add_replication_rule(dids=dsns, account="root", copies=2, rse_expression='Tier=1', grouping='NONE')
        assert_is_instance(ret, list)
