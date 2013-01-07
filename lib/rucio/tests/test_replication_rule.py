# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import re

from nose.tools import assert_is_instance, assert_regexp_matches

from rucio.client.dataidentifierclient import DataIdentifierClient
from rucio.client.replicationruleclient import ReplicationRuleClient
from rucio.client.rseclient import RSEClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.utils import generate_uuid as uuid
from rucio.daemons.Conveyor import run_once as Conveyor_run
from rucio.daemons.RRResolver import run_once as RRResolver_run


class TestIdentifierClients():

    def setup(self):
        self.did_client = DataIdentifierClient()
        self.rule_client = ReplicationRuleClient()
        self.rse_client = RSEClient()
        self.scope_client = ScopeClient()

    def test_add_replication_rule(self):
        """ REPLICATION RULE (CLIENT): Add a replication rule """

        # Add a scope
        tmp_scope = 'scope_%s' % uuid()
        self.scope_client.add_scope('root', tmp_scope)

        # Add a RSE
        tmp_rse = 'rse_%s' % uuid()
        self.rse_client.add_rse(tmp_rse)

        # Add 10 Tiers1 RSEs
        for i in xrange(5):
            tmp_rse_t1 = 'rse_%s' % uuid()
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
            self.did_client.add_identifier(scope=tmp_scope, name=tmp_dataset, sources=files)
            dsns.append({'scope': tmp_scope, 'name': tmp_dataset})

        ret = self.rule_client.add_replication_rule(dids=dsns, copies=2, rse_expression='Tier=1')
        assert_is_instance(ret, dict)
        assert_regexp_matches(ret['rule_id'], re.compile('[a-f0-9]{8}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{12}'))

        Conveyor_run()
