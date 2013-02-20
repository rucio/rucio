# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from nose.tools import assert_equal
from urlparse import urlparse

from rucio.client.accountclient import AccountClient
from rucio.client.dataidentifierclient import DataIdentifierClient
from rucio.client.metaclient import MetaClient
from rucio.client.rseclient import RSEClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.utils import generate_uuid


class TestReplica():

    def setup(self):
        self.account_client = AccountClient()
        self.scope_client = ScopeClient()
        self.meta_client = MetaClient()
        self.did_client = DataIdentifierClient()
        self.rse_client = RSEClient()

    def test_add_list_replica(self):
        """ REPLICA (CLIENT): Add and list file replica """
        tmp_scope = 'scope_%s' % generate_uuid()[:22]
        tmp_file = 'file_%s' % generate_uuid()
        self.scope_client.add_scope('root', tmp_scope)
        self.rse_client.add_file_replica('MOCK', tmp_scope, tmp_file, 1L, 1L)
        replicas = [r for r in self.did_client.list_replicas(scope=tmp_scope, name=tmp_file)]
        assert_equal(len(replicas), 1)
        replicas = [r for r in self.did_client.list_replicas(scope=tmp_scope, name=tmp_file, protocols=['posix'])]
        assert_equal(len(replicas), 1)
        for replica in replicas:
            for pfn in replica['pfns']:
                assert_equal(urlparse(pfn).path, pfn)
