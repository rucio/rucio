# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from nose.tools import assert_equal, assert_raises
from urlparse import urlparse

from rucio.client.accountclient import AccountClient
from rucio.client.didclient import DIDClient
from rucio.client.metaclient import MetaClient
from rucio.client.rseclient import RSEClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.exception import UnsupportedOperation
from rucio.common.utils import generate_uuid


class TestReplica():

    def setup(self):
        self.account_client = AccountClient()
        self.scope_client = ScopeClient()
        self.meta_client = MetaClient()
        self.did_client = DIDClient()
        self.rse_client = RSEClient()

    def test_add_list_replica(self):
        """ REPLICA (CLIENT): Add and list file replica """
        tmp_scope = 'scope_%s' % generate_uuid()[:22]
        tmp_file = 'file_%s' % generate_uuid()
        tmp_pfn = '/tmpt/%s' % tmp_file

        self.scope_client.add_scope('root', tmp_scope)

        self.rse_client.add_file_replica(rse='MOCK', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc737eb')

#        with assert_raises(UnsupportedOperation):
#            self.rse_client.add_file_replica(rse='MOCK', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc737eb', pfn=tmp_pfn)

        with assert_raises(UnsupportedOperation):
            self.rse_client.add_file_replica(rse='MOCK2', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc737eb')

        self.rse_client.add_file_replica(rse='MOCK2', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc737eb', pfn=tmp_pfn)

        replicas = [r for r in self.did_client.list_replicas(scope=tmp_scope, name=tmp_file)]
        assert_equal(len(replicas), 2)

        replicas = [r for r in self.did_client.list_replicas(scope=tmp_scope, name=tmp_file, protocols=['posix'])]
        assert_equal(len(replicas), 2)
        for replica in replicas:
            for pfn in replica['pfns']:
                assert_equal(urlparse(pfn).path, pfn)
