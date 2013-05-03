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

from rucio.client.accountclient import AccountClient
from rucio.client.didclient import DIDClient
from rucio.client.metaclient import MetaClient
from rucio.client.rseclient import RSEClient
from rucio.client.scopeclient import ScopeClient
from rucio.common.exception import FileConsistencyMismatch, UnsupportedOperation
from rucio.common.utils import generate_uuid
from rucio.rse.rsemanager import RSEMgr


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
        tmp_pfn = 'mock:///tmp/rucio_rse/non-determinsistc/path/%s' % tmp_file

        self.scope_client.add_scope('root', tmp_scope)

        self.rse_client.add_file_replica(rse='MOCK', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc737eb')

        with assert_raises(UnsupportedOperation):
            self.rse_client.add_file_replica(rse='MOCK', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc737eb', pfn=tmp_pfn)

        with assert_raises(UnsupportedOperation):
            self.rse_client.add_file_replica(rse='MOCK2', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc737eb')

        with assert_raises(FileConsistencyMismatch):
            self.rse_client.add_file_replica(rse='MOCK2', scope=tmp_scope, name=tmp_file, size=2L, adler32='0cc737eb', pfn=tmp_pfn)

        with assert_raises(FileConsistencyMismatch):
            self.rse_client.add_file_replica(rse='MOCK2', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc837eb', pfn=tmp_pfn)

        self.rse_client.add_file_replica(rse='MOCK2', scope=tmp_scope, name=tmp_file, size=1L, adler32='0cc737eb', pfn=tmp_pfn)

        replicas = [r for r in self.did_client.list_replicas(scope=tmp_scope, name=tmp_file)]
        assert_equal(len(replicas), 2)

        replicas = [r for r in self.did_client.list_replicas(scope=tmp_scope, name=tmp_file, schemes=['mock'])]
        print '---'
        print replicas
        print '---'
        assert_equal(len(replicas), 2)
        for replica in replicas:
            pfn_gen = RSEMgr().lfn2pfn(replica['rse'], {'scope': tmp_scope, 'filename': tmp_file}, scheme='mock')
            assert(pfn_gen == replica['pfns'][0])
