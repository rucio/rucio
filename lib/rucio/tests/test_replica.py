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
from rucio.common.exception import Duplicate, DataIdentifierNotFound
from rucio.common.utils import generate_uuid
from rucio.core.rse import add_replicas, delete_replicas
from rucio.core.did import add_did, attach_dids, get_did, set_status, list_files, list_replicas
from rucio.db.constants import DIDType
# from rucio.rse.rsemanager import RSEMgr


class TestReplicaCore:

    def test_add_list_replicas(self):
        """ REPLICA (CORE): Add and list file replicas """
        tmp_scope = 'mock'
        nbfiles = 13
        files = [{'scope': tmp_scope, 'name':  'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        rses = ['MOCK', 'MOCK3']
        for rse in rses:
            add_replicas(rse=rse, files=files, account='root')

        replica_cpt = 0
        for replica in list_replicas(dids=files):
            replica_cpt += 1

        assert_equal(nbfiles, replica_cpt)

    def test_delete_replicas(self):
        """ REPLICA (CORE): Delete replicas """
        tmp_scope = 'mock'
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name':  'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        add_replicas(rse='MOCK', files=files1, account='root')

        files2 = [{'scope': tmp_scope, 'name':  'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        add_replicas(rse='MOCK', files=files2, account='root')
        add_replicas(rse='MOCK3', files=files2, account='root')

        delete_replicas(rse='MOCK', files=files1+files2)

        for file in files1:
            with assert_raises(DataIdentifierNotFound):
                get_did(scope=file['scope'], name=file['name'])

        for file in files2:
            get_did(scope=file['scope'], name=file['name'])

    def test_delete_replicas_from_datasets(self):
        """ REPLICA (CORE): Delete replicas from dataset """
        tmp_scope = 'mock'
        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name':  'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]

        add_did(scope=tmp_scope, name=tmp_dsn1, type=DIDType.DATASET, account='root')
        add_did(scope=tmp_scope, name=tmp_dsn2, type=DIDType.DATASET, account='root')

        attach_dids(scope=tmp_scope, name=tmp_dsn1, rse='MOCK', dids=files1, account='root')
        attach_dids(scope=tmp_scope, name=tmp_dsn2, dids=files1, account='root')

        set_status(scope=tmp_scope, name=tmp_dsn1, open=False)

        delete_replicas(rse='MOCK', files=files1)

        with assert_raises(DataIdentifierNotFound):
            get_did(scope=tmp_scope, name=tmp_dsn1)

        get_did(scope=tmp_scope, name=tmp_dsn2)

        assert_equal([f for f in list_files(scope=tmp_scope, name=tmp_dsn2)], [])


class TestReplica:

    def setup(self):
        self.account_client = AccountClient()
        self.scope_client = ScopeClient()
        self.meta_client = MetaClient()
        self.did_client = DIDClient()
        self.rse_client = RSEClient()

    def test_bulk_add_replicas(self):
        """ REPLICA (CLIENT): Bulk add replicas """
        tmp_scope = 'mock'
        nbfiles = 5
        files = [{'scope': tmp_scope, 'name':  'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.rse_client.add_replicas(rse='MOCK', files=files)
        self.rse_client.add_replicas(rse='MOCK3', files=files)

    def test_bulk_add_existing_replicas(self):
        """ REPLICA (CLIENT): Bulk add replicas with existing dids"""
        tmp_scope = 'mock'
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name':  'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.rse_client.add_replicas(rse='MOCK', files=files1)
        files2 = [{'scope': tmp_scope, 'name':  'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.rse_client.add_replicas(rse='MOCK3', files=files1 + files2)

    def test_add_list_replica(self):
        """ REPLICA (CLIENT): Add and list file replica """
        tmp_scope = 'mock'
        tmp_file = 'file_%s' % generate_uuid()
        tmp_pfn = 'mock://localhost/tmp/rucio_rse/non-determinsistc/path/%s' % tmp_file

        self.rse_client.add_replica(rse='MOCK', scope=tmp_scope, name=tmp_file, bytes=1L, adler32='0cc737eb')

        with assert_raises(Duplicate):
            self.rse_client.add_replica(rse='MOCK', scope=tmp_scope, name=tmp_file, bytes=1L, adler32='0cc737eb', pfn=tmp_pfn)

        self.rse_client.add_replica(rse='MOCK2', scope=tmp_scope, name=tmp_file, bytes=1L, adler32='0cc737eb', pfn=tmp_pfn)

        replicas = [r for r in self.did_client.list_replicas(scope=tmp_scope, name=tmp_file)]

        assert_equal(len(replicas), 1)

        # replicas = [r for r in self.did_client.list_replicas(scope=tmp_scope, name=tmp_file, schemes=['mock'])]
        # assert_equal(len(replicas), 2)
        # for replica in replicas:
        #    pfn_gen = RSEMgr().lfn2pfn(replica['rse'], {'scope': tmp_scope, 'filename': tmp_file}, scheme='mock')
        #    assert(pfn_gen == replica['pfns'][0])
