# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import xmltodict

from nose.tools import assert_equal, assert_raises

from rucio.client.baseclient import BaseClient
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.common.config import config_get
from rucio.common.exception import Duplicate, DataIdentifierNotFound
from rucio.common.utils import generate_uuid
from rucio.core.did import add_did, attach_dids, get_did, set_status, list_files
from rucio.core.replica import add_replica, add_replicas, delete_replicas, update_replica_lock_counter, get_replica, list_replicas
from rucio.db.constants import DIDType


class TestReplicaCore:

    def test_add_list_replicas(self):
        """ REPLICA (CORE): Add and list file replicas """
        tmp_scope = 'mock'
        nbfiles = 13
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        rses = ['MOCK', 'MOCK3']
        for rse in rses:
            add_replicas(rse=rse, files=files, account='root')

        replica_cpt = 0
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replica_cpt += 1

        assert_equal(nbfiles, replica_cpt)

    def test_delete_replicas(self):
        """ REPLICA (CORE): Delete replicas """
        tmp_scope = 'mock'
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        add_replicas(rse='MOCK', files=files1, account='root')

        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        add_replicas(rse='MOCK', files=files2, account='root')
        add_replicas(rse='MOCK3', files=files2, account='root')

        delete_replicas(rse='MOCK', files=files1 + files2)

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
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]

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

    def test_update_lock_counter(self):
        """ RSE (CORE): Test the update of a replica lock counter """
        rse = 'MOCK'
        tmp_scope = 'mock'
        tmp_file = 'file_%s' % generate_uuid()
        add_replica(rse=rse, scope=tmp_scope, name=tmp_file, bytes=1L, adler32='0cc737eb', account='jdoe')

        values = (1, 1, 1, -1, -1, -1, 1, 1, -1)
        tombstones = (True, True, True, True, True, False, True, True, True)
        lock_counters = (1, 2, 3, 2, 1, 0, 1, 2, 1)
        for value, tombstone, lock_counter in zip(values, tombstones, lock_counters):
            status = update_replica_lock_counter(rse=rse, scope=tmp_scope, name=tmp_file, value=value)
            assert_equal(status, True)
            replica = get_replica(rse=rse, scope=tmp_scope, name=tmp_file)
            assert_equal(replica['tombstone'] is None, tombstone)
            assert_equal(lock_counter, replica['lock_cnt'])


class TestReplicaClients:

    def setup(self):
        self.replica_client = ReplicaClient()

    def test_add_list_replicas(self):
        """ REPLICA (CLIENT): Add and list file replicas """
        tmp_scope = 'mock'
        nbfiles = 5

        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK', files=files1)

        with assert_raises(Duplicate):
            self.replica_client.add_replicas(rse='MOCK', files=files1)

        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK3', files=files2)

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files1])]
        assert_equal(len(replicas), len(files1))

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['file'])]
        assert_equal(len(replicas), 5)

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['srm'])]
        assert_equal(len(replicas), 5)

    def test_delete_replicas(self):
        tmp_scope = 'mock'
        nbfiles = 5
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK', files=files)
        self.replica_client.delete_replicas(rse='MOCK', files=files)

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files])]
        assert_equal(len(replicas), 0)


class TestReplicaMetalink:

    def setup(self):
        self.did_client = DIDClient()
        self.replica_client = ReplicaClient()
        self.base_client = BaseClient(account='root',
                                      ca_cert=config_get('client', 'ca_cert'),
                                      auth_type='x509')
        self.token = self.base_client.headers['X-Rucio-Auth-Token']

        self.fname = generate_uuid()

        rses = ['LXPLUS', 'MOCK4']
        dsn = generate_uuid()
        self.files = [{'scope': 'mock', 'name': self.fname, 'bytes': 1L, 'adler32': '0cc737eb'}]

        self.did_client.add_dataset(scope='mock', name=dsn)
        self.did_client.add_files_to_dataset('mock', name=dsn, files=self.files, rse='MOCK')
        for r in rses:
            self.replica_client.add_replicas(r, self.files)

    def test_list_replicas_metalink_3(self):
        """ REPLICA (METALINK): List replicas as metalink version 3 """
        ml = xmltodict.parse(self.replica_client.list_replicas(self.files,
                                                               metalink=3),
                             xml_attribs=False)
        assert_equal(3, len(ml['metalink']['files']['file']['resources']['url']))

    def test_list_replicas_metalink_4(self):
        """ REPLICA (METALINK): List replicas as metalink version 4 """
        ml = xmltodict.parse(self.replica_client.list_replicas(self.files,
                                                               metalink=4),
                             xml_attribs=False)
        assert_equal(3, len(ml['metalink']['files']['file']['url']))
