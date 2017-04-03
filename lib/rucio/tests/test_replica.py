# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014, 2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014-2016
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

import xmltodict

from datetime import datetime, timedelta
from json import dumps, loads
from nose.tools import assert_equal, assert_in, assert_raises
from paste.fixture import TestApp


from rucio.db.sqla.constants import DIDType, ReplicaState
from rucio.client.baseclient import BaseClient
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.common.config import config_get
from rucio.common.exception import DataIdentifierNotFound, AccessDenied, UnsupportedOperation
from rucio.common.utils import generate_uuid
from rucio.core.did import add_did, attach_dids, get_did, set_status, list_files, get_did_atime
from rucio.core.replica import (add_replica, add_replicas, delete_replicas,
                                update_replica_lock_counter, get_replica, list_replicas,
                                declare_bad_file_replicas, list_bad_replicas,
                                update_replicas_paths, update_replica_state,
                                get_replica_atime, touch_replica)
from rucio.daemons.necromancer import run
from rucio.rse import rsemanager as rsemgr
from rucio.web.rest.authentication import APP as auth_app
from rucio.web.rest.replica import APP as rep_app


class TestReplicaCore:

    def test_update_replicas_paths(self):
        """ REPLICA (CORE): Force update the replica path """
        tmp_scope = 'mock'
        nbfiles = 5
        rse_info = rsemgr.get_rse_info('MOCK')
        files = [{'scope': tmp_scope,
                  'name': 'file_%s' % generate_uuid(),
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/does/not/really/matter/where',
                  'bytes': 1L,
                  'adler32': '0cc737eb',
                  'meta': {'events': 10},
                  'rse_id': rse_info['id'],
                  'path': '/does/not/really/matter/where'} for i in xrange(nbfiles)]
        add_replicas(rse='MOCK2', files=files, account='root', ignore_availability=True)
        update_replicas_paths(files)
        for replica in list_replicas(dids=[{'scope': f['scope'],
                                            'name': f['name'],
                                            'type': DIDType.FILE} for f in files],
                                     schemes=['srm']):
            # force the changed string - if we look it up from the DB, then we're not testing anything :-D
            assert_equal(replica['rses']['MOCK2'][0], 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/does/not/really/matter/where')

    def test_add_list_bad_replicas(self):
        """ REPLICA (CORE): Add bad replicas and list them"""
        tmp_scope = 'mock'
        nbfiles = 5
        # Adding replicas to deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        rse_info = rsemgr.get_rse_info('MOCK')
        rse_id1 = rse_info['id']
        add_replicas(rse='MOCK', files=files, account='root', ignore_availability=True)

        # Listing replicas on deterministic RSE
        replicas = []
        list_rep = []
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replicas.extend(replica['rses']['MOCK'])
            list_rep.append(replica)
        r = declare_bad_file_replicas(replicas, 'This is a good reason', 'root')
        assert_equal(r, {})
        bad_replicas = list_bad_replicas()
        nbbadrep = 0
        for rep in list_rep:
            for badrep in bad_replicas:
                if badrep['rse_id'] == rse_id1:
                    if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                        nbbadrep += 1
        assert_equal(len(replicas), nbbadrep)

        # Adding replicas to non-deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for i in xrange(nbfiles)]
        rse_info = rsemgr.get_rse_info('MOCK2')
        rse_id2 = rse_info['id']
        add_replicas(rse='MOCK2', files=files, account='root', ignore_availability=True)

        # Listing replicas on non-deterministic RSE
        replicas = []
        list_rep = []
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replicas.extend(replica['rses']['MOCK2'])
            list_rep.append(replica)
        r = declare_bad_file_replicas(replicas, 'This is a good reason', 'root')
        assert_equal(r, {})
        bad_replicas = list_bad_replicas()
        nbbadrep = 0
        for rep in list_rep:
            for badrep in bad_replicas:
                if badrep['rse_id'] == rse_id2:
                    if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                        nbbadrep += 1
        assert_equal(len(replicas), nbbadrep)

        # Now adding non-existing bad replicas
        files = ['srm://mock2.com/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), ]
        r = declare_bad_file_replicas(files, 'This is a good reason', 'root')
        output = ['%s Unknown replica' % rep for rep in files]
        assert_equal(r, {'MOCK2': output})

    def test_add_list_replicas(self):
        """ REPLICA (CORE): Add and list file replicas """
        tmp_scope = 'mock'
        nbfiles = 13
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        rses = ['MOCK', 'MOCK3']
        for rse in rses:
            add_replicas(rse=rse, files=files, account='root', ignore_availability=True)

        replica_cpt = 0
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replica_cpt += 1

        assert_equal(nbfiles, replica_cpt)

    def test_delete_replicas(self):
        """ REPLICA (CORE): Delete replicas """
        tmp_scope = 'mock'
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        add_replicas(rse='MOCK', files=files1, account='root', ignore_availability=True)

        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        add_replicas(rse='MOCK', files=files2, account='root', ignore_availability=True)
        add_replicas(rse='MOCK3', files=files2, account='root', ignore_availability=True)

        delete_replicas(rse='MOCK', files=files1 + files2)

        for file in files1:
            with assert_raises(DataIdentifierNotFound):
                print get_did(scope=file['scope'], name=file['name'])

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

    def test_touch_replicas(self):
        """ REPLICA (CORE): Touch replicas accessed_at timestamp"""
        tmp_scope = 'mock'
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        files2.append(files1[0])
        add_replicas(rse='MOCK', files=files1, account='root', ignore_availability=True)
        add_replicas(rse='MOCK', files=files2, account='root', ignore_availability=True)

        now = datetime.utcnow()

        now -= timedelta(microseconds=now.microsecond)

        assert_equal(None, get_replica_atime({'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse': 'MOCK'}))
        assert_equal(None, get_did_atime(scope=tmp_scope, name=files1[0]['name']))

        for r in [{'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse': 'MOCK', 'accessed_at': now}]:
            touch_replica(r)

        assert_equal(now, get_replica_atime({'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse': 'MOCK'}))
        assert_equal(now, get_did_atime(scope=tmp_scope, name=files1[0]['name']))

        for i in range(1, nbfiles):
            assert_equal(None, get_replica_atime({'scope': files1[i]['scope'], 'name': files1[i]['name'], 'rse': 'MOCK'}))

        for i in range(0, nbfiles - 1):
            assert_equal(None, get_replica_atime({'scope': files2[i]['scope'], 'name': files2[i]['name'], 'rse': 'MOCK'}))

    def test_list_replicas_all_states(self):
        """ REPLICA (CORE): list file replicas with all_states"""
        tmp_scope = 'mock'
        nbfiles = 13
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        rses = ['MOCK', 'MOCK3']
        for rse in rses:
            add_replicas(rse=rse, files=files, account='root', ignore_availability=True)

        for file in files:
            update_replica_state('MOCK', tmp_scope, file['name'], ReplicaState.COPYING)

        replica_cpt = 0
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm'], all_states=True):
            assert_in('states', replica)
            assert_equal(replica['states']['MOCK'], str(ReplicaState.COPYING))
            assert_equal(replica['states']['MOCK3'], str(ReplicaState.AVAILABLE))
            replica_cpt += 1

        assert_equal(nbfiles, replica_cpt)


class TestReplicaClients:

    def setup(self):
        self.replica_client = ReplicaClient()
        self.did_client = DIDClient()

    def test_add_list_bad_replicas(self):
        """ REPLICA (CLIENT): Add bad replicas"""
        tmp_scope = 'mock'
        nbfiles = 5
        # Adding replicas to deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        rse_info = rsemgr.get_rse_info('MOCK')
        rse_id1 = rse_info['id']
        self.replica_client.add_replicas(rse='MOCK', files=files)

        # Listing replicas on deterministic RSE
        replicas, list_rep = [], []
        for replica in self.replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
            replicas.extend(replica['rses']['MOCK'])
            list_rep.append(replica)
        r = self.replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
        assert_equal(r, {})
        bad_replicas = list_bad_replicas()
        nbbadrep = 0
        for rep in list_rep:
            for badrep in bad_replicas:
                if badrep['rse_id'] == rse_id1:
                    if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                        nbbadrep += 1
        assert_equal(len(replicas), nbbadrep)

        # Run necromancer once
        run(threads=1, bulk=10000, once=True)

        # Try to attach a lost file
        tmp_dsn = 'dataset_%s' % generate_uuid()
        self.did_client.add_dataset(scope=tmp_scope, name=tmp_dsn)
        with assert_raises(UnsupportedOperation):
            self.did_client.add_files_to_dataset(tmp_scope, name=tmp_dsn, files=files, rse='MOCK')

        # Adding replicas to non-deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for i in xrange(nbfiles)]
        rse_info = rsemgr.get_rse_info('MOCK2')
        rse_id2 = rse_info['id']
        self.replica_client.add_replicas(rse='MOCK2', files=files)

        # Listing replicas on non-deterministic RSE
        replicas, list_rep = [], []
        for replica in self.replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
            replicas.extend(replica['rses']['MOCK2'])
            list_rep.append(replica)
        print replicas, list_rep
        r = self.replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
        print r
        assert_equal(r, {})
        bad_replicas = list_bad_replicas()
        nbbadrep = 0
        for rep in list_rep:
            for badrep in bad_replicas:
                if badrep['rse_id'] == rse_id2:
                    if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                        nbbadrep += 1
        assert_equal(len(replicas), nbbadrep)

        # Now adding non-existing bad replicas
        files = ['srm://mock2.com/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), ]
        r = self.replica_client.declare_bad_file_replicas(files, 'This is a good reason')
        output = ['%s Unknown replica' % rep for rep in files]
        assert_equal(r, {'MOCK2': output})

    def test_add_suspicious_replicas(self):
        """ REPLICA (CLIENT): Add suspicious replicas"""
        tmp_scope = 'mock'
        nbfiles = 5
        # Adding replicas to deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK', files=files)

        # Listing replicas on deterministic RSE
        replicas = []
        list_rep = []
        for replica in self.replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
            replicas.extend(replica['rses']['MOCK'])
            list_rep.append(replica)
        r = self.replica_client.declare_suspicious_file_replicas(replicas, 'This is a good reason')
        assert_equal(r, {})

        # Adding replicas to non-deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK2', files=files)

        # Listing replicas on non-deterministic RSE
        replicas = []
        list_rep = []
        for replica in self.replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
            replicas.extend(replica['rses']['MOCK2'])
            list_rep.append(replica)
        r = self.replica_client.declare_suspicious_file_replicas(replicas, 'This is a good reason')
        assert_equal(r, {})

        # Now adding non-existing bad replicas
        files = ['srm://mock2.com/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), ]
        r = self.replica_client.declare_suspicious_file_replicas(files, 'This is a good reason')
        output = ['%s Unknown replica' % rep for rep in files]
        assert_equal(r, {'MOCK2': output})

    def test_bad_replica_methods_for_UI(self):
        """ REPLICA (REST): Test the listing of bad and suspicious replicas """
        mw = []
        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Auth-Token': str(token)}

        data = dumps({})
        r2 = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 200)
        tot_files = []
        for line in r2.body.split('\n'):
            if line != '':
                tot_files.append(dumps(line))
        nb_tot_files = len(tot_files)

        data = dumps({'state': 'B'})
        r2 = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 200)
        tot_bad_files = []
        for line in r2.body.split('\n'):
            if line != '':
                tot_bad_files.append(dumps(line))
        nb_tot_bad_files1 = len(tot_bad_files)

        data = dumps({'state': 'S', 'list_pfns': 'True'})
        r2 = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 200)
        tot_suspicious_files = []
        for line in r2.body.split('\n'):
            if line != '':
                tot_suspicious_files.append(dumps(line))
        nb_tot_suspicious_files = len(tot_suspicious_files)

        assert_equal(nb_tot_files, nb_tot_bad_files1 + nb_tot_suspicious_files)

        tomorrow = datetime.utcnow() + timedelta(2)
        data = dumps({'state': 'B', 'younger_than': tomorrow.isoformat()})
        r2 = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 200)
        tot_bad_files = []
        for line in r2.body.split('\n'):
            if line != '':
                tot_bad_files.append(dumps(line))
        nb_tot_bad_files = len(tot_bad_files)
        assert_equal(nb_tot_bad_files, 0)

        data = dumps({})
        r2 = TestApp(rep_app.wsgifunc(*mw)).get('/bad/summary', headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 200)
        nb_tot_bad_files2 = 0
        for line in r2.body.split('\n'):
            if line != '':
                line = loads(line)
                nb_tot_bad_files2 += int(line['BAD'])
        assert_equal(nb_tot_bad_files1, nb_tot_bad_files2)

    def test_add_list_replicas(self):
        """ REPLICA (CLIENT): Add, change state and list file replicas """
        tmp_scope = 'mock'
        nbfiles = 5

        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK', files=files1)

        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK3', files=files2)

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files1])]
        assert_equal(len(replicas), len(files1))

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['file'])]
        assert_equal(len(replicas), 5)

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['srm'])]
        assert_equal(len(replicas), 5)

        files3 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'state': 'U', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK3', files=files3)
        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files3], schemes=['file'])]
        for i in xrange(nbfiles):
            assert_equal(replicas[i]['rses'], {})
        files4 = []
        for file in files3:
            file['state'] = 'A'
            files4.append(file)
        self.replica_client.update_replicas_states('MOCK3', files=files4)
        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files3], schemes=['file'], unavailable=True)]
        assert_equal(len(replicas), 5)
        for i in xrange(nbfiles):
            assert_in('MOCK3', replicas[i]['rses'])

    def test_delete_replicas(self):
        """ REPLICA (CLIENT): Add and delete file replicas """
        tmp_scope = 'mock'
        nbfiles = 5
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK', files=files)
        with assert_raises(AccessDenied):
            self.replica_client.delete_replicas(rse='MOCK', files=files)

        # replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files])]
        # assert_equal(len(replicas), 0)


class TestReplicaMetalink:

    def setup(self):
        self.did_client = DIDClient()
        self.replica_client = ReplicaClient()
        self.base_client = BaseClient(account='root',
                                      ca_cert=config_get('client', 'ca_cert'),
                                      auth_type='x509')
        self.token = self.base_client.headers['X-Rucio-Auth-Token']

        self.fname = generate_uuid()

        rses = ['MOCK', 'MOCK3', 'MOCK4']
        dsn = generate_uuid()
        self.files = [{'scope': 'mock', 'name': self.fname, 'bytes': 1L, 'adler32': '0cc737eb'}]

        self.did_client.add_dataset(scope='mock', name=dsn)
        self.did_client.add_files_to_dataset('mock', name=dsn, files=self.files, rse='MOCK')
        for r in rses:
            self.replica_client.add_replicas(r, self.files)

    def test_list_replicas_metalink_3(self):
        """ REPLICA (METALINK): List replicas as metalink version 3 """
        ml = xmltodict.parse(self.replica_client.list_replicas(self.files,
                                                               metalink=3,
                                                               unavailable=True,
                                                               schemes=['https', 'sftp', 'file']),
                             xml_attribs=False)
        assert_equal(3, len(ml['metalink']['files']['file']['resources']['url']))

    def test_list_replicas_metalink_4(self):
        """ REPLICA (METALINK): List replicas as metalink version 4 """
        ml = xmltodict.parse(self.replica_client.list_replicas(self.files,
                                                               metalink=4,
                                                               unavailable=True,
                                                               schemes=['https', 'sftp', 'file']),
                             xml_attribs=False)
        assert_equal(3, len(ml['metalink']['file']['url']))

    def test_get_did_from_pfns_nondeterministic(self):
        """ REPLICA (CLIENT): Get list of DIDs associated to PFNs for non-deterministic sites"""
        rse = 'MOCK2'
        tmp_scope = 'mock'
        nbfiles = 3
        pfns = []
        input = {}
        rse_info = rsemgr.get_rse_info(rse)
        assert_equal(rse_info['deterministic'], False)
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for i in xrange(nbfiles)]
        for f in files:
            input[f['pfn']] = {'scope': f['scope'], 'name': f['name']}
        add_replicas(rse=rse, files=files, account='root', ignore_availability=True)
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm'], ignore_availability=True):
            for rse in replica['rses']:
                pfns.extend(replica['rses'][rse])
        for result in self.replica_client.get_did_from_pfns(pfns, rse):
            pfn = result.keys()[0]
            assert_equal(input[pfn], result.values()[0])

    def test_get_did_from_pfns_deterministic(self):
        """ REPLICA (CLIENT): Get list of DIDs associated to PFNs for deterministic sites"""
        tmp_scope = 'mock'
        rse = 'MOCK3'
        nbfiles = 3
        pfns = []
        input = {}
        rse_info = rsemgr.get_rse_info(rse)
        assert_equal(rse_info['deterministic'], True)
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1L, 'adler32': '0cc737eb', 'meta': {'events': 10}} for i in xrange(nbfiles)]
        p = rsemgr.create_protocol(rse_info, 'read', scheme='srm')
        for f in files:
            pfn = p.lfns2pfns(lfns={'scope': f['scope'], 'name': f['name']}).values()[0]
            pfns.append(pfn)
            input[pfn] = {'scope': f['scope'], 'name': f['name']}
        add_replicas(rse=rse, files=files, account='root', ignore_availability=True)
        for result in self.replica_client.get_did_from_pfns(pfns, rse):
            pfn = result.keys()[0]
            assert_equal(input[pfn], result.values()[0])
