# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2013-2017
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013-2014
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2019
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019

from __future__ import print_function
from datetime import datetime, timedelta
from json import dumps, loads

import xmltodict

from nose.tools import assert_equal, assert_in, assert_raises
from paste.fixture import TestApp


from rucio.db.sqla.constants import DIDType, ReplicaState, OBSOLETE
from rucio.client.baseclient import BaseClient
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.common.config import config_get
from rucio.common.utils import generate_uuid, clean_surls
from rucio.common.exception import (DataIdentifierNotFound, AccessDenied, UnsupportedOperation,
                                    RucioException, ReplicaIsLocked, ReplicaNotFound)
from rucio.core.did import add_did, attach_dids, get_did, set_status, list_files, get_did_atime
from rucio.core.replica import (add_replica, add_replicas, delete_replicas, get_replicas_state,
                                update_replica_lock_counter, get_replica, list_replicas,
                                declare_bad_file_replicas, list_bad_replicas,
                                update_replicas_paths, update_replica_state,
                                get_replica_atime, touch_replica, get_bad_pfns, set_tombstone)
from rucio.core.rse import add_rse, add_protocol, add_rse_attribute, del_rse_attribute
from rucio.client.ruleclient import RuleClient
from rucio.daemons.badreplicas.necromancer import run as necromancer_run
from rucio.daemons.badreplicas.minos import run as minos_run
from rucio.daemons.badreplicas.minos_temporary_expiration import run as minos_temp_run
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import execute, rse_name_generator
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
                  'bytes': 1,
                  'adler32': '0cc737eb',
                  'meta': {'events': 10},
                  'rse_id': rse_info['id'],
                  'path': '/does/not/really/matter/where'} for _ in range(nbfiles)]
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
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
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
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
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
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        rses = ['MOCK', 'MOCK3']
        for rse in rses:
            add_replicas(rse=rse, files=files, account='root', ignore_availability=True)

        replica_cpt = 0
        for _ in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replica_cpt += 1

        assert_equal(nbfiles, replica_cpt)

    def test_delete_replicas(self):
        """ REPLICA (CORE): Delete replicas """
        tmp_scope = 'mock'
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        add_replicas(rse='MOCK', files=files1, account='root', ignore_availability=True)

        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        add_replicas(rse='MOCK', files=files2, account='root', ignore_availability=True)
        add_replicas(rse='MOCK3', files=files2, account='root', ignore_availability=True)

        delete_replicas(rse='MOCK', files=files1 + files2)

        for file in files1:
            with assert_raises(DataIdentifierNotFound):
                print(get_did(scope=file['scope'], name=file['name']))

        for file in files2:
            get_did(scope=file['scope'], name=file['name'])

    def test_delete_replicas_from_datasets(self):
        """ REPLICA (CORE): Delete replicas from dataset """
        tmp_scope = 'mock'
        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]

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
        add_replica(rse=rse, scope=tmp_scope, name=tmp_file, bytes=1, adler32='0cc737eb', account='jdoe')

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
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
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
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
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

    def test_list_replica_with_domain(self):
        """ REPLICA (CORE): Add and list file replicas forcing domain"""

        tmp_rse = rse_name_generator()
        add_rse(tmp_rse)

        protocols = [{'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 17,
                      'prefix': '/i/prefer/the/lan',
                      'impl': 'rucio.rse.protocols.mock.Default',
                      'domains': {
                          'lan': {'read': 1,
                                  'write': 1,
                                  'delete': 1},
                          'wan': {'read': 2,
                                  'write': 2,
                                  'delete': 2}}},
                     {'scheme': 'MOCK',
                      'hostname': 'localhost',
                      'port': 18,
                      'prefix': '/i/prefer/the/wan',
                      'impl': 'rucio.rse.protocols.mock.Default',
                      'domains': {
                          'lan': {'read': 2,
                                  'write': 2,
                                  'delete': 2},
                          'wan': {'read': 1,
                                  'write': 1,
                                  'delete': 1}}}, ]
        for p in protocols:
            add_protocol(tmp_rse, p)

        nbfiles = 3
        files = [{'scope': 'mock',
                  'name': 'file_%s' % generate_uuid(),
                  'bytes': 1234,
                  'adler32': '01234567',
                  'meta': {'events': 1234}} for _ in range(nbfiles)]

        add_replicas(rse=tmp_rse, files=files, account='root', ignore_availability=True)

        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'],
                                     domain='wan'):
            assert_in('/i/prefer/the/wan', replica['pfns'].keys()[0])

        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'],
                                     domain='lan'):
            assert_in('/i/prefer/the/lan', replica['pfns'].keys()[0])

        # test old client behaviour - get all WAN answers
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK']):
            cmd = 'rucio list-file-replicas --pfns %s:%s' % (replica['scope'], replica['name'])
            _, stdout, _ = execute(cmd)
            assert_in('/i/prefer/the/wan', stdout)

        # # force all LAN
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'], domain='lan'):
            cmd = 'rucio list-file-replicas --pfns --domain=lan %s:%s' % (replica['scope'], replica['name'])
            errno, stdout, stderr = execute(cmd)
            assert_in('/i/prefer/the/lan', stdout)

        # # force all WAN
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'], domain='wan'):
            cmd = 'rucio list-file-replicas --pfns --domain=wan %s:%s' % (replica['scope'], replica['name'])
            errno, stdout, stderr = execute(cmd)
            assert_in('/i/prefer/the/wan', stdout)

        # # force both WAN and LAN
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'], domain='all'):
            cmd = 'rucio list-file-replicas --pfns --domain=all %s:%s' % (replica['scope'], replica['name'])
            errno, stdout, stderr = execute(cmd)
            assert_in('/i/prefer/the/wan', stdout)
            assert_in('/i/prefer/the/lan', stdout)

    def test_list_replica_with_schemes(self):
        """ REPLICA (CORE): Add and list file replicas forcing schemes"""

        rc = ReplicaClient()

        rse = 'APERTURE_%s' % rse_name_generator()
        add_rse(rse)

        add_protocol(rse, {'scheme': 'http',
                           'hostname': 'http.aperture.com',
                           'port': 80,
                           'prefix': '//test/chamber/',
                           'impl': 'rucio.rse.protocols.gfalv2.Default',
                           'domains': {
                               'lan': {'read': 1, 'write': 1, 'delete': 1},
                               'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        scope = 'mock'
        name = 'element_%s' % generate_uuid()
        file_item = {'scope': scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef'}

        add_replicas(rse=rse, files=[file_item], account='root')

        replicas = list(rc.list_replicas([{'scope': scope, 'name': name}]))
        assert_in('http://', replicas[0]['pfns'].keys()[0])

    def test_replica_no_site(self):
        """ REPLICA (CORE): Test listing replicas without site attribute """

        rc = ReplicaClient()

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

        add_rse_attribute(rse=rse, key='site', value='APERTURE')

        files = [{'scope': 'mock', 'name': 'element_%s' % generate_uuid(),
                  'bytes': 1234, 'adler32': 'deadbeef'}]
        add_replicas(rse=rse, files=files, account='root')

        replicas = [r for r in rc.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files])]
        assert_in('root://', replicas[0]['pfns'].keys()[0])

        replicas = [r for r in rc.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files],
                                                client_location={'site': 'SOMEWHERE'})]
        assert_in('root://', replicas[0]['pfns'].keys()[0])

        del_rse_attribute(rse=rse, key='site')

        replicas = [r for r in rc.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files])]
        assert_in('root://', replicas[0]['pfns'].keys()[0])

        replicas = [r for r in rc.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files],
                                                client_location={'site': 'SOMEWHERE'})]
        assert_in('root://', replicas[0]['pfns'].keys()[0])

    def test_set_tombstone(self):
        """ REPLICA (CORE): set tombstone on replica """
        # Set tombstone on one replica
        rse = 'MOCK4'
        scope = 'mock'
        user = 'root'
        name = generate_uuid()
        add_replica(rse, scope, name, 4, user)
        assert_equal(get_replica(rse, scope, name)['tombstone'], None)
        set_tombstone(rse, scope, name)
        assert_equal(get_replica(rse, scope, name)['tombstone'], OBSOLETE)

        # Set tombstone on locked replica
        name = generate_uuid()
        add_replica(rse, scope, name, 4, user)
        RuleClient().add_replication_rule([{'name': name, 'scope': scope}], 1, rse, locked=True)
        with assert_raises(ReplicaIsLocked):
            set_tombstone(rse, scope, name)

        # Set tombstone on not found replica
        name = generate_uuid()
        with assert_raises(ReplicaNotFound):
            set_tombstone(rse, scope, name)


class TestReplicaClients:

    def setup(self):
        self.replica_client = ReplicaClient()
        self.did_client = DIDClient()

    def test_add_list_bad_replicas(self):
        """ REPLICA (CLIENT): Add bad replicas"""
        tmp_scope = 'mock'
        nbfiles = 5
        # Adding replicas to deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
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
        necromancer_run(threads=1, bulk=10000, once=True)

        # Try to attach a lost file
        tmp_dsn = 'dataset_%s' % generate_uuid()
        self.did_client.add_dataset(scope=tmp_scope, name=tmp_dsn)
        with assert_raises(UnsupportedOperation):
            self.did_client.add_files_to_dataset(tmp_scope, name=tmp_dsn, files=files, rse='MOCK')

        # Adding replicas to non-deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
        rse_info = rsemgr.get_rse_info('MOCK2')
        rse_id2 = rse_info['id']
        self.replica_client.add_replicas(rse='MOCK2', files=files)

        # Listing replicas on non-deterministic RSE
        replicas, list_rep = [], []
        for replica in self.replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
            replicas.extend(replica['rses']['MOCK2'])
            list_rep.append(replica)
        print(replicas, list_rep)
        r = self.replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
        print(r)
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
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
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
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
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
        result = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(result.status, 200)
        token = str(result.header('X-Rucio-Auth-Token'))
        headers2 = {'X-Rucio-Auth-Token': str(token)}

        data = dumps({})
        result = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(result.status, 200)
        tot_files = []
        for line in result.body.split('\n'):
            if line != '':
                tot_files.append(dumps(line))
        nb_tot_files = len(tot_files)

        data = dumps({'state': 'B'})
        result = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(result.status, 200)
        tot_bad_files = []
        for line in result.body.split('\n'):
            if line != '':
                tot_bad_files.append(dumps(line))
        nb_tot_bad_files1 = len(tot_bad_files)

        data = dumps({'state': 'S', 'list_pfns': 'True'})
        result = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(result.status, 200)
        tot_suspicious_files = []
        for line in result.body.split('\n'):
            if line != '':
                tot_suspicious_files.append(dumps(line))
        nb_tot_suspicious_files = len(tot_suspicious_files)

        data = dumps({'state': 'T', 'list_pfns': 'True'})
        result = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(result.status, 200)
        tot_temporary_unavailable_files = []
        for line in result.body.split('\n'):
            if line != '':
                tot_temporary_unavailable_files.append(dumps(line))
        nb_tot_temporary_unavailable_files = len(tot_temporary_unavailable_files)

        assert_equal(nb_tot_files, nb_tot_bad_files1 + nb_tot_suspicious_files + nb_tot_temporary_unavailable_files)

        tomorrow = datetime.utcnow() + timedelta(days=1)
        data = dumps({'state': 'B', 'younger_than': tomorrow.isoformat()})
        result = TestApp(rep_app.wsgifunc(*mw)).get('/bad/states', headers=headers2, params=data, expect_errors=True)
        assert_equal(result.status, 200)
        tot_bad_files = []
        for line in result.body.split('\n'):
            if line != '':
                tot_bad_files.append(dumps(line))
        nb_tot_bad_files = len(tot_bad_files)
        assert_equal(nb_tot_bad_files, 0)

        data = dumps({})
        result = TestApp(rep_app.wsgifunc(*mw)).get('/bad/summary', headers=headers2, params=data, expect_errors=True)
        assert_equal(result.status, 200)
        nb_tot_bad_files2 = 0
        for line in result.body.split('\n'):
            if line != '':
                line = loads(line)
                nb_tot_bad_files2 += int(line.get('BAD', 0))
        assert_equal(nb_tot_bad_files1, nb_tot_bad_files2)

    def test_list_replicas_content_type(self):
        """ REPLICA (REST): send a GET to list replicas with specific ACCEPT header."""
        mw = []
        account = 'root'
        headers1 = {'X-Rucio-Account': account, 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)
        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))
        scope = 'mock'
        name = 'file_%s' % generate_uuid()
        files1 = [{'scope': scope, 'name': name, 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}}]
        self.replica_client.add_replicas(rse='MOCK', files=files1)

        # unsupported requested content type
        headers = {'X-Rucio-Auth-Token': str(token), 'Accept': 'application/unsupported'}
        res = TestApp(rep_app.wsgifunc(*mw)).get('/%s/%s' % (scope, name), headers=headers, expect_errors=True)
        assert_equal(res.status, 406)

        # content type json stream
        headers = {'X-Rucio-Auth-Token': str(token), 'Accept': 'application/x-json-stream'}
        res = TestApp(rep_app.wsgifunc(*mw)).get('/%s/%s' % (scope, name), headers=headers, expect_errors=True)
        assert_equal([header[1] for header in res.headers if header[0] == 'Content-Type'][0], 'application/x-json-stream')

        # content type metalink4
        headers = {'X-Rucio-Auth-Token': str(token), 'Accept': 'application/metalink4+xml'}
        res = TestApp(rep_app.wsgifunc(*mw)).get('/%s/%s' % (scope, name), headers=headers, expect_errors=True)
        assert_equal([header[1] for header in res.headers if header[0] == 'Content-Type'][0], 'application/metalink4+xml')

        # no requested content type
        headers = {'X-Rucio-Auth-Token': str(token)}
        res = TestApp(rep_app.wsgifunc(*mw)).get('/%s/%s' % (scope, name), headers=headers, expect_errors=True)
        assert_equal([header[1] for header in res.headers if header[0] == 'Content-Type'][0], 'application/x-json-stream')

        # all content types
        headers = {'X-Rucio-Auth-Token': str(token), 'Accept': '*/*'}
        res = TestApp(rep_app.wsgifunc(*mw)).get('/%s/%s' % (scope, name), headers=headers, expect_errors=True)
        assert_equal([header[1] for header in res.headers if header[0] == 'Content-Type'][0], 'application/x-json-stream')

        # multiple content types
        headers = {'X-Rucio-Auth-Token': str(token), 'Accept': 'application/unsupported, application/x-json-stream'}
        res = TestApp(rep_app.wsgifunc(*mw)).get('/%s/%s' % (scope, name), headers=headers, expect_errors=True)
        assert_equal([header[1] for header in res.headers if header[0] == 'Content-Type'][0], 'application/x-json-stream')
        headers = {'X-Rucio-Auth-Token': str(token), 'Accept': 'application/unsupported, */*;q=0.8'}
        res = TestApp(rep_app.wsgifunc(*mw)).get('/%s/%s' % (scope, name), headers=headers, expect_errors=True)
        assert_equal([header[1] for header in res.headers if header[0] == 'Content-Type'][0], 'application/x-json-stream')

    def test_add_list_replicas(self):
        """ REPLICA (CLIENT): Add, change state and list file replicas """
        tmp_scope = 'mock'
        nbfiles = 5

        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK', files=files1)

        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK3', files=files2)

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files1])]
        assert_equal(len(replicas), len(files1))

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['file'])]
        assert_equal(len(replicas), 5)

        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['srm'])]
        assert_equal(len(replicas), 5)

        files3 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'state': 'U', 'meta': {'events': 10}} for _ in range(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK3', files=files3)
        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files3], schemes=['file'])]
        for i in range(nbfiles):
            assert_equal(replicas[i]['rses'], {})
        files4 = []
        for file in files3:
            file['state'] = 'A'
            files4.append(file)
        self.replica_client.update_replicas_states('MOCK3', files=files4)
        replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files3], schemes=['file'], unavailable=True)]
        assert_equal(len(replicas), 5)
        for i in range(nbfiles):
            assert_in('MOCK3', replicas[i]['rses'])

    def test_delete_replicas(self):
        """ REPLICA (CLIENT): Add and delete file replicas """
        tmp_scope = 'mock'
        nbfiles = 5
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK', files=files)
        with assert_raises(AccessDenied):
            self.replica_client.delete_replicas(rse='MOCK', files=files)

        # replicas = [r for r in self.replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files])]
        # assert_equal(len(replicas), 0)

    def test_add_temporary_unavailable_pfns(self):
        """ REPLICA (CLIENT): Add temporary unavailable PFNs"""
        tmp_scope = 'mock'
        nbfiles = 5
        # Adding replicas to deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        self.replica_client.add_replicas(rse='MOCK', files=files)

        # Listing replicas on deterministic RSE
        list_rep = []
        for replica in self.replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
            pfn = replica['pfns'].keys()[0]
            list_rep.append(pfn)

        # Submit bad PFNs
        now = datetime.utcnow()
        reason_str = generate_uuid()
        self.replica_client.add_bad_pfns(pfns=list_rep, reason=str(reason_str), state='TEMPORARY_UNAVAILABLE', expires_at=now.isoformat())
        result = get_bad_pfns(limit=10000, thread=None, total_threads=None, session=None)
        bad_pfns = {}
        for res in result:
            bad_pfns[res['pfn']] = (res['state'], res['reason'], res['expires_at'])

        for pfn in list_rep:
            pfn = str(clean_surls([pfn])[0])
            assert_in(pfn, bad_pfns)
            assert_equal(str(bad_pfns[pfn][0]), 'TEMPORARY_UNAVAILABLE')
            assert_equal(bad_pfns[pfn][1], reason_str)

        # Submit with wrong state
        with assert_raises(RucioException):
            self.replica_client.add_bad_pfns(pfns=list_rep, reason=str(reason_str), state='BADSTATE', expires_at=now.isoformat())

        # Run minos once
        minos_run(threads=1, bulk=10000, once=True)
        result = get_bad_pfns(limit=10000, thread=None, total_threads=None, session=None)
        pfns = [res['pfn'] for res in result]
        res_pfns = []
        for replica in list_rep:
            if replica in pfns:
                res_pfns.append(replica)
        assert_equal(res_pfns, [])

        # Check the state in the replica table
        for did in files:
            rep = get_replicas_state(scope=did['scope'], name=did['name'])
            assert_equal(str(rep.keys()[0]), 'TEMPORARY_UNAVAILABLE')

        rep = []
        for did in files:
            did['state'] = ReplicaState.from_sym('TEMPORARY_UNAVAILABLE')
            rep.append(did)

        # Run the minos expiration
        minos_temp_run(threads=1, once=True)
        # Check the state in the replica table
        for did in files:
            rep = get_replicas_state(scope=did['scope'], name=did['name'])
            assert_equal(str(rep.keys()[0]), 'AVAILABLE')

    def test_set_tombstone(self):
        """ REPLICA (CLIENT): set tombstone on replica """
        # Set tombstone on one replica
        rse = 'MOCK4'
        scope = 'mock'
        user = 'root'
        name = generate_uuid()
        add_replica(rse, scope, name, 4, user)
        assert_equal(get_replica(rse, scope, name)['tombstone'], None)
        self.replica_client.set_tombstone([{'rse': rse, 'scope': scope, 'name': name}])
        assert_equal(get_replica(rse, scope, name)['tombstone'], OBSOLETE)

        # Set tombstone on locked replica
        name = generate_uuid()
        add_replica(rse, scope, name, 4, user)
        RuleClient().add_replication_rule([{'name': name, 'scope': scope}], 1, rse, locked=True)
        with assert_raises(ReplicaIsLocked):
            self.replica_client.set_tombstone([{'rse': rse, 'scope': scope, 'name': name}])

        # Set tombstone on not found replica
        name = generate_uuid()
        with assert_raises(ReplicaNotFound):
            self.replica_client.set_tombstone([{'rse': rse, 'scope': scope, 'name': name}])


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
        self.files = [{'scope': 'mock', 'name': self.fname, 'bytes': 1, 'adler32': '0cc737eb'}]

        self.did_client.add_dataset(scope='mock', name=dsn)
        self.did_client.add_files_to_dataset('mock', name=dsn, files=self.files, rse='MOCK')
        for r in rses:
            self.replica_client.add_replicas(r, self.files)

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
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
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
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        p = rsemgr.create_protocol(rse_info, 'read', scheme='srm')
        for f in files:
            pfn = p.lfns2pfns(lfns={'scope': f['scope'], 'name': f['name']}).values()[0]
            pfns.append(pfn)
            input[pfn] = {'scope': f['scope'], 'name': f['name']}
        add_replicas(rse=rse, files=files, account='root', ignore_availability=True)
        for result in self.replica_client.get_did_from_pfns(pfns, rse):
            pfn = result.keys()[0]
            assert_equal(input[pfn], result.values()[0])
