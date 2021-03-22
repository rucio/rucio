# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013-2014
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2019
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Tobias Wegner <twegner@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Luc Goossens <luc.goossens@cern.ch>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Ilija Vukotic <ivukotic@uchicago.edu>, 2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from __future__ import print_function
import hashlib
import os
import sys
import time
import unittest
from datetime import datetime, timedelta
from json import dumps, loads
from xml.etree import ElementTree
import pytest
import xmltodict
from werkzeug.datastructures import MultiDict
from rucio.client.baseclient import BaseClient
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.ruleclient import RuleClient
from rucio.core.config import set as cconfig_set
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import (DataIdentifierNotFound, AccessDenied, UnsupportedOperation,
                                    RucioException, ReplicaIsLocked, ReplicaNotFound, ScopeNotFound,
                                    DatabaseException)
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid, clean_surls, parse_response
from rucio.core.did import add_did, attach_dids, get_did, set_status, list_files, get_did_atime
from rucio.core.replica import (add_replica, add_replicas, delete_replicas, get_replicas_state,
                                update_replica_lock_counter, get_replica, list_replicas,
                                declare_bad_file_replicas, list_bad_replicas,
                                update_replicas_paths, update_replica_state, get_RSEcoverage_of_dataset,
                                get_replica_atime, touch_replica, get_bad_pfns, set_tombstone)
from rucio.core.rse import add_rse, add_protocol, add_rse_attribute, del_rse_attribute, get_rse_id
from rucio.daemons.badreplicas.minos import run as minos_run
from rucio.daemons.badreplicas.minos_temporary_expiration import run as minos_temp_run
from rucio.daemons.badreplicas.necromancer import run as necromancer_run
from rucio.db.sqla.constants import DIDType, ReplicaState, BadPFNStatus, OBSOLETE
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import execute, rse_name_generator, headers, auth, Mime, accept


if sys.version_info >= (3, 3):
    from unittest import mock
else:
    import mock

# This method will be used by the mock to replace requests.get to VP server


def mocked_VP_requests_get(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.ok = True

        def json(self):
            return self.json_data

    if args[0] == 'https://vps-mock.cern.ch/serverRanges':
        return MockResponse({
            "AGLT2": {
                "servers": [
                    ["192.41.231.239:1094", "100"],
                    ["192.41.230.42:1094", "100"],
                    ["192.41.230.43:1094", "100"]
                ],
                "ranges": [
                    [1, 0.3333],
                    [2, 0.6666],
                    [0, 1]
                ]
            }}, 200)
    if args[0] == 'https://vps-mock.cern.ch/ds/4/scope:name':
        return MockResponse(["AGLT2_VP_DISK", "MWT2_VP_DISK", "NET2_VP_DISK"], 200)

    return MockResponse(None, 404)


class TestReplicaCore(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

    @mock.patch('rucio.core.replica.requests.get', side_effect=mocked_VP_requests_get)
    def test_cache_replicas(self, mock_get):
        """ REPLICA (CORE): Test listing replicas with cached root protocol """

        rse = 'APERTURE_%s' % rse_name_generator()
        rse_id = add_rse(rse, **self.vo)

        add_protocol(rse_id, {'scheme': 'root',
                              'hostname': 'root.aperture.com',
                              'port': 1409,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.xrootd.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})
        add_protocol(rse_id, {'scheme': 'http',
                              'hostname': 'root.aperture.com',
                              'port': 1409,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.xrootd.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)

        files = []

        name = 'file_%s' % generate_uuid()
        hstr = hashlib.md5(('%s:%s' % (tmp_scope, name)).encode('utf-8')).hexdigest()
        pfn = 'root://root.aperture.com:1409//test/chamber/mock/%s/%s/%s' % (hstr[0:2], hstr[2:4], name)
        files.append({'scope': tmp_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef', 'pfn': pfn})

        name = 'element_%s' % generate_uuid()
        hstr = hashlib.md5(('%s:%s' % (tmp_scope, name)).encode('utf-8')).hexdigest()
        pfn = 'http://root.aperture.com:1409//test/chamber/mock/%s/%s/%s' % (hstr[0:2], hstr[2:4], name)
        files.append({'scope': tmp_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef', 'pfn': pfn})

        add_replicas(rse_id=rse_id, files=files, account=root)

        cconfig_set('clientcachemap', 'BLACKMESA', 'AGLT2')
        cconfig_set('virtual_placement', 'vp_endpoint', 'https://vps-mock.cern.ch')

        for rep in list_replicas(
                dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                schemes=['root'],
                domain='wan',
                client_location={'site': 'BLACKMESA'}):
            assert list(rep['pfns'].keys())[0].count('root://') == 2

        for rep in list_replicas(
                dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                schemes=['root'],
                domain='wan',
                client_location={'site': rse}):
            assert list(rep['pfns'].keys())[0].count('root://') == 1

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_update_replicas_paths(self):
        """ REPLICA (CORE): Force update the replica path """
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        nbfiles = 5
        rse_id = get_rse_id(rse='MOCK', **self.vo)
        rse_id2 = get_rse_id(rse='MOCK2', **self.vo)
        files = [{'scope': tmp_scope,
                  'name': 'file_%s' % generate_uuid(),
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/does/not/really/matter/where',
                  'bytes': 1,
                  'adler32': '0cc737eb',
                  'meta': {'events': 10},
                  'rse_id': rse_id,
                  'path': '/does/not/really/matter/where'} for _ in range(nbfiles)]
        add_replicas(rse_id=rse_id2, files=files, account=root, ignore_availability=True)
        update_replicas_paths(files)
        for replica in list_replicas(dids=[{'scope': f['scope'],
                                            'name': f['name'],
                                            'type': DIDType.FILE} for f in files],
                                     schemes=['srm']):
            # force the changed string - if we look it up from the DB, then we're not testing anything :-D
            assert replica['rses'][rse_id2][0] == 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/does/not/really/matter/where'

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_add_list_bad_replicas(self):
        """ REPLICA (CORE): Add bad replicas and list them"""
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        nbfiles = 5
        # Adding replicas to deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        rse_id1 = get_rse_id(rse='MOCK', **self.vo)
        add_replicas(rse_id=rse_id1, files=files, account=root, ignore_availability=True)

        # Listing replicas on deterministic RSE
        replicas = []
        list_rep = []
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replicas.extend(replica['rses'][rse_id1])
            list_rep.append(replica)
        r = declare_bad_file_replicas(replicas, 'This is a good reason', root)
        assert r == {}
        bad_replicas = list_bad_replicas()
        nbbadrep = 0
        for rep in list_rep:
            for badrep in bad_replicas:
                if badrep['rse_id'] == rse_id1:
                    if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                        nbbadrep += 1
        assert len(replicas) == nbbadrep

        # Adding replicas to non-deterministic RSE
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
        rse_id2 = get_rse_id(rse='MOCK2', **self.vo)
        add_replicas(rse_id=rse_id2, files=files, account=root, ignore_availability=True)

        # Listing replicas on non-deterministic RSE
        replicas = []
        list_rep = []
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replicas.extend(replica['rses'][rse_id2])
            list_rep.append(replica)
        r = declare_bad_file_replicas(replicas, 'This is a good reason', root)
        assert r == {}
        bad_replicas = list_bad_replicas()
        nbbadrep = 0
        for rep in list_rep:
            for badrep in bad_replicas:
                if badrep['rse_id'] == rse_id2:
                    if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                        nbbadrep += 1
        assert len(replicas) == nbbadrep

        # Now adding non-existing bad replicas
        files = ['srm://mock2.com/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), ]
        r = declare_bad_file_replicas(files, 'This is a good reason', root)
        output = ['%s Unknown replica' % rep for rep in files]
        assert r == {rse_id2: output}

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_add_list_replicas(self):
        """ REPLICA (CORE): Add and list file replicas """
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        nbfiles = 13
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        rses = ['MOCK', 'MOCK3']
        for rse in rses:
            rse_id = get_rse_id(rse=rse, **self.vo)
            add_replicas(rse_id=rse_id, files=files, account=root, ignore_availability=True)

        replica_cpt = 0
        for _ in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replica_cpt += 1

        assert nbfiles == replica_cpt

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_delete_replicas(self):
        """ REPLICA (CORE): Delete replicas """
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        rse_id1 = get_rse_id(rse='MOCK', **self.vo)
        rse_id2 = get_rse_id(rse='MOCK3', **self.vo)

        add_replicas(rse_id=rse_id1, files=files1, account=root, ignore_availability=True)

        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        add_replicas(rse_id=rse_id1, files=files2, account=root, ignore_availability=True)
        add_replicas(rse_id=rse_id2, files=files2, account=root, ignore_availability=True)

        delete_replicas(rse_id=rse_id1, files=files1 + files2)

        for file in files1:
            with pytest.raises(DataIdentifierNotFound):
                print(get_did(scope=file['scope'], name=file['name']))

        for file in files2:
            get_did(scope=file['scope'], name=file['name'])

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_delete_replicas_from_datasets(self):
        """ REPLICA (CORE): Delete replicas from dataset """
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        rse_id = get_rse_id(rse='MOCK', **self.vo)

        add_did(scope=tmp_scope, name=tmp_dsn1, type=DIDType.DATASET, account=root)
        add_did(scope=tmp_scope, name=tmp_dsn2, type=DIDType.DATASET, account=root)

        attach_dids(scope=tmp_scope, name=tmp_dsn1, rse_id=rse_id, dids=files1, account=root)
        attach_dids(scope=tmp_scope, name=tmp_dsn2, dids=files1, account=root)

        set_status(scope=tmp_scope, name=tmp_dsn1, open=False)

        delete_replicas(rse_id=rse_id, files=files1)

        with pytest.raises(DataIdentifierNotFound):
            get_did(scope=tmp_scope, name=tmp_dsn1)

        get_did(scope=tmp_scope, name=tmp_dsn2)

        assert [f for f in list_files(scope=tmp_scope, name=tmp_dsn2)] == []

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_update_lock_counter(self):
        """ RSE (CORE): Test the update of a replica lock counter """
        rse = 'MOCK'
        rse_id = get_rse_id(rse=rse, **self.vo)

        tmp_scope = InternalScope('mock', **self.vo)
        tmp_file = 'file_%s' % generate_uuid()
        add_replica(rse_id=rse_id, scope=tmp_scope, name=tmp_file, bytes=1, adler32='0cc737eb', account=InternalAccount('jdoe', **self.vo))

        values = (1, 1, 1, -1, -1, -1, 1, 1, -1)
        tombstones = (True, True, True, True, True, False, True, True, True)
        lock_counters = (1, 2, 3, 2, 1, 0, 1, 2, 1)
        for value, tombstone, lock_counter in zip(values, tombstones, lock_counters):
            status = update_replica_lock_counter(rse_id=rse_id, scope=tmp_scope, name=tmp_file, value=value)
            assert status is True
            replica = get_replica(rse_id=rse_id, scope=tmp_scope, name=tmp_file)
            value = replica['tombstone'] is None
            assert value is tombstone
            assert lock_counter == replica['lock_cnt']

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_touch_replicas(self):
        """ REPLICA (CORE): Touch replicas accessed_at timestamp"""
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        nbfiles = 5
        files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        files2.append(files1[0])
        rse_id = get_rse_id(rse='MOCK', **self.vo)

        add_replicas(rse_id=rse_id, files=files1, account=root, ignore_availability=True)
        add_replicas(rse_id=rse_id, files=files2, account=root, ignore_availability=True)

        now = datetime.utcnow()

        now -= timedelta(microseconds=now.microsecond)

        assert get_replica_atime({'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse_id': rse_id}) is None
        assert get_did_atime(scope=tmp_scope, name=files1[0]['name']) is None

        for r in [{'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse_id': rse_id, 'accessed_at': now}]:
            touch_replica(r)

        assert now == get_replica_atime({'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse_id': rse_id})
        assert now == get_did_atime(scope=tmp_scope, name=files1[0]['name'])

        for i in range(1, nbfiles):
            assert get_replica_atime({'scope': files1[i]['scope'], 'name': files1[i]['name'], 'rse_id': rse_id}) is None

        for i in range(0, nbfiles - 1):
            assert get_replica_atime({'scope': files2[i]['scope'], 'name': files2[i]['name'], 'rse_id': rse_id}) is None

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_list_replicas_all_states(self):
        """ REPLICA (CORE): list file replicas with all_states"""
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        nbfiles = 13
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        rses = [get_rse_id(rse='MOCK', **self.vo), get_rse_id(rse='MOCK3', **self.vo)]
        for rse_id in rses:
            add_replicas(rse_id=rse_id, files=files, account=root, ignore_availability=True)

        for file in files:
            update_replica_state(rses[0], tmp_scope, file['name'], ReplicaState.COPYING)

        replica_cpt = 0
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm'], all_states=True):
            assert 'states' in replica
            assert replica['states'][rses[0]] == str(ReplicaState.COPYING.name)
            assert replica['states'][rses[1]] == str(ReplicaState.AVAILABLE.name)
            replica_cpt += 1

        assert nbfiles == replica_cpt

    @pytest.mark.dirty
    def test_list_replica_with_domain(self):
        """ REPLICA (CORE): Add and list file replicas forcing domain"""

        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)

        tmp_rse = rse_name_generator()
        tmp_rse_id = add_rse(tmp_rse, **self.vo)

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
            add_protocol(tmp_rse_id, p)

        nbfiles = 3
        files = [{'scope': tmp_scope,
                  'name': 'file_%s' % generate_uuid(),
                  'bytes': 1234,
                  'adler32': '01234567',
                  'meta': {'events': 1234}} for _ in range(nbfiles)]

        add_replicas(rse_id=tmp_rse_id, files=files, account=root, ignore_availability=True)

        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'],
                                     domain='wan'):
            assert '/i/prefer/the/wan' in list(replica['pfns'].keys())[0]
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'],
                                     domain='lan'):
            assert '/i/prefer/the/lan' in list(replica['pfns'].keys())[0]
        # test old client behaviour - get all WAN answers
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK']):
            cmd = 'rucio list-file-replicas --pfns %s:%s' % (replica['scope'], replica['name'])
            _, stdout, _ = execute(cmd)
            assert '/i/prefer/the/wan' in stdout

        # # force all LAN
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'], domain='lan'):
            cmd = 'rucio list-file-replicas --pfns --domain=lan %s:%s' % (replica['scope'], replica['name'])
            errno, stdout, stderr = execute(cmd)
            assert '/i/prefer/the/lan' in stdout

        # # force all WAN
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'], domain='wan'):
            cmd = 'rucio list-file-replicas --pfns --domain=wan %s:%s' % (replica['scope'], replica['name'])
            errno, stdout, stderr = execute(cmd)
            assert '/i/prefer/the/wan' in stdout

        # # force both WAN and LAN
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files],
                                     schemes=['MOCK'], domain='all'):
            cmd = 'rucio list-file-replicas --pfns --domain=all %s:%s' % (replica['scope'], replica['name'])
            errno, stdout, stderr = execute(cmd)
            assert '/i/prefer/the/wan' in stdout
            assert '/i/prefer/the/lan' in stdout

    @pytest.mark.dirty
    def test_list_replica_with_schemes(self):
        """ REPLICA (CORE): Add and list file replicas forcing schemes"""

        rc = ReplicaClient()

        rse = 'APERTURE_%s' % rse_name_generator()
        rse_id = add_rse(rse, **self.vo)

        add_protocol(rse_id, {'scheme': 'http',
                              'hostname': 'http.aperture.com',
                              'port': 80,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.gfalv2.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)

        name = 'element_%s' % generate_uuid()
        file_item = {'scope': scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef'}

        add_replicas(rse_id=rse_id, files=[file_item], account=root)

        replicas = list(rc.list_replicas([{'scope': scope.external, 'name': name}]))
        assert 'http://' in list(replicas[0]['pfns'].keys())[0]

    @pytest.mark.dirty
    def test_replica_no_site(self):
        """ REPLICA (CORE): Test listing replicas without site attribute """

        rc = ReplicaClient()

        rse = 'APERTURE_%s' % rse_name_generator()
        rse_id = add_rse(rse, **self.vo)

        add_protocol(rse_id, {'scheme': 'root',
                              'hostname': 'root.aperture.com',
                              'port': 1409,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.xrootd.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        add_rse_attribute(rse_id=rse_id, key='site', value='APERTURE')

        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)

        files = [{'scope': tmp_scope, 'name': 'element_%s' % generate_uuid(),
                  'bytes': 1234, 'adler32': 'deadbeef'}]
        add_replicas(rse_id=rse_id, files=files, account=root)

        replicas = [r for r in rc.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files])]
        assert 'root://' in list(replicas[0]['pfns'].keys())[0]
        replicas = [r for r in rc.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files],
                                                client_location={'site': 'SOMEWHERE'})]
        assert 'root://' in list(replicas[0]['pfns'].keys())[0]
        del_rse_attribute(rse_id=rse_id, key='site')

        replicas = [r for r in rc.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files])]
        assert 'root://' in list(replicas[0]['pfns'].keys())[0]
        replicas = [r for r in rc.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files],
                                                client_location={'site': 'SOMEWHERE'})]
        assert 'root://' in list(replicas[0]['pfns'].keys())[0]

    @pytest.mark.dirty
    def test_replica_mixed_protocols(self):
        """ REPLICA (CORE): Test adding replicas with mixed protocol """

        rse = 'APERTURE_%s' % rse_name_generator()
        rse_id = add_rse(rse, **self.vo)

        add_protocol(rse_id, {'scheme': 'root',
                              'hostname': 'root.aperture.com',
                              'port': 1409,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.xrootd.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})
        add_protocol(rse_id, {'scheme': 'http',
                              'hostname': 'root.aperture.com',
                              'port': 1409,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.xrootd.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)

        files = []

        name = 'element_%s' % generate_uuid()
        hstr = hashlib.md5(('%s:%s' % (tmp_scope, name)).encode('utf-8')).hexdigest()
        pfn = 'root://root.aperture.com:1409//test/chamber/mock/%s/%s/%s' % (hstr[0:2], hstr[2:4], name)
        files.append({'scope': tmp_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef', 'pfn': pfn})

        name = 'element_%s' % generate_uuid()
        hstr = hashlib.md5(('%s:%s' % (tmp_scope, name)).encode('utf-8')).hexdigest()
        pfn = 'http://root.aperture.com:1409//test/chamber/mock/%s/%s/%s' % (hstr[0:2], hstr[2:4], name)
        files.append({'scope': tmp_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef', 'pfn': pfn})

        add_replicas(rse_id=rse_id, files=files, account=root)

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_set_tombstone(self):
        """ REPLICA (CORE): set tombstone on replica """
        # Set tombstone on one replica
        rse = 'MOCK4'
        rse_id = get_rse_id(rse=rse, **self.vo)
        scope = InternalScope('mock', **self.vo)
        user = InternalAccount('root', **self.vo)
        name = generate_uuid()
        add_replica(rse_id, scope, name, 4, user)
        assert get_replica(rse_id, scope, name)['tombstone'] is None
        set_tombstone(rse_id, scope, name)
        assert get_replica(rse_id, scope, name)['tombstone'] == OBSOLETE

        # Set tombstone on locked replica
        name = generate_uuid()
        add_replica(rse_id, scope, name, 4, user)
        RuleClient().add_replication_rule([{'name': name, 'scope': scope.external}], 1, rse, locked=True)
        with pytest.raises(ReplicaIsLocked):
            set_tombstone(rse_id, scope, name)

        # Set tombstone on not found replica
        name = generate_uuid()
        with pytest.raises(ReplicaNotFound):
            set_tombstone(rse_id, scope, name)

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_list_replicas_with_updated_after(self):
        """ REPLICA (CORE): Add and list file replicas with updated_after filter """
        scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        mock = get_rse_id(rse='MOCK', **self.vo)
        dsn = 'ds_ua_test_%s' % generate_uuid()
        add_did(scope=scope, name=dsn, type='DATASET', account=root)
        #
        t0 = datetime.utcnow()
        time.sleep(2)
        lfn = '%s._%s.data' % (dsn, '0001')
        add_replica(rse_id=mock, scope=scope, name=lfn, bytes=12345, account=root)
        attach_dids(scope=scope, name=dsn, dids=[{'scope': scope, 'name': lfn}], account=root)
        time.sleep(2)
        t1 = datetime.utcnow()
        time.sleep(2)
        lfn = '%s._%s.data' % (dsn, '0002')
        add_replica(rse_id=mock, scope=scope, name=lfn, bytes=12345, account=root)
        attach_dids(scope=scope, name=dsn, dids=[{'scope': scope, 'name': lfn}], account=root)
        time.sleep(2)
        t2 = datetime.utcnow()
        time.sleep(2)
        lfn = '%s._%s.data' % (dsn, '0003')
        add_replica(rse_id=mock, scope=scope, name=lfn, bytes=12345, account=root)
        attach_dids(scope=scope, name=dsn, dids=[{'scope': scope, 'name': lfn}], account=root)
        time.sleep(2)
        t3 = datetime.utcnow()
        #
        assert len(list(list_replicas([{'scope': scope, 'name': dsn}], updated_after=None))) == 3
        assert len(list(list_replicas([{'scope': scope, 'name': dsn}], updated_after=t0))) == 3
        assert len(list(list_replicas([{'scope': scope, 'name': dsn}], updated_after=t1))) == 2
        assert len(list(list_replicas([{'scope': scope, 'name': dsn}], updated_after=t2))) == 1
        assert len(list(list_replicas([{'scope': scope, 'name': dsn}], updated_after=t3))) == 0

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_get_RSE_coverage_of_dataset(self):
        """ REPLICA (CORE): test RSE coverage retrieval """
        scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        mock1 = get_rse_id(rse='MOCK', **self.vo)
        mock3 = get_rse_id(rse='MOCK3', **self.vo)
        mock4 = get_rse_id(rse='MOCK4', **self.vo)
        dsn = 'ds_cov_test_%s' % generate_uuid()
        add_did(scope=scope, name=dsn, type='DATASET', account=root)

        # test empty dataset
        cov = get_RSEcoverage_of_dataset(scope=scope, name=dsn)
        print(cov)
        assert cov == {}
        # add files/replicas
        for i in range(1, 8):
            add_replica(rse_id=mock1, scope=scope, name=dsn + '_%06d.data' % i, bytes=100, account=root)
        for i in range(8, 11):
            add_replica(rse_id=mock3, scope=scope, name=dsn + '_%06d.data' % i, bytes=100, account=root)
        for i in range(11, 16):
            add_replica(rse_id=mock4, scope=scope, name=dsn + '_%06d.data' % i, bytes=100, account=root)

        attach_dids(scope=scope, name=dsn, dids=[{'scope': scope, 'name': dsn + '_%06d.data' % i} for i in range(1, 16)], account=root)
        cov = get_RSEcoverage_of_dataset(scope=scope, name=dsn)
        print(cov)
        assert cov[mock1] == 700
        assert cov[mock3] == 300
        assert cov[mock4] == 500


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_add_list_bad_replicas(vo, replica_client, did_client):
    """ REPLICA (CLIENT): Add bad replicas"""
    tmp_scope = 'mock'
    nbfiles = 5
    # Adding replicas to deterministic RSE
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    rse_id1 = get_rse_id('MOCK', vo=vo)
    replica_client.add_replicas(rse='MOCK', files=files)

    # Listing replicas on deterministic RSE
    replicas, list_rep = [], []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
        replicas.extend(replica['rses']['MOCK'])
        list_rep.append(replica)
    r = replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse_id1:
                if badrep['scope'].external == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # Run necromancer once
    necromancer_run(threads=1, bulk=10000, once=True)

    # Try to attach a lost file
    tmp_dsn = 'dataset_%s' % generate_uuid()
    did_client.add_dataset(scope=tmp_scope, name=tmp_dsn)
    with pytest.raises(UnsupportedOperation):
        did_client.add_files_to_dataset(tmp_scope, name=tmp_dsn, files=files, rse='MOCK')

    # Adding replicas to non-deterministic RSE
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
              'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
    rse_id2 = get_rse_id('MOCK2', vo=vo)
    replica_client.add_replicas(rse='MOCK2', files=files)

    # Listing replicas on non-deterministic RSE
    replicas, list_rep = [], []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
        replicas.extend(replica['rses']['MOCK2'])
        list_rep.append(replica)
    print(replicas, list_rep)
    r = replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
    print(r)
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse_id2:
                if badrep['scope'].external == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # Now adding non-existing bad replicas
    files = ['srm://mock2.com/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), ]
    r = replica_client.declare_bad_file_replicas(files, 'This is a good reason')
    output = ['%s Unknown replica' % rep for rep in files]
    assert r == {'MOCK2': output}


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_add_suspicious_replicas(replica_client):
    """ REPLICA (CLIENT): Add suspicious replicas"""
    tmp_scope = 'mock'
    nbfiles = 5
    # Adding replicas to deterministic RSE
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse='MOCK', files=files)

    # Listing replicas on deterministic RSE
    replicas = []
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
        replicas.extend(replica['rses']['MOCK'])
        list_rep.append(replica)
    r = replica_client.declare_suspicious_file_replicas(replicas, 'This is a good reason')
    assert r == {}
    # Adding replicas to non-deterministic RSE
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
              'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse='MOCK2', files=files)

    # Listing replicas on non-deterministic RSE
    replicas = []
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
        replicas.extend(replica['rses']['MOCK2'])
        list_rep.append(replica)
    r = replica_client.declare_suspicious_file_replicas(replicas, 'This is a good reason')
    assert r == {}
    # Now adding non-existing bad replicas
    files = ['srm://mock2.com/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), ]
    r = replica_client.declare_suspicious_file_replicas(files, 'This is a good reason')
    output = ['%s Unknown replica' % rep for rep in files]
    assert r == {'MOCK2': output}


@pytest.mark.noparallel(reason='fails when run in parallel')
def test_bad_replica_methods_for_UI(rest_client, auth_token):
    """ REPLICA (REST): Test the listing of bad and suspicious replicas """
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)))
    assert response.status_code == 200
    tot_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_files.append(dumps(line))
    nb_tot_files = len(tot_files)

    data = {'state': 'B'}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_bad_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_bad_files.append(dumps(line))
    nb_tot_bad_files1 = len(tot_bad_files)

    data = {'state': 'S', 'list_pfns': 'True'}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_suspicious_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_suspicious_files.append(dumps(line))
    nb_tot_suspicious_files = len(tot_suspicious_files)

    data = {'state': 'T', 'list_pfns': 'True'}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_temporary_unavailable_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_temporary_unavailable_files.append(dumps(line))
    nb_tot_temporary_unavailable_files = len(tot_temporary_unavailable_files)

    assert nb_tot_files == nb_tot_bad_files1 + nb_tot_suspicious_files + nb_tot_temporary_unavailable_files

    tomorrow = datetime.utcnow() + timedelta(days=1)
    data = {'state': 'B', 'younger_than': tomorrow.isoformat()}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_bad_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_bad_files.append(dumps(line))
    nb_tot_bad_files = len(tot_bad_files)
    assert nb_tot_bad_files == 0

    response = rest_client.get('/replicas/bad/summary', headers=headers(auth(auth_token)))
    assert response.status_code == 200
    nb_tot_bad_files2 = 0
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            line = loads(line)
            nb_tot_bad_files2 += int(line.get('BAD', 0))
    assert nb_tot_bad_files1 == nb_tot_bad_files2


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_list_replicas_content_type(replica_client, rest_client, auth_token):
    """ REPLICA (REST): send a GET to list replicas with specific ACCEPT header."""
    scope = 'mock'
    name = 'file_%s' % generate_uuid()
    files1 = [{'scope': scope, 'name': name, 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}}]
    replica_client.add_replicas(rse='MOCK', files=files1)

    # unsupported requested content type
    response = rest_client.get('/replicas/%s/%s' % (scope, name), headers=headers(auth(auth_token), accept('application/unsupported')))
    assert response.status_code == 406

    # content type json stream
    response = rest_client.get('/replicas/%s/%s' % (scope, name), headers=headers(auth(auth_token), accept(Mime.JSON_STREAM)))
    assert [header[1] for header in response.headers if header[0] == 'Content-Type'][0] == Mime.JSON_STREAM

    # content type metalink4
    response = rest_client.get('/replicas/%s/%s' % (scope, name), headers=headers(auth(auth_token), accept(Mime.METALINK)))
    assert [header[1] for header in response.headers if header[0] == 'Content-Type'][0] == Mime.METALINK

    # no requested content type
    response = rest_client.get('/replicas/%s/%s' % (scope, name), headers=headers(auth(auth_token)))
    assert [header[1] for header in response.headers if header[0] == 'Content-Type'][0] == Mime.JSON_STREAM

    # all content types
    response = rest_client.get('/replicas/%s/%s' % (scope, name), headers=headers(auth(auth_token), accept('*/*')))
    assert [header[1] for header in response.headers if header[0] == 'Content-Type'][0] == Mime.JSON_STREAM

    # multiple content types
    response = rest_client.get('/replicas/%s/%s' % (scope, name), headers=headers(auth(auth_token), accept('application/unsupported, application/x-json-stream')))
    assert [header[1] for header in response.headers if header[0] == 'Content-Type'][0] == Mime.JSON_STREAM

    response = rest_client.get('/replicas/%s/%s' % (scope, name), headers=headers(auth(auth_token), accept('application/unsupported, */*;q=0.8')))
    assert [header[1] for header in response.headers if header[0] == 'Content-Type'][0] == Mime.JSON_STREAM


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_add_list_replicas(replica_client):
    """ REPLICA (CLIENT): Add, change state and list file replicas """
    tmp_scope = 'mock'
    nbfiles = 5

    files1 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse='MOCK', files=files1)

    files2 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse='MOCK3', files=files2)

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files1])]
    assert len(replicas) == len(files1)

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['file'])]
    assert len(replicas) == 5

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['srm'])]
    assert len(replicas) == 5

    files3 = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'state': 'U', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse='MOCK3', files=files3)
    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files3], schemes=['file'])]
    for i in range(nbfiles):
        assert replicas[i]['rses'] == {}
    files4 = []
    for file in files3:
        file['state'] = 'A'
        files4.append(file)
    replica_client.update_replicas_states('MOCK3', files=files4)
    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files3], schemes=['file'], unavailable=True)]
    assert len(replicas) == 5
    for i in range(nbfiles):
        assert 'MOCK3' in replicas[i]['rses']


def test_add_replica_scope_not_found(replica_client):
    """ REPLICA (CLIENT): Add replica with missing scope """
    files = [{'scope': 'nonexistingscope', 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb'}]
    with pytest.raises(ScopeNotFound):
        replica_client.add_replicas(rse='MOCK', files=files)


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_delete_replicas(replica_client):
    """ REPLICA (CLIENT): Add and delete file replicas """
    tmp_scope = 'mock'
    nbfiles = 5
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse='MOCK', files=files)
    with pytest.raises(AccessDenied):
        replica_client.delete_replicas(rse='MOCK', files=files)

    # replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files])]
    # assert len(replicas) == 0


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_add_temporary_unavailable_pfns(vo, replica_client):
    """ REPLICA (CLIENT): Add temporary unavailable PFNs"""
    tmp_scope = 'mock'
    nbfiles = 5
    # Adding replicas to deterministic RSE
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse='MOCK', files=files)

    # Listing replicas on deterministic RSE
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], unavailable=True):
        pfn = list(replica['pfns'].keys())[0]
        list_rep.append(pfn)

    # Submit bad PFNs
    now = datetime.utcnow()
    reason_str = generate_uuid()
    replica_client.add_bad_pfns(pfns=list_rep, reason=str(reason_str), state='TEMPORARY_UNAVAILABLE', expires_at=now.isoformat())
    result = get_bad_pfns(limit=10000, thread=None, total_threads=None, session=None)
    bad_pfns = {}
    for res in result:
        bad_pfns[res['pfn']] = (res['state'], res['reason'], res['expires_at'])

    for pfn in list_rep:
        pfn = str(clean_surls([pfn])[0])
        assert pfn in bad_pfns
        assert bad_pfns[pfn][0] == BadPFNStatus.TEMPORARY_UNAVAILABLE
        assert bad_pfns[pfn][1] == reason_str

    # Submit with wrong state
    with pytest.raises(RucioException):
        replica_client.add_bad_pfns(pfns=list_rep, reason=str(reason_str), state='BADSTATE', expires_at=now.isoformat())

    # Run minos once
    minos_run(threads=1, bulk=10000, once=True)
    result = get_bad_pfns(limit=10000, thread=None, total_threads=None, session=None)
    pfns = [res['pfn'] for res in result]
    res_pfns = []
    for replica in list_rep:
        if replica in pfns:
            res_pfns.append(replica)
    assert res_pfns == []

    # Check the state in the replica table
    for did in files:
        rep = get_replicas_state(scope=InternalScope(did['scope'], vo=vo), name=did['name'])
        assert list(rep.keys())[0] == ReplicaState.TEMPORARY_UNAVAILABLE

    rep = []
    for did in files:
        did['state'] = ReplicaState.TEMPORARY_UNAVAILABLE
        rep.append(did)

    # Run the minos expiration
    minos_temp_run(threads=1, once=True)
    # Check the state in the replica table
    for did in files:
        rep = get_replicas_state(scope=InternalScope(did['scope'], vo=vo), name=did['name'])
        assert list(rep.keys())[0] == ReplicaState.AVAILABLE


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_set_tombstone2(vo, replica_client):
    """ REPLICA (CLIENT): set tombstone on replica """
    # Set tombstone on one replica
    rse = 'MOCK4'
    rse_id = get_rse_id(rse=rse, vo=vo)
    scope = InternalScope('mock', vo=vo)
    user = InternalAccount('root', vo=vo)
    name = generate_uuid()
    add_replica(rse_id, scope, name, 4, user)
    assert get_replica(rse_id, scope, name)['tombstone'] is None
    replica_client.set_tombstone([{'rse': rse, 'scope': scope.external, 'name': name}])
    assert get_replica(rse_id, scope, name)['tombstone'] == OBSOLETE

    # Set tombstone on locked replica
    name = generate_uuid()
    add_replica(rse_id, scope, name, 4, user)
    RuleClient().add_replication_rule([{'name': name, 'scope': scope.external}], 1, rse, locked=True)
    with pytest.raises(ReplicaIsLocked):
        replica_client.set_tombstone([{'rse': rse, 'scope': scope.external, 'name': name}])

    # Set tombstone on not found replica
    name = generate_uuid()
    with pytest.raises(ReplicaNotFound):
        replica_client.set_tombstone([{'rse': rse, 'scope': scope.external, 'name': name}])


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined RSE')
class TestReplicaMetalink(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

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
        assert 3 == len(ml['metalink']['file']['url'])

    def test_get_did_from_pfns_nondeterministic(self):
        """ REPLICA (CLIENT): Get list of DIDs associated to PFNs for non-deterministic sites"""
        rse = 'MOCK2'
        rse_id = get_rse_id(rse=rse, **self.vo)
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        nbfiles = 3
        pfns = []
        input = {}
        rse_info = rsemgr.get_rse_info(rse=rse, **self.vo)
        assert rse_info['deterministic'] is False
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
                  'pfn': 'srm://mock2.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/%s/%s' % (tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
        for f in files:
            input[f['pfn']] = {'scope': f['scope'].external, 'name': f['name']}
        add_replicas(rse_id=rse_id, files=files, account=root, ignore_availability=True)
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm'], ignore_availability=True):
            for r in replica['rses']:
                pfns.extend(replica['rses'][r])
        for result in self.replica_client.get_did_from_pfns(pfns, rse):
            pfn = list(result.keys())[0]
            assert input[pfn] == list(result.values())[0]

    def test_get_did_from_pfns_deterministic(self):
        """ REPLICA (CLIENT): Get list of DIDs associated to PFNs for deterministic sites"""
        tmp_scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)
        rse = 'MOCK3'
        rse_id = get_rse_id(rse=rse, **self.vo)
        nbfiles = 3
        pfns = []
        input = {}
        rse_info = rsemgr.get_rse_info(rse=rse, **self.vo)
        assert rse_info['deterministic'] is True
        files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        p = rsemgr.create_protocol(rse_info, 'read', scheme='srm')
        for f in files:
            pfn = list(p.lfns2pfns(lfns={'scope': f['scope'].external, 'name': f['name']}).values())[0]
            pfns.append(pfn)
            input[pfn] = {'scope': f['scope'].external, 'name': f['name']}
        add_replicas(rse_id=rse_id, files=files, account=root, ignore_availability=True)
        for result in self.replica_client.get_did_from_pfns(pfns, rse):
            pfn = list(result.keys())[0]
            assert input[pfn] == list(result.values())[0]


@pytest.mark.parametrize("content_type", [Mime.METALINK, Mime.JSON_STREAM])
def test_list_replicas_streaming_error(content_type, vo, did_client, replica_client):
    """
    REPLICA (CLIENT): List replicas and test for behavior when an error occurs while streaming.
    Complicated test ahead! Mocking the wsgi frameworks, because the
    wsgi test clients failed, showing different behavior than on the
    apache webserver. Running the code against the apache web server
    was problematic, because it was not easily possible to inject
    raising an error after returning an element from the API.
    """
    # mock data taken from a real response
    mock_api_response = {
        "adler32": "0cc737eb", "name": "file_a07ae361c1b844ba95f65b0ac385a3be", "rses": {
            "MOCK3": ["srm://mock3.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/mock/bf/a5/file_a07ae361c1b844ba95f65b0ac385a3be"],
            "MOCK": ["https://mock.com:2880/pnfs/rucio/disk-only/scratchdisk/mock/bf/a5/file_a07ae361c1b844ba95f65b0ac385a3be"],
            "MOCK4": ["file://localhost/tmp/rucio_rse/mock/bf/a5/file_a07ae361c1b844ba95f65b0ac385a3be"]
        }, "space_token": "RUCIODISK", "bytes": 1, "states": {"MOCK3": "AVAILABLE", "MOCK": "AVAILABLE", "MOCK4": "AVAILABLE"}, "pfns": {
            "srm://mock3.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/mock/bf/a5/file_a07ae361c1b844ba95f65b0ac385a3be": {
                "domain": "wan", "rse": "MOCK3", "priority": 3, "volatile": False, "client_extract": False, "type": "DISK", "rse_id": "4bce8ccadf594c42a627f842ccdb8fc2"
            },
            "https://mock.com:2880/pnfs/rucio/disk-only/scratchdisk/mock/bf/a5/file_a07ae361c1b844ba95f65b0ac385a3be": {
                "domain": "wan", "rse": "MOCK", "priority": 2, "volatile": False, "client_extract": False, "type": "DISK", "rse_id": "908b01ee6fa04dd497c52d4869d778ca"
            },
            "file://localhost/tmp/rucio_rse/mock/bf/a5/file_a07ae361c1b844ba95f65b0ac385a3be": {
                "domain": "wan", "rse": "MOCK4", "priority": 1, "volatile": False, "client_extract": False, "type": "DISK", "rse_id": "fd69ce85288845d9adcb54e2a7017520"
            }
        }, "scope": "mock", "md5": None
    }

    def api_returns(*_, **__):
        yield mock_api_response
        # raise after yielding an element
        raise DatabaseException('Database error for testing')

    json_data = dumps({'dids': [{'scope': 'mock', 'name': generate_uuid()}]})
    rest_backend = os.environ.get('REST_BACKEND', 'webpy')
    if rest_backend == 'webpy':
        def list_replicas_on_api():
            class MockedHTTPError(Exception):
                def __init__(self, status_code, exc_cls, exc_msg):
                    super(MockedHTTPError, self).__init__("MockedHTTPError %s, %s: %s" % (status_code, exc_cls, exc_msg))

                @classmethod
                def generate(cls, *args, **kwargs):
                    raise cls(*args, **kwargs)

            class FakeCtx:
                env = {
                    'issuer': 'root',
                    'vo': vo,
                    'request_id': generate_uuid(),
                    'HTTP_ACCEPT': content_type,
                }
                query = None
                ip = '127.0.0.1'

            with mock.patch('rucio.web.rest.common.ctx', new=FakeCtx()), \
                    mock.patch('rucio.web.rest.replica.ctx', new=FakeCtx()), \
                    mock.patch('rucio.web.rest.replica.data', return_value=json_data), \
                    mock.patch('rucio.web.rest.replica.header'), \
                    mock.patch('rucio.web.rest.replica.generate_http_error', side_effect=MockedHTTPError.generate), \
                    mock.patch('rucio.web.rest.replica.list_replicas', side_effect=api_returns):
                from rucio.web.rest.replica import ListReplicas
                list_replicas_restapi = ListReplicas()
                with pytest.raises(MockedHTTPError, match='MockedHTTPError 500, DatabaseException: Database error for testing'):
                    for element in list_replicas_restapi.POST():
                        yield element

    elif rest_backend == 'flask':
        def list_replicas_on_api():
            from werkzeug.datastructures import Headers

            class FakeRequest:
                class FakeAcceptMimetypes:
                    provided = False
                    best_match = mock.MagicMock(return_value=content_type)

                environ = {
                    'issuer': 'root',
                    'vo': vo,
                    'request_id': generate_uuid(),
                }
                query_string = None
                args = MultiDict()
                data = json_data
                get_data = mock.MagicMock(return_value=json_data)
                headers = Headers()
                accept_mimetypes = FakeAcceptMimetypes()
                remote_addr = '127.0.0.1'

            response_mock = mock.Mock(return_value=None)

            class FakeFlask:
                request = FakeRequest()
                abort = mock.MagicMock()
                Response = response_mock

            with mock.patch('rucio.web.rest.flaskapi.v1.common.flask', new=FakeFlask()), \
                    mock.patch('rucio.web.rest.flaskapi.v1.replicas.request', new=FakeRequest()), \
                    mock.patch('rucio.web.rest.flaskapi.v1.replicas.list_replicas', side_effect=api_returns):
                from rucio.web.rest.flaskapi.v1.replicas import ListReplicas
                list_replicas_restapi = ListReplicas()
                list_replicas_restapi.post()
                # for debugging when this test fails
                print(f'Response({response_mock.call_args})')
                print(f'  args = {response_mock.call_args[0]}')
                print(f'kwargs = {response_mock.call_args[1]}')
                assert response_mock.call_args[1]['content_type'] == content_type
                response_iter = response_mock.call_args[0][0]
                assert response_iter != '', 'unexpected empty response'
                # since we're directly accessing the generator for Flask, there is no error handling
                with pytest.raises(DatabaseException, match='Database error for testing'):
                    for element in response_iter:
                        yield element

    else:
        return pytest.xfail('unknown REST_BACKEND: ' + rest_backend)

    if content_type == Mime.METALINK:
        # for metalink, this builds the incomplete XML that should be returned by the API on error
        metalink = ''
        for line in list_replicas_on_api():
            metalink += line
        assert metalink
        print(metalink)
        with pytest.raises(ElementTree.ParseError):
            ElementTree.fromstring(metalink)

    elif content_type == Mime.JSON_STREAM:
        # for the json stream mimetype the API method just returns all mocked replicas on error
        replicas = []
        for json_doc in list_replicas_on_api():
            if json_doc:
                replicas.append(parse_response(json_doc))
        assert replicas
        print(replicas)
        assert replicas == [mock_api_response]

    else:
        pytest.fail('unknown content_type parameter on test: ' + content_type)
