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
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2021
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Tobias Wegner <twegner@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Luc Goossens <luc.goossens@cern.ch>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Ilija Vukotic <ivukotic@uchicago.edu>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from __future__ import print_function

import hashlib
import time
from datetime import datetime, timedelta
from json import dumps, loads
from unittest import mock
from xml.etree import ElementTree

import pytest
import xmltodict
from werkzeug.datastructures import MultiDict

from rucio.client.ruleclient import RuleClient
from rucio.common.exception import (DataIdentifierNotFound, AccessDenied, UnsupportedOperation,
                                    RucioException, ReplicaIsLocked, ReplicaNotFound, ScopeNotFound,
                                    DatabaseException)
from rucio.common.utils import generate_uuid, clean_surls, parse_response
from rucio.core.config import set as cconfig_set
from rucio.core.did import add_did, attach_dids, get_did, set_status, list_files, get_did_atime
from rucio.core.replica import (add_replica, add_replicas, delete_replicas, get_replicas_state,
                                get_replica, list_replicas, declare_bad_file_replicas, list_bad_replicas,
                                update_replica_state, get_RSEcoverage_of_dataset, get_replica_atime,
                                touch_replica, get_bad_pfns, set_tombstone)
from rucio.core.rse import add_protocol, add_rse_attribute, del_rse_attribute
from rucio.daemons.badreplicas.minos import run as minos_run
from rucio.daemons.badreplicas.minos_temporary_expiration import run as minos_temp_run
from rucio.daemons.badreplicas.necromancer import run as necromancer_run
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, ReplicaState, BadPFNStatus, OBSOLETE
from rucio.db.sqla.session import transactional_session
from rucio.rse import rsemanager as rsemgr
from rucio.tests.common import execute, headers, auth, Mime, accept


def mocked_VP_requests_get(*args, **kwargs):
    """This method will be used by the mock to replace requests.get to VP server."""
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


class TestReplicaCore:

    @mock.patch('rucio.core.replica.requests.get', side_effect=mocked_VP_requests_get)
    def test_cache_replicas(self, mock_get, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Test listing replicas with cached root protocol """

        rse, rse_id = rse_factory.make_rse()

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

        files = []

        name = 'file_%s' % generate_uuid()
        hstr = hashlib.md5(('%s:%s' % (mock_scope, name)).encode('utf-8')).hexdigest()
        pfn = 'root://root.aperture.com:1409//test/chamber/mock/%s/%s/%s' % (hstr[0:2], hstr[2:4], name)
        files.append({'scope': mock_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef', 'pfn': pfn})

        name = 'element_%s' % generate_uuid()
        hstr = hashlib.md5(('%s:%s' % (mock_scope, name)).encode('utf-8')).hexdigest()
        pfn = 'http://root.aperture.com:1409//test/chamber/mock/%s/%s/%s' % (hstr[0:2], hstr[2:4], name)
        files.append({'scope': mock_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef', 'pfn': pfn})

        add_replicas(rse_id=rse_id, files=files, account=root_account)

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

    @pytest.mark.noparallel(reason='calls list_bad_replicas() which acts on all bad replicas without any filtering')
    def test_add_list_bad_replicas(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Add bad replicas and list them"""

        nbfiles = 5
        # Adding replicas to deterministic RSE
        _, rse1_id = rse_factory.make_srm_rse(deterministic=True)
        files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        add_replicas(rse_id=rse1_id, files=files, account=root_account, ignore_availability=True)

        # Listing replicas on deterministic RSE
        replicas = []
        list_rep = []
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replicas.extend(replica['rses'][rse1_id])
            list_rep.append(replica)
        r = declare_bad_file_replicas(replicas, 'This is a good reason', root_account)
        assert r == {}
        bad_replicas = list_bad_replicas()
        nbbadrep = 0
        for rep in list_rep:
            for badrep in bad_replicas:
                if badrep['rse_id'] == rse1_id:
                    if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                        nbbadrep += 1
        assert len(replicas) == nbbadrep

        # Adding replicas to non-deterministic RSE
        _, rse2_id = rse_factory.make_srm_rse(deterministic=False)
        files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
                  'pfn': 'srm://%s.cern.ch/srm/managerv2?SFN=/test/%s/%s' % (rse2_id, mock_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
        add_replicas(rse_id=rse2_id, files=files, account=root_account, ignore_availability=True)

        # Listing replicas on non-deterministic RSE
        replicas = []
        list_rep = []
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replicas.extend(replica['rses'][rse2_id])
            list_rep.append(replica)
        r = declare_bad_file_replicas(replicas, 'This is a good reason', root_account)
        assert r == {}
        bad_replicas = list_bad_replicas()
        nbbadrep = 0
        for rep in list_rep:
            for badrep in bad_replicas:
                if badrep['rse_id'] == rse2_id:
                    if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                        nbbadrep += 1
        assert len(replicas) == nbbadrep

        # Now adding non-existing bad replicas
        files = ['srm://%s.cern.ch/test/%s/%s' % (rse2_id, mock_scope, generate_uuid()), ]
        r = declare_bad_file_replicas(files, 'This is a good reason', root_account)
        output = ['%s Unknown replica' % rep for rep in files]
        assert r == {rse2_id: output}

    def test_add_list_replicas(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Add and list file replicas """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()

        nbfiles = 13
        files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        for rse_id in [rse1_id, rse2_id]:
            add_replicas(rse_id=rse_id, files=files, account=root_account, ignore_availability=True)

        replica_cpt = 0
        for _ in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
            replica_cpt += 1

        assert nbfiles == replica_cpt

    def test_delete_replicas(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Delete replicas """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()

        nbfiles = 5
        files1 = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]

        add_replicas(rse_id=rse1_id, files=files1, account=root_account, ignore_availability=True)

        files2 = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        add_replicas(rse_id=rse1_id, files=files2, account=root_account, ignore_availability=True)
        add_replicas(rse_id=rse2_id, files=files2, account=root_account, ignore_availability=True)

        delete_replicas(rse_id=rse1_id, files=files1 + files2)

        for file in files1:
            with pytest.raises(DataIdentifierNotFound):
                print(get_did(scope=file['scope'], name=file['name']))

        for file in files2:
            get_did(scope=file['scope'], name=file['name'])

    def test_delete_replicas_from_datasets(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Delete replicas from dataset """
        _, rse_id = rse_factory.make_mock_rse()

        tmp_dsn1 = 'dsn_%s' % generate_uuid()
        tmp_dsn2 = 'dsn_%s' % generate_uuid()
        nbfiles = 5
        files1 = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]

        add_did(scope=mock_scope, name=tmp_dsn1, type=DIDType.DATASET, account=root_account)
        add_did(scope=mock_scope, name=tmp_dsn2, type=DIDType.DATASET, account=root_account)

        attach_dids(scope=mock_scope, name=tmp_dsn1, rse_id=rse_id, dids=files1, account=root_account)
        attach_dids(scope=mock_scope, name=tmp_dsn2, dids=files1, account=root_account)

        set_status(scope=mock_scope, name=tmp_dsn1, open=False)

        delete_replicas(rse_id=rse_id, files=files1)

        with pytest.raises(DataIdentifierNotFound):
            get_did(scope=mock_scope, name=tmp_dsn1)

        get_did(scope=mock_scope, name=tmp_dsn2)

        assert [f for f in list_files(scope=mock_scope, name=tmp_dsn2)] == []

    def test_touch_replicas(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Touch replicas accessed_at timestamp"""

        _, rse_id = rse_factory.make_mock_rse()

        nbfiles = 5
        files1 = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        files2 = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        files2.append(files1[0])

        add_replicas(rse_id=rse_id, files=files1, account=root_account, ignore_availability=True)
        add_replicas(rse_id=rse_id, files=files2, account=root_account, ignore_availability=True)

        now = datetime.utcnow()

        now -= timedelta(microseconds=now.microsecond)

        assert get_replica_atime({'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse_id': rse_id}) is None
        assert get_did_atime(scope=mock_scope, name=files1[0]['name']) is None

        for r in [{'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse_id': rse_id, 'accessed_at': now}]:
            touch_replica(r)

        assert now == get_replica_atime({'scope': files1[0]['scope'], 'name': files1[0]['name'], 'rse_id': rse_id})
        assert now == get_did_atime(scope=mock_scope, name=files1[0]['name'])

        for i in range(1, nbfiles):
            assert get_replica_atime({'scope': files1[i]['scope'], 'name': files1[i]['name'], 'rse_id': rse_id}) is None

        for i in range(0, nbfiles - 1):
            assert get_replica_atime({'scope': files2[i]['scope'], 'name': files2[i]['name'], 'rse_id': rse_id}) is None

    def test_list_replicas_all_states(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): list file replicas with all_states"""
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()
        nbfiles = 13
        files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        rses = [rse1_id, rse2_id]
        for rse_id in rses:
            add_replicas(rse_id=rse_id, files=files, account=root_account, ignore_availability=True)

        for file in files:
            update_replica_state(rses[0], mock_scope, file['name'], ReplicaState.COPYING)

        replica_cpt = 0
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm'], all_states=True):
            assert 'states' in replica
            assert replica['states'][rses[0]] == str(ReplicaState.COPYING.name)
            assert replica['states'][rses[1]] == str(ReplicaState.AVAILABLE.name)
            replica_cpt += 1

        assert nbfiles == replica_cpt

    def test_list_replica_with_domain(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Add and list file replicas forcing domain"""

        rse, rse_id = rse_factory.make_rse()

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
            add_protocol(rse_id, p)

        nbfiles = 3
        files = [{'scope': mock_scope,
                  'name': 'file_%s' % generate_uuid(),
                  'bytes': 1234,
                  'adler32': '01234567',
                  'meta': {'events': 1234}} for _ in range(nbfiles)]

        add_replicas(rse_id=rse_id, files=files, account=root_account, ignore_availability=True)

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

    def test_list_replica_with_schemes(self, rse_factory, mock_scope, root_account, replica_client):
        """ REPLICA (CORE): Add and list file replicas forcing schemes"""

        rse, rse_id = rse_factory.make_rse()

        add_protocol(rse_id, {'scheme': 'http',
                              'hostname': 'http.aperture.com',
                              'port': 80,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.gfalv2.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        name = 'element_%s' % generate_uuid()
        file_item = {'scope': mock_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef'}

        add_replicas(rse_id=rse_id, files=[file_item], account=root_account)

        replicas = list(replica_client.list_replicas([{'scope': mock_scope.external, 'name': name}]))
        assert 'http://' in list(replicas[0]['pfns'].keys())[0]

    def test_replica_no_site(self, rse_factory, mock_scope, root_account, replica_client):
        """ REPLICA (CORE): Test listing replicas without site attribute """

        rse, rse_id = rse_factory.make_rse()

        add_protocol(rse_id, {'scheme': 'root',
                              'hostname': 'root.aperture.com',
                              'port': 1409,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.xrootd.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        add_rse_attribute(rse_id=rse_id, key='site', value='APERTURE')

        files = [{'scope': mock_scope, 'name': 'element_%s' % generate_uuid(),
                  'bytes': 1234, 'adler32': 'deadbeef'}]
        add_replicas(rse_id=rse_id, files=files, account=root_account)

        replicas = [r for r in replica_client.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files])]
        assert 'root://' in list(replicas[0]['pfns'].keys())[0]
        replicas = [r for r in replica_client.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files],
                                                            client_location={'site': 'SOMEWHERE'})]
        assert 'root://' in list(replicas[0]['pfns'].keys())[0]
        del_rse_attribute(rse_id=rse_id, key='site')

        replicas = [r for r in replica_client.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files])]
        assert 'root://' in list(replicas[0]['pfns'].keys())[0]
        replicas = [r for r in replica_client.list_replicas(dids=[{'scope': 'mock', 'name': f['name']} for f in files],
                                                            client_location={'site': 'SOMEWHERE'})]
        assert 'root://' in list(replicas[0]['pfns'].keys())[0]

    def test_replica_mixed_protocols(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Test adding replicas with mixed protocol """

        rse, rse_id = rse_factory.make_rse()

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

        files = []

        name = 'element_%s' % generate_uuid()
        hstr = hashlib.md5(('%s:%s' % (mock_scope, name)).encode('utf-8')).hexdigest()
        pfn = 'root://root.aperture.com:1409//test/chamber/mock/%s/%s/%s' % (hstr[0:2], hstr[2:4], name)
        files.append({'scope': mock_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef', 'pfn': pfn})

        name = 'element_%s' % generate_uuid()
        hstr = hashlib.md5(('%s:%s' % (mock_scope, name)).encode('utf-8')).hexdigest()
        pfn = 'http://root.aperture.com:1409//test/chamber/mock/%s/%s/%s' % (hstr[0:2], hstr[2:4], name)
        files.append({'scope': mock_scope, 'name': name, 'bytes': 1234, 'adler32': 'deadbeef', 'pfn': pfn})

        add_replicas(rse_id=rse_id, files=files, account=root_account)

    def test_set_tombstone(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): set tombstone on replica """
        # Set tombstone on one replica
        rse, rse_id = rse_factory.make_mock_rse()
        name = generate_uuid()
        add_replica(rse_id, mock_scope, name, 4, root_account)
        assert get_replica(rse_id, mock_scope, name)['tombstone'] is None
        set_tombstone(rse_id, mock_scope, name)
        assert get_replica(rse_id, mock_scope, name)['tombstone'] == OBSOLETE

        # Set tombstone on locked replica
        name = generate_uuid()
        add_replica(rse_id, mock_scope, name, 4, root_account)
        RuleClient().add_replication_rule([{'name': name, 'scope': mock_scope.external}], 1, rse, locked=True)
        with pytest.raises(ReplicaIsLocked):
            set_tombstone(rse_id, mock_scope, name)

        # Set tombstone on not found replica
        name = generate_uuid()
        with pytest.raises(ReplicaNotFound):
            set_tombstone(rse_id, mock_scope, name)

    def test_core_default_tombstone_correctly_set(self, rse_factory, did_factory, root_account):
        """ REPLICA (CORE): Per-RSE default tombstone is correctly taken into consideration"""

        # One RSE has an attribute set, the other uses the default value of "None" for tombstone
        rse1, rse1_id = rse_factory.make_mock_rse()
        rse2, rse2_id = rse_factory.make_mock_rse()
        tombstone_delay = 3600
        add_rse_attribute(rse_id=rse2_id, key='tombstone_delay', value=tombstone_delay)

        # Will use the default tombstone delay
        did1 = did_factory.random_did()
        add_replica(rse1_id, bytes=4, account=root_account, **did1)
        assert get_replica(rse1_id, **did1)['tombstone'] is None

        # Will use the configured value on the RSE
        did2 = did_factory.random_did()
        add_replica(rse2_id, bytes=4, account=root_account, **did2)
        tombstone = get_replica(rse2_id, **did2)['tombstone']
        expected_tombstone = datetime.utcnow() + timedelta(seconds=tombstone_delay)
        assert expected_tombstone - timedelta(minutes=5) < tombstone < expected_tombstone + timedelta(minutes=5)

        # Adding rule removes the tombstone
        RuleClient().add_replication_rule([{'name': did1['name'], 'scope': did1['scope'].external}], 1, rse1, locked=True)
        assert get_replica(rse1_id, **did1)['tombstone'] is None
        RuleClient().add_replication_rule([{'name': did2['name'], 'scope': did2['scope'].external}], 1, rse2, locked=True)
        assert get_replica(rse2_id, **did2)['tombstone'] is None

    def test_list_replicas_with_updated_after(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): Add and list file replicas with updated_after filter """
        _, rse_id = rse_factory.make_mock_rse()
        dsn = 'ds_ua_test_%s' % generate_uuid()
        add_did(scope=mock_scope, name=dsn, type='DATASET', account=root_account)
        #
        t0 = datetime.utcnow()
        time.sleep(2)
        lfn = '%s._%s.data' % (dsn, '0001')
        add_replica(rse_id=rse_id, scope=mock_scope, name=lfn, bytes=12345, account=root_account)
        attach_dids(scope=mock_scope, name=dsn, dids=[{'scope': mock_scope, 'name': lfn}], account=root_account)
        time.sleep(2)
        t1 = datetime.utcnow()
        time.sleep(2)
        lfn = '%s._%s.data' % (dsn, '0002')
        add_replica(rse_id=rse_id, scope=mock_scope, name=lfn, bytes=12345, account=root_account)
        attach_dids(scope=mock_scope, name=dsn, dids=[{'scope': mock_scope, 'name': lfn}], account=root_account)
        time.sleep(2)
        t2 = datetime.utcnow()
        time.sleep(2)
        lfn = '%s._%s.data' % (dsn, '0003')
        add_replica(rse_id=rse_id, scope=mock_scope, name=lfn, bytes=12345, account=root_account)
        attach_dids(scope=mock_scope, name=dsn, dids=[{'scope': mock_scope, 'name': lfn}], account=root_account)
        time.sleep(2)
        t3 = datetime.utcnow()
        #
        assert len(list(list_replicas([{'scope': mock_scope, 'name': dsn}], updated_after=None))) == 3
        assert len(list(list_replicas([{'scope': mock_scope, 'name': dsn}], updated_after=t0))) == 3
        assert len(list(list_replicas([{'scope': mock_scope, 'name': dsn}], updated_after=t1))) == 2
        assert len(list(list_replicas([{'scope': mock_scope, 'name': dsn}], updated_after=t2))) == 1
        assert len(list(list_replicas([{'scope': mock_scope, 'name': dsn}], updated_after=t3))) == 0

    def test_get_RSE_coverage_of_dataset(self, rse_factory, mock_scope, root_account):
        """ REPLICA (CORE): test RSE coverage retrieval """
        _, rse1_id = rse_factory.make_mock_rse()
        _, rse2_id = rse_factory.make_mock_rse()
        _, rse3_id = rse_factory.make_mock_rse()

        dsn = 'ds_cov_test_%s' % generate_uuid()
        add_did(scope=mock_scope, name=dsn, type='DATASET', account=root_account)

        # test empty dataset
        cov = get_RSEcoverage_of_dataset(scope=mock_scope, name=dsn)
        print(cov)
        assert cov == {}
        # add files/replicas
        for i in range(1, 8):
            add_replica(rse_id=rse1_id, scope=mock_scope, name=dsn + '_%06d.data' % i, bytes=100, account=root_account)
        for i in range(8, 11):
            add_replica(rse_id=rse2_id, scope=mock_scope, name=dsn + '_%06d.data' % i, bytes=100, account=root_account)
        for i in range(11, 16):
            add_replica(rse_id=rse3_id, scope=mock_scope, name=dsn + '_%06d.data' % i, bytes=100, account=root_account)

        attach_dids(scope=mock_scope, name=dsn, dids=[{'scope': mock_scope, 'name': dsn + '_%06d.data' % i} for i in range(1, 16)], account=root_account)
        cov = get_RSEcoverage_of_dataset(scope=mock_scope, name=dsn)
        print(cov)
        assert cov[rse1_id] == 700
        assert cov[rse2_id] == 300
        assert cov[rse3_id] == 500


@pytest.mark.noparallel(reason='calls list_bad_replicas() and runs necromancer. Both act on all bad replicas without any filtering')
def test_client_add_list_bad_replicas(rse_factory, replica_client, did_client):
    """ REPLICA (CLIENT): Add bad replicas"""
    tmp_scope = 'mock'
    nbfiles = 5
    # Adding replicas to deterministic RSE
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    rse1, rse1_id = rse_factory.make_srm_rse(deterministic=True)
    replica_client.add_replicas(rse=rse1, files=files)

    # Listing replicas on deterministic RSE
    replicas, list_rep = [], []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse1])
        list_rep.append(replica)
    r = replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse1_id:
                if badrep['scope'].external == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # Run necromancer once
    necromancer_run(threads=1, bulk=10000, once=True)

    # Try to attach a lost file
    tmp_dsn = 'dataset_%s' % generate_uuid()
    did_client.add_dataset(scope=tmp_scope, name=tmp_dsn)
    with pytest.raises(UnsupportedOperation):
        did_client.add_files_to_dataset(tmp_scope, name=tmp_dsn, files=files, rse=rse1)

    # Adding replicas to non-deterministic RSE
    rse2, rse2_id = rse_factory.make_srm_rse(deterministic=False)
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
              'pfn': 'srm://%s.cern.ch/srm/managerv2?SFN=/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse2, files=files)

    # Listing replicas on non-deterministic RSE
    replicas, list_rep = [], []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse2])
        list_rep.append(replica)
    print(replicas, list_rep)
    r = replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
    print(r)
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse2_id:
                if badrep['scope'].external == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # Now adding non-existing bad replicas
    files = ['srm://%s.cern.ch/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), ]
    r = replica_client.declare_bad_file_replicas(files, 'This is a good reason')
    output = ['%s Unknown replica' % rep for rep in files]
    assert r == {rse2: output}


def test_client_add_suspicious_replicas(rse_factory, replica_client):
    """ REPLICA (CLIENT): Add suspicious replicas"""
    tmp_scope = 'mock'
    nbfiles = 5
    # Adding replicas to deterministic RSE
    rse1, _ = rse_factory.make_srm_rse(deterministic=True)
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse1, files=files)

    # Listing replicas on deterministic RSE
    replicas = []
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse1])
        list_rep.append(replica)
    r = replica_client.declare_suspicious_file_replicas(replicas, 'This is a good reason')
    assert r == {}

    # Adding replicas to non-deterministic RSE
    rse2, rse2_id = rse_factory.make_srm_rse(deterministic=False)
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
              'pfn': 'srm://%s.cern.ch/srm/managerv2?SFN=/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse2, files=files)

    # Listing replicas on non-deterministic RSE
    replicas = []
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse2])
        list_rep.append(replica)
    r = replica_client.declare_suspicious_file_replicas(replicas, 'This is a good reason')
    assert r == {}
    # Now adding non-existing bad replicas
    files = ['srm://%s.cern.ch/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), ]
    r = replica_client.declare_suspicious_file_replicas(files, 'This is a good reason')
    output = ['%s Unknown replica' % rep for rep in files]
    assert r == {rse2: output}


@pytest.mark.noparallel(reason='Lists bad replicas multiple times. If the list changes between calls, test fails.')
def test_rest_bad_replica_methods_for_ui(rest_client, auth_token):
    __test_rest_bad_replica_methods_for_ui(rest_client, auth_token, list_pfns=False)
    __test_rest_bad_replica_methods_for_ui(rest_client, auth_token, list_pfns=True)


def __test_rest_bad_replica_methods_for_ui(rest_client, auth_token, list_pfns):
    """ REPLICA (REST): Test the listing of bad and suspicious replicas """
    if list_pfns:
        common_data = {'list_pfns': 'True'}
    else:
        common_data = {}

    data = {**common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_files.append(dumps(line))
    nb_tot_files = len(tot_files)

    data = {'state': 'B', **common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_bad_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_bad_files.append(dumps(line))
    nb_tot_bad_files1 = len(tot_bad_files)

    data = {'state': 'S', **common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_suspicious_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_suspicious_files.append(dumps(line))
    nb_tot_suspicious_files = len(tot_suspicious_files)

    data = {'state': 'T', **common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_temporary_unavailable_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_temporary_unavailable_files.append(dumps(line))
    nb_tot_temporary_unavailable_files = len(tot_temporary_unavailable_files)

    assert nb_tot_files == nb_tot_bad_files1 + nb_tot_suspicious_files + nb_tot_temporary_unavailable_files

    tomorrow = datetime.utcnow() + timedelta(days=1)
    data = {'state': 'B', 'younger_than': tomorrow.isoformat(), **common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_bad_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_bad_files.append(dumps(line))
    nb_tot_bad_files = len(tot_bad_files)
    assert nb_tot_bad_files == 0

    if not list_pfns:
        response = rest_client.get('/replicas/bad/summary', headers=headers(auth(auth_token)))
        assert response.status_code == 200
        nb_tot_bad_files2 = 0
        for line in response.get_data(as_text=True).split('\n'):
            if line != '':
                line = loads(line)
                nb_tot_bad_files2 += int(line.get('BAD', 0))
        assert nb_tot_bad_files1 == nb_tot_bad_files2


def test_rest_list_replicas_content_type(rse_factory, mock_scope, replica_client, rest_client, auth_token):
    """ REPLICA (REST): send a GET to list replicas with specific ACCEPT header."""
    rse, _ = rse_factory.make_mock_rse()
    scope = mock_scope.external
    name = 'file_%s' % generate_uuid()
    files1 = [{'scope': scope, 'name': name, 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}}]
    replica_client.add_replicas(rse=rse, files=files1)

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


def test_client_add_list_replicas(rse_factory, replica_client, mock_scope):
    """ REPLICA (CLIENT): Add, change state and list file replicas """
    rse1, _ = rse_factory.make_posix_rse()
    rse2, _ = rse_factory.make_posix_rse()
    nbfiles = 5

    files1 = [{'scope': mock_scope.external, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse1, files=files1)

    files2 = [{'scope': mock_scope.external, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse2, files=files2)

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files1])]
    assert len(replicas) == len(files1)

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['file'])]
    assert len(replicas) == 5

    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files2], schemes=['srm'])]
    assert len(replicas) == 5

    files3 = [{'scope': mock_scope.external, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'state': 'U', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse2, files=files3)
    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files3], schemes=['file'])]
    for i in range(nbfiles):
        assert replicas[i]['rses'] == {}
    files4 = []
    for file in files3:
        file['state'] = 'A'
        files4.append(file)
    replica_client.update_replicas_states(rse2, files=files4)
    replicas = [r for r in replica_client.list_replicas(dids=[{'scope': i['scope'], 'name': i['name']} for i in files3], schemes=['file'], all_states=True)]
    assert len(replicas) == 5
    for i in range(nbfiles):
        assert rse2 in replicas[i]['rses']


def test_client_add_replica_scope_not_found(replica_client):
    """ REPLICA (CLIENT): Add replica with missing scope """
    files = [{'scope': 'nonexistingscope', 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb'}]
    with pytest.raises(ScopeNotFound):
        replica_client.add_replicas(rse='MOCK', files=files)


def test_client_access_denied_on_delete_replicas(rse_factory, mock_scope, replica_client):
    """ REPLICA (CLIENT): Access denied on delete file replicas """
    rse, _ = rse_factory.make_mock_rse()
    nbfiles = 5
    files = [{'scope': mock_scope.external, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse, files=files)
    with pytest.raises(AccessDenied):
        replica_client.delete_replicas(rse=rse, files=files)

    for f in files:
        replicas = list(replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']}]))
        assert len(replicas) == 1


def test_client_list_replicas_on_did_without_replicas(rse_factory, did_factory, replica_client, did_client, root_account):
    """ REPLICA (CLIENT): dids of type FILE, but without replicas, must be listed with empty pfns and rses"""
    rse, _ = rse_factory.make_posix_rse()
    file = did_factory.random_did()
    dataset = did_factory.make_dataset()
    container = did_factory.make_container()

    @transactional_session
    def __add_file_did_without_replica(session=None):
        models.DataIdentifier(scope=file['scope'], name=file['name'], did_type=DIDType.FILE, bytes=1, adler32='0cc737eb', account=root_account).save(session=session, flush=False)

    __add_file_did_without_replica()

    # make all scopes external
    file, dataset, container = ({'scope': did['scope'].external, 'name': did['name']} for did in (file, dataset, container))

    did_client.add_files_to_dataset(files=[file], **dataset)
    did_client.add_datasets_to_container(dsns=[dataset], **container)

    replicas = list(replica_client.list_replicas(dids=[file]))
    assert len(replicas) == 1
    assert not replicas[0]['rses']
    assert not replicas[0]['pfns']
    # TODO: fix listing dids without replicas from datasets and containers and uncomment the following 2 asserts
    # assert list(replica_client.list_replicas(dids=[dataset]))
    # assert list(replica_client.list_replicas(dids=[container]))


def test_client_list_blocklisted_replicas(rse_factory, did_factory, replica_client, did_client):
    """ REPLICA (CLIENT): Blocklisted replicas are filtered in list replicas"""

    rse, _ = rse_factory.make_posix_rse()
    file = did_factory.upload_test_file(rse)
    dataset = did_factory.make_dataset()
    container = did_factory.make_container()

    # make all scopes external
    file, dataset, container = ({'scope': did['scope'].external, 'name': did['name']} for did in (file, dataset, container))

    did_client.add_files_to_dataset(files=[file], **dataset)
    did_client.add_datasets_to_container(dsns=[dataset], **container)

    # availability_write will not have any impact on listing replicas
    did_factory.client.update_rse(rse, {'availability_write': False})
    for did in (file, dataset, container):
        replicas = list(replica_client.list_replicas(dids=[did]))
        assert len(replicas) == 1
        assert len(replicas[0]['rses']) == 1

    # if availability_read is set to false, the replicas from the given rse will not be listed
    did_factory.client.update_rse(rse, {'availability_read': False})
    replicas = list(replica_client.list_replicas(dids=[file], ignore_availability=False))
    assert len(replicas) == 1
    assert not replicas[0]['rses'] and not replicas[0]['pfns']
    for did in (dataset, container):
        replicas = list(replica_client.list_replicas(dids=[did], ignore_availability=False))
        assert len(replicas) == 0
    # By default unavailable replicas will be returned
    for did in (file, dataset, container):
        replicas = list(replica_client.list_replicas(dids=[did]))
        assert len(replicas) == 1
        assert len(replicas[0]['rses']) == 1


@pytest.mark.dirty
@pytest.mark.noparallel(reason='runs minos, which acts on all bad pfns')
def test_client_add_temporary_unavailable_pfns(rse_factory, mock_scope, replica_client):
    """ REPLICA (CLIENT): Add temporary unavailable PFNs"""
    rse, rse_id = rse_factory.make_posix_rse()
    nbfiles = 5
    # Adding replicas to deterministic RSE
    files = [{'scope': mock_scope.external, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse, files=files)

    # Listing replicas on deterministic RSE
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['file'], all_states=True):
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
    pfns = [res['pfn'] for res in result if res['pfn'] in bad_pfns]
    res_pfns = []
    for replica in list_rep:
        if replica in pfns:
            res_pfns.append(replica)
    assert res_pfns == []

    # Check the state in the replica table
    for did in files:
        rep = get_replicas_state(scope=mock_scope, name=did['name'])
        assert list(rep.keys())[0] == ReplicaState.TEMPORARY_UNAVAILABLE

    rep = []
    for did in files:
        did['state'] = ReplicaState.TEMPORARY_UNAVAILABLE
        rep.append(did)

    # Run the minos expiration
    minos_temp_run(threads=1, once=True)
    # Check the state in the replica table
    for did in files:
        rep = get_replicas_state(scope=mock_scope, name=did['name'])
        assert list(rep.keys())[0] == ReplicaState.AVAILABLE


def test_client_set_tombstone(rse_factory, mock_scope, root_account, replica_client):
    """ REPLICA (CLIENT): set tombstone on replica """
    # Set tombstone on one replica
    rse, rse_id = rse_factory.make_mock_rse()
    name = generate_uuid()
    add_replica(rse_id, mock_scope, name, 4, root_account)
    assert get_replica(rse_id, mock_scope, name)['tombstone'] is None
    replica_client.set_tombstone([{'rse': rse, 'scope': mock_scope.external, 'name': name}])
    assert get_replica(rse_id, mock_scope, name)['tombstone'] == OBSOLETE

    # Set tombstone on locked replica
    name = generate_uuid()
    add_replica(rse_id, mock_scope, name, 4, root_account)
    RuleClient().add_replication_rule([{'name': name, 'scope': mock_scope.external}], 1, rse, locked=True)
    with pytest.raises(ReplicaIsLocked):
        replica_client.set_tombstone([{'rse': rse, 'scope': mock_scope.external, 'name': name}])

    # Set tombstone on not found replica
    name = generate_uuid()
    with pytest.raises(ReplicaNotFound):
        replica_client.set_tombstone([{'rse': rse, 'scope': mock_scope.external, 'name': name}])


def test_client_get_nrandom(rse_factory, did_factory, did_client, replica_client):
    """ REPLICA (CLIENT): get N random replicas from a dataset"""
    rse, _ = rse_factory.make_posix_rse()

    dataset = did_factory.make_dataset()
    dataset = {'scope': dataset['scope'].external, 'name': dataset['name']}

    files = []
    for _ in range(10):
        file = did_factory.upload_test_file(rse)
        file = {'scope': file['scope'].external, 'name': file['name']}
        files.append(file)
    did_client.add_files_to_dataset(files=files, **dataset)

    replicas = list(replica_client.list_replicas(dids=[dataset], nrandom=5))
    assert len(replicas) == 5

    # Requesting more files than actually exist in the dataset, will return all files
    replicas = list(replica_client.list_replicas(dids=[dataset], nrandom=15))
    assert len(replicas) == 10


class TestReplicaMetalink:

    @pytest.mark.dirty
    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_client_list_replicas_metalink_4(self, did_client, replica_client):
        """ REPLICA (METALINK): List replicas as metalink version 4 """
        fname = generate_uuid()

        rses = ['MOCK', 'MOCK3', 'MOCK4']
        dsn = generate_uuid()
        files = [{'scope': 'mock', 'name': fname, 'bytes': 1, 'adler32': '0cc737eb'}]

        did_client.add_dataset(scope='mock', name=dsn)
        did_client.add_files_to_dataset('mock', name=dsn, files=files, rse='MOCK')
        for r in rses:
            replica_client.add_replicas(r, files)

        ml = xmltodict.parse(replica_client.list_replicas(files,
                                                          metalink=4,
                                                          all_states=True,
                                                          schemes=['https', 'sftp', 'file']),
                             xml_attribs=False)
        assert 3 == len(ml['metalink']['file']['url'])

    def test_client_get_did_from_pfns_nondeterministic(self, vo, rse_factory, mock_scope, root_account, replica_client):
        """ REPLICA (CLIENT): Get list of DIDs associated to PFNs for non-deterministic sites"""
        rse, rse_id = rse_factory.make_srm_rse(deterministic=False)
        nbfiles = 3
        pfns = []
        input = {}
        rse_info = rsemgr.get_rse_info(rse=rse, vo=vo)
        assert rse_info['deterministic'] is False
        files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
                  'pfn': 'srm://%s.cern.ch/srm/managerv2?SFN=/test/%s/%s' % (rse_id, mock_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
        for f in files:
            input[f['pfn']] = {'scope': f['scope'].external, 'name': f['name']}
        add_replicas(rse_id=rse_id, files=files, account=root_account, ignore_availability=True)
        for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm'], ignore_availability=True):
            for r in replica['rses']:
                pfns.extend(replica['rses'][r])
        for result in replica_client.get_did_from_pfns(pfns, rse):
            pfn = list(result.keys())[0]
            assert input[pfn] == list(result.values())[0]

    def test_client_get_did_from_pfns_deterministic(self, vo, rse_factory, mock_scope, root_account, replica_client):
        """ REPLICA (CLIENT): Get list of DIDs associated to PFNs for deterministic sites"""
        rse, rse_id = rse_factory.make_srm_rse()
        nbfiles = 3
        pfns = []
        input = {}
        rse_info = rsemgr.get_rse_info(rse=rse, vo=vo)
        assert rse_info['deterministic'] is True
        files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        p = rsemgr.create_protocol(rse_info, 'read', scheme='srm')
        for f in files:
            pfn = list(p.lfns2pfns(lfns={'scope': f['scope'].external, 'name': f['name']}).values())[0]
            pfns.append(pfn)
            input[pfn] = {'scope': f['scope'].external, 'name': f['name']}
        add_replicas(rse_id=rse_id, files=files, account=root_account, ignore_availability=True)
        for result in replica_client.get_did_from_pfns(pfns, rse):
            pfn = list(result.keys())[0]
            assert input[pfn] == list(result.values())[0]


@pytest.mark.parametrize("content_type", [Mime.METALINK, Mime.JSON_STREAM])
def test_client_list_replicas_streaming_error(content_type, vo, did_client, replica_client):
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
