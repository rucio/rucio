# Copyright 2017-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2017-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from nose.tools import assert_equal, assert_in, assert_not_in

from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.replica import add_replicas
from rucio.core.rse import add_rse, add_protocol
from rucio.tests.common import rse_name_generator


class TestArchive(object):

    def __init__(self):
        self.dc = DIDClient()
        self.rc = ReplicaClient()

        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

    def test_add_and_list_archive(self):
        """  ARCHIVE (CLIENT): Add files to archive and list the content """
        scope, rse = 'mock', 'MOCK'
        archive_files = ['file_' + generate_uuid() + '.zip' for _ in range(2)]
        files = []
        for i in range(10):
            files.append({'scope': scope, 'name': 'lfn.%s' % str(generate_uuid()),
                          'bytes': 724963570,
                          'adler32': '0cc737eb',
                          'type': 'FILE',
                          'meta': {'guid': str(generate_uuid())}})
        for archive_file in archive_files:

            self.rc.add_replicas(rse=rse, files=[{'scope': scope,
                                                  'name': archive_file,
                                                  'bytes': 1,
                                                  'adler32': '0cc737eb'}])

            self.dc.add_files_to_archive(scope=scope, name=archive_file, files=files)

            content = [f for f in self.dc.list_archive_content(scope=scope, name=archive_file)]

            assert_equal(len(content), 10)

    def test_list_archive_contents_transparently(self):
        """ ARCHIVE (CORE): Transparent archive listing """

        scope = InternalScope('mock', **self.vo)
        rse = 'APERTURE_%s' % rse_name_generator()
        rse_id = add_rse(rse, **self.vo)
        root = InternalAccount('root', **self.vo)

        add_protocol(rse_id, {'scheme': 'root',
                              'hostname': 'root.aperture.com',
                              'port': 1409,
                              'prefix': '//test/chamber/',
                              'impl': 'rucio.rse.protocols.xrootd.Default',
                              'domains': {
                                  'lan': {'read': 1, 'write': 1, 'delete': 1},
                                  'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        # register archive
        archive = {'scope': scope, 'name': 'weighted.storage.cube.zip', 'type': 'FILE',
                   'bytes': 2596, 'adler32': 'beefdead'}
        archive_client = archive.copy()
        archive_client['scope'] = archive_client['scope'].external

        add_replicas(rse_id=rse_id, files=[archive], account=root)

        # archived files with replicas
        files_with_replicas = [{'scope': scope, 'name': 'witrep-%i-%s' % (i, str(generate_uuid())), 'type': 'FILE',
                                'bytes': 1234, 'adler32': 'deadbeef'} for i in range(2)]
        files_with_replicas_client = []
        for f in files_with_replicas:
            new_file = f.copy()
            new_file['scope'] = new_file['scope'].external
            files_with_replicas_client.append(new_file)

        add_replicas(rse_id=rse_id, files=files_with_replicas, account=root)
        self.dc.add_files_to_archive(scope=archive_client['scope'], name=archive_client['name'], files=files_with_replicas_client)

        res = [r['pfns'] for r in self.rc.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files_with_replicas_client],
                                                        resolve_archives=True)]
        assert_equal(len(res), 2)
        assert_equal(len(res[0]), 2)
        assert_equal(len(res[1]), 2)
        for r in res:
            for p in r:
                if r[p]['domain'] == 'zip':
                    assert_in('weighted.storage.cube.zip?xrdcl.unzip=witrep-', p)
                else:
                    assert_not_in('weighted.storage.cube.zip?xrdcl.unzip=witrep-', p)

        # archived files without replicas
        files = [{'scope': scope.external, 'name': 'norep-%i-%s' % (i, str(generate_uuid())), 'type': 'FILE',
                  'bytes': 1234, 'adler32': 'deadbeef'} for i in range(2)]
        self.dc.add_files_to_archive(scope=archive_client['scope'], name=archive_client['name'], files=files)
        res = [r['pfns'] for r in self.rc.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files],
                                                        resolve_archives=True)]
        assert_equal(len(res), 2)
        for r in res:
            assert_in('weighted.storage.cube.zip?xrdcl.unzip=norep-', list(r.keys())[0])

    def test_list_archive_contents_at_rse(self):
        """ ARCHIVE (CORE): Transparent archive listing at RSE """

        scope = InternalScope('mock', **self.vo)
        root = InternalAccount('root', **self.vo)

        rse1 = 'APERTURE_%s' % rse_name_generator()
        rse1_id = add_rse(rse1, **self.vo)
        add_protocol(rse1_id, {'scheme': 'root',
                               'hostname': 'root.aperture.com',
                               'port': 1409,
                               'prefix': '//test/chamber/',
                               'impl': 'rucio.rse.protocols.xrootd.Default',
                               'domains': {
                                   'lan': {'read': 1, 'write': 1, 'delete': 1},
                                   'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        rse2 = 'BLACKMESA_%s' % rse_name_generator()
        rse2_id = add_rse(rse2, **self.vo)
        add_protocol(rse2_id, {'scheme': 'root',
                               'hostname': 'root.blackmesa.com',
                               'port': 1409,
                               'prefix': '//lambda/complex/',
                               'impl': 'rucio.rse.protocols.xrootd.Default',
                               'domains': {
                                   'lan': {'read': 1, 'write': 1, 'delete': 1},
                                   'wan': {'read': 1, 'write': 1, 'delete': 1}}})

        # register archive
        archive1 = {'scope': scope, 'name': 'cube.1.zip', 'type': 'FILE', 'bytes': 2596, 'adler32': 'beefdead'}
        archive2 = {'scope': scope, 'name': 'cube.2.zip', 'type': 'FILE', 'bytes': 5432, 'adler32': 'deadbeef'}
        add_replicas(rse_id=rse1_id, files=[archive1], account=root)
        add_replicas(rse_id=rse2_id, files=[archive2], account=root)

        # archived files with replicas
        archived_file = [{'scope': scope.external, 'name': 'zippedfile-%i-%s' % (i, str(generate_uuid())), 'type': 'FILE',
                          'bytes': 4322, 'adler32': 'beefbeef'} for i in range(2)]
        self.dc.add_files_to_archive(scope=scope.external, name=archive1['name'], files=archived_file)
        self.dc.add_files_to_archive(scope=scope.external, name=archive2['name'], files=archived_file)

        res = [r['pfns'] for r in self.rc.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in archived_file],
                                                        rse_expression=rse1,
                                                        resolve_archives=True)]

        res = self.rc.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in archived_file], metalink=True, rse_expression=rse1, resolve_archives=True)
        assert_in('APERTURE', res)
        assert_not_in('BLACKMESA', res)

        res = self.rc.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in archived_file], metalink=True, rse_expression=rse2, resolve_archives=True)
        assert_in('BLACKMESA', res)
        assert_not_in('APERTURE', res)
