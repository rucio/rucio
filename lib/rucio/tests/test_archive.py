# -*- coding: utf-8 -*-
# Copyright 2017-2021 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from rucio.common.utils import generate_uuid
from rucio.core.replica import add_replicas


def test_add_and_list_archive(rse_factory, replica_client, did_client, mock_scope):
    """  ARCHIVE (CLIENT): Add files to archive and list the content """
    rse, _ = rse_factory.make_mock_rse()
    scope = mock_scope.external
    archive_files = ['file_' + generate_uuid() + '.zip' for _ in range(2)]
    files = []
    for i in range(10):
        files.append({'scope': scope, 'name': 'lfn.%s' % str(generate_uuid()),
                      'bytes': 724963570,
                      'adler32': '0cc737eb',
                      'type': 'FILE',
                      'meta': {'guid': str(generate_uuid())}})
    for archive_file in archive_files:

        replica_client.add_replicas(rse=rse, files=[{'scope': scope,
                                                     'name': archive_file,
                                                     'bytes': 1,
                                                     'adler32': '0cc737eb'}])

        did_client.add_files_to_archive(scope=scope, name=archive_file, files=files)

        content = [f for f in did_client.list_archive_content(scope=scope, name=archive_file)]

        assert len(content) == 10


def test_list_archive_contents_transparently(rse_factory, replica_client, did_client, mock_scope, root_account):
    """ ARCHIVE (CORE): Transparent archive listing """

    rse, rse_id = rse_factory.make_xroot_rse()

    # register archive
    archive = {'scope': mock_scope, 'name': 'weighted.storage.cube.zip', 'type': 'FILE',
               'bytes': 2596, 'adler32': 'beefdead'}
    archive_client = archive.copy()
    archive_client['scope'] = archive_client['scope'].external

    add_replicas(rse_id=rse_id, files=[archive], account=root_account)

    # archived files with replicas
    files_with_replicas = [{'scope': mock_scope, 'name': 'witrep-%i-%s' % (i, str(generate_uuid())), 'type': 'FILE',
                            'bytes': 1234, 'adler32': 'deadbeef'} for i in range(2)]
    files_with_replicas_client = []
    for f in files_with_replicas:
        new_file = f.copy()
        new_file['scope'] = new_file['scope'].external
        files_with_replicas_client.append(new_file)

    add_replicas(rse_id=rse_id, files=files_with_replicas, account=root_account)
    did_client.add_files_to_archive(scope=archive_client['scope'], name=archive_client['name'], files=files_with_replicas_client)

    res = [r['pfns'] for r in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files_with_replicas_client],
                                                           resolve_archives=True)]
    assert len(res) == 2
    assert len(res[0]) == 2
    assert len(res[1]) == 2
    for r in res:
        for p in r:
            if r[p]['domain'] == 'zip':
                assert 'weighted.storage.cube.zip?xrdcl.unzip=witrep-' in p
            else:
                assert 'weighted.storage.cube.zip?xrdcl.unzip=witrep-' not in p

    # archived files without replicas
    files = [{'scope': mock_scope.external, 'name': 'norep-%i-%s' % (i, str(generate_uuid())), 'type': 'FILE',
              'bytes': 1234, 'adler32': 'deadbeef'} for i in range(2)]
    did_client.add_files_to_archive(scope=archive_client['scope'], name=archive_client['name'], files=files)
    res = [r['pfns'] for r in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files],
                                                           resolve_archives=True)]
    assert len(res) == 2
    for r in res:
        assert 'weighted.storage.cube.zip?xrdcl.unzip=norep-' in list(r.keys())[0]


def test_list_archive_contents_at_rse(rse_factory, mock_scope, root_account, did_client, replica_client):
    """ ARCHIVE (CORE): Transparent archive listing at RSE """

    rse1, rse1_id = rse_factory.make_xroot_rse()
    rse2, rse2_id = rse_factory.make_xroot_rse()
    # register archive
    archive1 = {'scope': mock_scope, 'name': 'cube.1.zip', 'type': 'FILE', 'bytes': 2596, 'adler32': 'beefdead'}
    archive2 = {'scope': mock_scope, 'name': 'cube.2.zip', 'type': 'FILE', 'bytes': 5432, 'adler32': 'deadbeef'}
    add_replicas(rse_id=rse1_id, files=[archive1], account=root_account)
    add_replicas(rse_id=rse2_id, files=[archive2], account=root_account)

    # archived files with replicas
    archived_file = [{'scope': mock_scope.external, 'name': 'zippedfile-%i-%s' % (i, str(generate_uuid())), 'type': 'FILE',
                      'bytes': 4322, 'adler32': 'beefbeef'} for i in range(2)]
    did_client.add_files_to_archive(scope=mock_scope.external, name=archive1['name'], files=archived_file)
    did_client.add_files_to_archive(scope=mock_scope.external, name=archive2['name'], files=archived_file)

    res = [r['pfns'] for r in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in archived_file],
                                                           rse_expression=rse1,
                                                           resolve_archives=True)]

    res = replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in archived_file], metalink=True, rse_expression=rse1, resolve_archives=True)
    assert rse1 in res
    assert rse2 not in res

    res = replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in archived_file], metalink=True, rse_expression=rse2, resolve_archives=True)
    assert rse1 not in res
    assert rse2 in res
