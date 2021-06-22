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
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2021
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from rucio.common.utils import generate_uuid
from rucio.core.replica import add_replicas, delete_replicas
from rucio.core.rse import add_protocol, update_rse
from rucio.core.did import attach_dids, get_metadata


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

    # if archive file is on a blocklisted RSE, it must not be listed
    both_rses = rse1 + '|' + rse2
    update_rse(rse1_id, {'availability_read': False})
    update_rse(rse2_id, {'availability_read': False})
    res = replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in archived_file],
                                       metalink=True, rse_expression=both_rses, resolve_archives=True, ignore_availability=False)
    assert rse1 not in res
    assert rse2 not in res
    res = replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in archived_file], metalink=True, rse_expression=both_rses, resolve_archives=True)
    assert rse1 in res
    assert rse2 in res


def test_archive_on_dataset_level(rse_factory, did_factory, root_account):
    rse_name, rse_id = rse_factory.make_xroot_rse()

    dataset1 = did_factory.make_dataset()
    dataset2 = did_factory.make_dataset()
    container = did_factory.make_container()
    attach_dids(dids=[dataset1, dataset2], account=root_account, **container)

    # Add a random file to the datasets to avoid dataset deletion when the archive is deleted
    a_file = did_factory.random_did()
    add_replicas(rse_id=rse_id, files=[{**a_file, 'bytes': 500, 'type': 'FILE', 'adler32': 'beefbeef'}], account=root_account)
    attach_dids(dids=[a_file], account=root_account, **dataset1)
    attach_dids(dids=[a_file], account=root_account, **dataset2)
    # adding a non-archive file should not set is_archive=True
    metadata = get_metadata(**dataset1)
    assert not metadata['is_archive']

    # Create an archive and its constituents, attach the archive to datasets
    archive = did_factory.random_did(name_prefix='archive', name_suffix='.zip')
    add_replicas(rse_id=rse_id, files=[{**archive, 'bytes': 500, 'type': 'FILE', 'adler32': 'beefbeef'}], account=root_account)
    constituents = [did_factory.random_did() for _ in range(2)]
    # Add archive to one dataset _before_ attaching files to the archive (before is_archive is set on the archive did)
    attach_dids(dids=[archive], account=root_account, **dataset1)
    attach_dids(dids=[{**c, 'bytes': 200, 'adler32': 'ababbaba'} for c in constituents], account=root_account, **archive)
    # Attach to another dataset _after_ attaching files to the archive
    attach_dids(dids=[archive], account=root_account, **dataset2)

    # Both datasets must have is_archive = True
    metadata = get_metadata(**dataset1)
    assert metadata['is_archive'] is True
    metadata = get_metadata(**dataset2)
    assert metadata['is_archive'] is True

    # Delete the archive, the datasets must now have is_archive == false
    delete_replicas(rse_id=rse_id, files=[archive])

    metadata = get_metadata(**dataset1)
    assert not metadata['is_archive']
    metadata = get_metadata(**dataset2)
    assert not metadata['is_archive']


def test_root_priority_is_highest(rse_factory, mock_scope, root_account, did_client, replica_client):
    """ ARCHIVE (CORE): Ensure that the root protocol is prioritized for archives"""

    # Add 2 RSEs. Set the root protocol to have the lowest priority overall
    rse1, rse1_id = rse_factory.make_rse()
    rse2, rse2_id = rse_factory.make_rse()
    add_protocol(rse1_id, {'scheme': 'file',
                           'hostname': 'xrootpriority1.aperture.com',
                           'port': 1409,
                           'prefix': '/prefix1/',
                           'impl': 'rucio.rse.protocols.posix.Default',
                           'domains': {
                               'lan': {'read': 1, 'write': 1, 'delete': 1},
                               'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse1_id, {'scheme': 'root',
                           'hostname': 'xrootpriority1.aperture.com',
                           'port': 1410,
                           'prefix': '/prefix2/',
                           'impl': 'rucio.rse.protocols.xrootd.Default',
                           'domains': {
                               'lan': {'read': 2, 'write': 2, 'delete': 2},
                               'wan': {'read': 2, 'write': 2, 'delete': 2}}})
    add_protocol(rse2_id, {'scheme': 'file',
                           'hostname': 'xrootpriority2.aperture.com',
                           'port': 1409,
                           'prefix': '/prefix3/',
                           'impl': 'rucio.rse.protocols.posix.Default',
                           'domains': {
                               'lan': {'read': 1, 'write': 1, 'delete': 1},
                               'wan': {'read': 1, 'write': 1, 'delete': 1}}})

    # register archive
    archive = {'scope': mock_scope, 'name': 'cube.1.zip', 'type': 'FILE', 'bytes': 2596, 'adler32': 'beefdead'}
    add_replicas(rse_id=rse1_id, files=[archive], account=root_account)
    add_replicas(rse_id=rse2_id, files=[archive], account=root_account)

    # archived files with replicas
    archived_file = [{'scope': mock_scope, 'name': 'zippedfile-%i-%s' % (i, str(generate_uuid())), 'type': 'FILE',
                      'bytes': 4322, 'adler32': 'beefbeef'} for i in range(2)]
    did_client.add_files_to_archive(scope=mock_scope.external, name=archive['name'], files=archived_file)

    both_rses = '%s|%s' % (rse1, rse2)
    replicas = list(replica_client.list_replicas(dids=[{'scope': f['scope'].external, 'name': f['name']} for f in archived_file], rse_expression=both_rses))

    for replica in replicas:
        # The root protocol pfn must have the smallest (best) priority
        assert len(replica['pfns']) == 3
        root_pfn = next(filter(lambda pfn: pfn.startswith('root'), replica['pfns']))
        posix_pfn = next(filter(lambda pfn: pfn.startswith('file'), replica['pfns']))
        assert replica['pfns'][root_pfn]['priority'] == 1
        assert replica['pfns'][root_pfn]['priority'] < replica['pfns'][posix_pfn]['priority']

        # The root protocol supports downloading files directly from archives. Client_extract must be false
        assert not replica['pfns'][root_pfn]['client_extract']
        assert replica['pfns'][posix_pfn]['client_extract']

        assert replica['pfns'][root_pfn]['domain'] == 'zip'
        assert replica['pfns'][posix_pfn]['domain'] == 'zip'
