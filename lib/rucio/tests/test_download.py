# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import logging
import os
import shutil
import tarfile
from tempfile import TemporaryDirectory
from unittest.mock import ANY, MagicMock, patch
from zipfile import ZipFile

import pytest

from rucio.client.downloadclient import DownloadClient
from rucio.common.config import config_add_section, config_set
from rucio.common.exception import InputValidationError, NoFilesDownloaded, RucioException
from rucio.common.types import InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import did as did_core
from rucio.core import scope as scope_core
from rucio.core.rse import add_protocol
from rucio.client.downloadclient import FileDownloadState
from rucio.rse import rsemanager as rsemgr
from rucio.rse.protocols.posix import Default as PosixProtocol
from rucio.tests.common import skip_rse_tests_with_accounts, scope_name_generator, file_generator


@pytest.fixture
def download_client():
    logger = logging.getLogger('dlul_client')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)
    return DownloadClient(logger=logger)


def _check_download_result(actual_result, expected_result):
    assert len(expected_result) == len(actual_result)
    expected_result = sorted(expected_result, key=lambda x: x['did'])
    actual_result = sorted(actual_result, key=lambda x: x['did'])
    for i, expected in enumerate(expected_result):
        for param_name, expected_value in expected.items():
            assert param_name and actual_result[i][param_name] == expected[param_name]


def test_download_without_base_dir(rse_factory, did_factory, download_client):
    scope = str(did_factory.default_scope)
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    did_str = '%s:%s' % (did['scope'], did['name'])
    try:
        # download to the default location, i.e. to ./
        result = download_client.download_dids([{'did': did_str}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': did_str,
                    'clientState': 'DONE',
                }
            ],
        )

        # re-downloading the same file again should not overwrite it
        result = download_client.download_dids([{'did': did_str}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': did_str,
                    'clientState': 'ALREADY_DONE',
                }
            ],
        )
    finally:
        shutil.rmtree(scope)


def test_download_exception_return_information(did_factory, rse_factory, download_client):
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    did_str = '%s:%s' % (did['scope'], did['name'])

    with patch('rucio.client.downloadclient.DownloadClient._download_item', side_effect=Exception()):
        res = download_client.download_dids([{"did": did_str}], deactivate_file_download_exceptions=True)

    assert len(res) == 1
    assert res[0]["clientState"] == "FAILED"


@pytest.mark.dirty(reason='creates a new scope which is not cleaned up')
def test_overlapping_did_names(rse_factory, did_factory, download_client, root_account, mock_scope, vo):
    """
    Downloading two different did with different scope but same name to the same directory must fail
    """
    rse, _ = rse_factory.make_posix_rse()
    scope1 = mock_scope
    scope2 = InternalScope(scope_name_generator(), vo=vo)
    scope_core.add_scope(scope2, root_account)
    did1 = did_factory.upload_test_file(rse, scope=scope1)
    did2 = did_factory.upload_test_file(rse, scope=scope2, name=did1['name'])
    dataset = did_factory.make_dataset()
    did_core.attach_dids(dids=[did1, did2], account=root_account, **dataset)

    did1_str = '%s:%s' % (did1['scope'], did1['name'])
    did2_str = '%s:%s' % (did2['scope'], did2['name'])
    dataset1_did_str = '%s:%s' % (dataset['scope'], dataset['name'])

    with TemporaryDirectory() as tmp_dir:
        with pytest.raises(RucioException):
            download_client.download_dids([{'did': dataset1_did_str, 'base_dir': tmp_dir, 'no_subdir': True}])

    with TemporaryDirectory() as tmp_dir:
        with pytest.raises(RucioException):
            download_client.download_dids([{'did': did1_str, 'base_dir': tmp_dir, 'no_subdir': True},
                                           {'did': did2_str, 'base_dir': tmp_dir, 'no_subdir': True}])


def test_overlapping_containers_and_wildcards(rse_factory, did_factory, download_client, root_account):
    """
    Verify that wildcard resolution is correctly done. Overlapping containers and wildcards are handled without issues.
    """
    rse1, _ = rse_factory.make_posix_rse()
    rse2, _ = rse_factory.make_posix_rse()
    dids_on_rse1 = [did_factory.upload_test_file(rse1) for _ in range(5)]
    dids_on_rse2 = [did_factory.upload_test_file(rse2) for _ in range(5)]
    dids = dids_on_rse1 + dids_on_rse2
    datasets = [did_factory.make_dataset() for _ in range(3)]
    container = did_factory.make_container()
    dids_in_dataset1, dids_in_dataset2, dids_in_dataset3 = dids[:6], dids[3:7], dids[4:]
    did_core.attach_dids(dids=dids_in_dataset1, account=root_account, **datasets[0])
    did_core.attach_dids(dids=dids_in_dataset2, account=root_account, **datasets[1])
    did_core.attach_dids(dids=dids_in_dataset3, account=root_account, **datasets[2])
    did_core.attach_dids(dids=datasets, account=root_account, **container)

    dataset1_str, dataset2_str, dataset3_str = ['%s:%s' % (d['scope'], d['name']) for d in datasets]
    container_str = '%s:%s' % (container['scope'], container['name'])

    with TemporaryDirectory() as tmp_dir:
        # No filters: all dids will be grouped and downloaded together
        result = download_client.download_dids([{'did': dataset1_str, 'base_dir': tmp_dir},
                                                {'did': dataset2_str, 'base_dir': tmp_dir},
                                                {'did': dataset3_str, 'base_dir': tmp_dir},
                                                {'did': container_str, 'base_dir': tmp_dir}])
        assert len(result) == len(dids)

    with TemporaryDirectory() as tmp_dir:
        # Verify that wildcard resolution works correctly
        result = download_client.download_dids([{'did': '%s:%sdataset_*' % (did_factory.default_scope, did_factory.name_prefix), 'base_dir': tmp_dir},
                                                {'did': container_str, 'base_dir': tmp_dir}])
        assert len(result) == len(dids)

    with TemporaryDirectory() as tmp_dir:
        # Test with an RSE filter
        result = download_client.download_dids([{'did': dataset1_str, 'base_dir': tmp_dir, 'rse': rse1},
                                                {'did': dataset2_str, 'base_dir': tmp_dir, 'rse': rse1},
                                                {'did': dataset3_str, 'base_dir': tmp_dir, 'rse': rse1}])
        assert len(result) == len(dids_on_rse1)

    with TemporaryDirectory() as tmp_dir1, TemporaryDirectory() as tmp_dir2, TemporaryDirectory() as tmp_dir3:
        # Test with nrandom
        result = download_client.download_dids([{'did': dataset1_str, 'base_dir': tmp_dir1, 'nrandom': 3},
                                                {'did': dataset2_str, 'base_dir': tmp_dir2, 'nrandom': 3},
                                                {'did': dataset3_str, 'base_dir': tmp_dir3, 'nrandom': 3}])
        assert 3 <= len(result) <= 9

    with TemporaryDirectory() as tmp_dir1, TemporaryDirectory() as tmp_dir2:
        # Test with filters complex overlapping of filters and different destination directories
        download_client.download_dids([{'did': dataset1_str, 'base_dir': tmp_dir1, 'rse': rse1},
                                       {'did': dataset2_str, 'base_dir': tmp_dir1, 'rse': rse2},
                                       {'did': dataset3_str, 'base_dir': tmp_dir2, 'rse': rse2}])
        dids_on_rse1_and_dataset1 = [d for d in dids_on_rse1 if d in dids_in_dataset1]
        dids_on_rse2_and_dataset2 = [d for d in dids_on_rse2 if d in dids_in_dataset2]
        dids_on_rse2_and_dataset3 = [d for d in dids_on_rse2 if d in dids_in_dataset3]

        for dst_dir, expected_dids in (('%s/%s' % (tmp_dir1, datasets[0]['name']), dids_on_rse1_and_dataset1),
                                       ('%s/%s' % (tmp_dir1, datasets[1]['name']), dids_on_rse2_and_dataset2),
                                       ('%s/%s' % (tmp_dir2, datasets[2]['name']), dids_on_rse2_and_dataset3)):
            files_in_dir = os.listdir(dst_dir)
            for did in expected_dids:
                assert did['name'] in files_in_dir

            assert len(files_in_dir) == len(expected_dids)


def test_download_to_two_paths(rse_factory, did_factory, download_client):
    scope = str(did_factory.default_scope)
    rse, _ = rse_factory.make_posix_rse()
    base_name = generate_uuid()
    item000 = did_factory.upload_test_file(rse, name=base_name + '.000', return_full_item=True)
    item001 = did_factory.upload_test_file(rse, name=base_name + '.001', return_full_item=True)
    item100 = did_factory.upload_test_file(rse, name=base_name + '.100', return_full_item=True)
    did000_str = '%s:%s' % (item000['did_scope'], item000['did_name'])
    did001_str = '%s:%s' % (item001['did_scope'], item001['did_name'])
    did100_str = '%s:%s' % (item100['did_scope'], item100['did_name'])

    with TemporaryDirectory() as tmp_dir1, TemporaryDirectory() as tmp_dir2:
        # Download two overlapping wildcard dids to two separate paths.
        # 000 will be in both paths. Other two files only in one of the two paths.
        result = download_client.download_dids([{'did': '%s:%s.*0' % (scope, base_name), 'base_dir': tmp_dir1},
                                                {'did': '%s:%s.0*' % (scope, base_name), 'base_dir': tmp_dir2}])
        paths000 = next(filter(lambda r: r['did'] == did000_str, result))['dest_file_paths']
        paths001 = next(filter(lambda r: r['did'] == did001_str, result))['dest_file_paths']
        paths100 = next(filter(lambda r: r['did'] == did100_str, result))['dest_file_paths']

        assert len(paths000) == 2
        assert any(p.startswith(tmp_dir1) for p in paths000)
        assert any(p.startswith(tmp_dir2) for p in paths000)

        assert len(paths001) == 1
        assert paths001[0].startswith(tmp_dir2)

        assert len(paths100) == 1
        assert paths100[0].startswith(tmp_dir1)


def test_download_multiple(rse_factory, did_factory, download_client):
    scope = str(did_factory.default_scope)
    rse, _ = rse_factory.make_posix_rse()
    base_name = generate_uuid()
    item000 = did_factory.upload_test_file(rse, name=base_name + '.000', return_full_item=True)
    item001 = did_factory.upload_test_file(rse, name=base_name + '.001', return_full_item=True)
    item100 = did_factory.upload_test_file(rse, name=base_name + '.100', return_full_item=True)
    did000_str = '%s:%s' % (item000['did_scope'], item000['did_name'])
    did001_str = '%s:%s' % (item001['did_scope'], item001['did_name'])
    did100_str = '%s:%s' % (item100['did_scope'], item100['did_name'])

    with TemporaryDirectory() as tmp_dir:
        # Download specific DID
        result = download_client.download_dids([{'did': did000_str, 'base_dir': tmp_dir}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': did000_str,
                    'clientState': 'DONE',
                }
            ],
        )

        # Download multiple files with wildcard. One file already exists on the file system. Will not be re-downloaded.
        result = download_client.download_dids([{'did': '%s:%s.0*' % (scope, base_name), 'base_dir': tmp_dir}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': did000_str,
                    'clientState': 'ALREADY_DONE',
                },
                {
                    'did': did001_str,
                    'clientState': 'DONE',
                },
            ],
        )

        # Download with filter
        result = download_client.download_dids([{'filters': {'guid': item000['guid'], 'scope': scope}, 'base_dir': tmp_dir}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': did000_str,
                }
            ],
        )

        # Download with wildcard and name
        result = download_client.download_dids([{'did': '%s:*' % scope, 'filters': {'guid': item100['guid']}, 'base_dir': tmp_dir}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': did100_str,
                    'clientState': 'DONE',
                }
            ],
        )

        # Don't create subdirectories by scope
        result = download_client.download_dids([{'did': '%s:%s.*' % (scope, base_name), 'base_dir': tmp_dir, 'no_subdir': True}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': did000_str,
                    'clientState': 'DONE',
                    'dest_file_paths': ['%s/%s' % (tmp_dir, item000['did_name'])],
                },
                {
                    'did': did001_str,
                    'clientState': 'DONE',
                    'dest_file_paths': ['%s/%s' % (tmp_dir, item001['did_name'])],
                },
                {
                    'did': did100_str,
                    'clientState': 'DONE',
                    'dest_file_paths': ['%s/%s' % (tmp_dir, item100['did_name'])],
                },
            ],
        )

        # Re-download file existing on the file system with no-subdir set. It must be overwritten.
        result = download_client.download_dids([{'did': did100_str, 'base_dir': tmp_dir, 'no_subdir': True}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': did100_str,
                    'clientState': 'ALREADY_DONE',
                    'dest_file_paths': ['%s/%s' % (tmp_dir, item100['did_name'])],
                }
            ],
        )


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined XRD1 RSE, may fails when run in parallel')  # TODO: verify if it really fails
@skip_rse_tests_with_accounts
def test_download_from_archive_on_xrd(did_factory, download_client, did_client):
    scope = 'test'
    rse = 'XRD1'
    base_name = 'testDownloadArchive' + generate_uuid()
    with TemporaryDirectory() as tmp_dir:
        # Create a zip archive with two files and upload it
        name000 = base_name + '.000'
        data000 = '000'
        adler000 = '01230091'
        name001 = base_name + '.001'
        data001 = '001'
        adler001 = '01240092'
        zip_name = base_name + '.zip'
        zip_path = '%s/%s' % (tmp_dir, zip_name)
        with ZipFile(zip_path, 'w') as myzip:
            myzip.writestr(name000, data=data000)
            myzip.writestr(name001, data=data001)
        did_factory.upload_test_file(rse, scope=scope, name=zip_name, path=zip_path)
        did_client.add_files_to_archive(
            scope,
            zip_name,
            [
                {'scope': scope, 'name': name000, 'bytes': len(data000), 'type': 'FILE', 'adler32': adler000, 'meta': {'guid': str(generate_uuid())}},
                {'scope': scope, 'name': name001, 'bytes': len(data001), 'type': 'FILE', 'adler32': adler001, 'meta': {'guid': str(generate_uuid())}},
            ],
        )

        # Download one file from the archive
        result = download_client.download_dids([{'did': '%s:%s' % (scope, name000), 'base_dir': tmp_dir}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': '%s:%s' % (scope, name000),
                    'clientState': 'DONE',
                },
            ],
        )
        with open('%s/%s/%s' % (tmp_dir, scope, name000), 'r') as file:
            assert file.read() == data000

        # Download both files from the archive
        result = download_client.download_dids([{'did': '%s:%s.00*' % (scope, base_name), 'base_dir': tmp_dir}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': '%s:%s' % (scope, name000),
                    'clientState': 'ALREADY_DONE',
                },
                {
                    'did': '%s:%s' % (scope, name001),
                    'clientState': 'DONE',
                },
            ],
        )
        with open('%s/%s/%s' % (tmp_dir, scope, name001), 'r') as file:
            assert file.read() == data001

        pfn = next(filter(lambda r: name001 in r['did'], result))['sources'][0]['pfn']
        # Download by pfn from the archive
        result = download_client.download_pfns([{'did': '%s:%s' % (scope, name001), 'pfn': pfn, 'rse': rse, 'base_dir': tmp_dir, 'no_subdir': True}])
        _check_download_result(
            actual_result=result,
            expected_result=[
                {
                    'did': '%s:%s' % (scope, name001),
                    'clientState': 'DONE',
                },
            ],
        )


def test_download_archive_client_extract(rse_factory, did_factory, download_client, did_client, mock_scope):
    """
    Verify that client extraction works correctly for files inside archives
    """
    rse, _ = rse_factory.make_posix_rse()
    scope = mock_scope.external
    base_name = 'testDownloadClientExtract' + generate_uuid()
    with TemporaryDirectory() as tmp_dir:
        # Create a tar archive with a file inside and upload it
        name = base_name + '.000'
        data = '000'
        adler32 = '01230091'
        tar_name = base_name + '.tar.gz'
        tar_path = '%s/%s' % (tmp_dir, tar_name)
        with tarfile.open(tar_path, 'w:gz') as tar:
            file_path = "%s/%s" % (tmp_dir, name)
            with open(file_path, 'w') as file:
                file.write(data)
            tar.add(file_path, arcname=name)
        did_factory.upload_test_file(rse, scope=scope, name=tar_name, path=tar_path)
        did_client.add_files_to_archive(scope, tar_name, [
            {'scope': scope, 'name': name, 'bytes': len(data), 'type': 'FILE', 'adler32': adler32, 'meta': {'guid': str(generate_uuid())}},
        ])

    with TemporaryDirectory() as tmp_dir:
        with pytest.raises(NoFilesDownloaded):
            # If archive resolution is disabled, the download must fail
            download_client.download_dids([{'did': '%s:%s' % (scope, name), 'base_dir': tmp_dir, 'no_resolve_archives': True}])

    with TemporaryDirectory() as tmp_dir:
        result = download_client.download_dids([{'did': '%s:%s' % (scope, name), 'base_dir': tmp_dir}])
        assert len(result) == 1
        with open('%s/%s/%s' % (tmp_dir, scope, name), 'r') as file:
            assert file.read() == data


@pytest.mark.dirty
def test_trace_copy_out_and_checksum_validation(vo, rse_factory, did_factory, download_client):
    rse, _ = rse_factory.make_posix_rse()
    scope = str(did_factory.default_scope)
    did = did_factory.upload_test_file(rse)
    did_str = '%s:%s' % (did['scope'], did['name'])

    with TemporaryDirectory() as tmp_dir:
        # Try downloading non-existing did
        traces = []
        with pytest.raises(NoFilesDownloaded):
            download_client.download_dids([{'did': 'some:randomNonExistingDid', 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'FILE_NOT_FOUND'

        # Download specific DID
        traces = []
        download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'DONE'

        # Download same DID again
        traces = []
        result = download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'ALREADY_DONE'

        # Change the local file and download the same file again. Checksum validation should fail and it must be re-downloaded
        with open(result[0]['dest_file_paths'][0], 'a') as f:
            f.write("more data")
        traces = []
        result = download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'DONE'

        pfn = result[0]['sources'][0]['pfn']

    # Switch to a new empty directory
    with TemporaryDirectory() as tmp_dir:
        # Wildcards in did name are not allowed on pfn downloads
        traces = []
        with pytest.raises(InputValidationError):
            download_client.download_pfns([{'did': '%s:*' % scope, 'pfn': pfn, 'rse': rse, 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert not traces

        # Same pfn, but without wildcard in the did should work
        traces = []
        download_client.download_pfns([{'did': did_str, 'pfn': pfn, 'rse': rse, 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'DONE'

        # Same pfn. Local file already present. Shouldn't be overwritten.
        traces = []
        download_client.download_pfns([{'did': did_str, 'pfn': pfn, 'rse': rse, 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'ALREADY_DONE'

        # Provide wrong checksum for validation, the file will be re-downloaded but checksum validation fails
        traces = []
        with pytest.raises(NoFilesDownloaded):
            download_client.download_pfns([{'did': did_str, 'pfn': pfn, 'rse': rse, 'adler32': 'wrong', 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'FAIL_VALIDATE'

    # Switch to a new empty directory
    with TemporaryDirectory() as tmp_dir:
        # Simulate checksum corruption by changing the source file. We rely on the particularity
        # that the MOCK4 rse uses the posix protocol: files are stored on the local file system
        protocol = rsemgr.create_protocol(rsemgr.get_rse_info(rse, vo=vo), operation='read')
        assert isinstance(protocol, PosixProtocol)
        mock_rse_local_path = protocol.pfn2path(pfn)
        with open(mock_rse_local_path, 'w') as f:
            f.write('some completely other data')

        # Download fails checksum validation
        traces = []
        with pytest.raises(NoFilesDownloaded):
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'FAIL_VALIDATE'

        # Ignore_checksum set. Download works.
        traces = []
        download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir, 'ignore_checksum': True}], traces_copy_out=traces)
        assert len(traces) == 1 and traces[0]['clientState'] == 'DONE'


def test_disable_no_files_download_error(vo, rse_factory, did_factory, download_client):
    rse, _ = rse_factory.make_posix_rse()
    with TemporaryDirectory() as tmp_dir:
        res = download_client.download_dids([{'did': 'some:randomNonExistingDid', 'base_dir': tmp_dir}], deactivate_file_download_exceptions=True)
        print('Downloaded object', res)
        assert res[0]['clientState'] == 'FILE_NOT_FOUND'


def test_nrandom_respected(rse_factory, did_factory, download_client, root_account):
    rse, _ = rse_factory.make_posix_rse()
    did1 = did_factory.upload_test_file(rse)
    did2 = did_factory.upload_test_file(rse)
    did3 = did_factory.upload_test_file(rse)
    did4 = did_factory.upload_test_file(rse)
    dataset1 = did_factory.make_dataset()
    dataset2 = did_factory.make_dataset()
    did_core.attach_dids(dids=[did1, did2], account=root_account, **dataset1)
    did_core.attach_dids(dids=[did3, did4], account=root_account, **dataset2)

    dataset1_did_str = '%s:%s' % (dataset1['scope'], dataset1['name'])
    dataset2_did_str = '%s:%s' % (dataset2['scope'], dataset2['name'])

    with TemporaryDirectory() as tmp_dir:
        nrandom = 1
        result = download_client.download_dids([{'did': dataset1_did_str, 'nrandom': nrandom, 'base_dir': tmp_dir}])
        assert len(result) == nrandom

    with TemporaryDirectory() as tmp_dir:
        # If two separate items are provided, nrandom applies to each item separately
        nrandom = 1
        result = download_client.download_dids([{'did': dataset1_did_str, 'nrandom': nrandom, 'base_dir': tmp_dir},
                                                {'did': dataset2_did_str, 'nrandom': nrandom, 'base_dir': tmp_dir}])
        assert len(result) == 2 * nrandom

    with TemporaryDirectory() as tmp_dir:
        # If a single item is provided, but it resolves to two datasets, only a single file will be downloaded
        nrandom = 1
        result = download_client.download_dids([{'did': '%s:%sdataset_*' % (did_factory.default_scope, did_factory.name_prefix), 'nrandom': nrandom, 'base_dir': tmp_dir}])
        assert len(result) == nrandom

    with TemporaryDirectory() as tmp_dir:
        nrandom = 2
        result = download_client.download_dids([{'did': dataset1_did_str, 'nrandom': nrandom, 'base_dir': tmp_dir}])
        assert len(result) == nrandom


def test_download_blocklisted_replicas(rse_factory, did_factory, download_client, rse_client):
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    did_str = '%s:%s' % (did['scope'], did['name'])

    rse_client.update_rse(rse, {'availability_read': False})

    with TemporaryDirectory() as tmp_dir:
        with pytest.raises(NoFilesDownloaded):
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir}])


def test_transfer_timeout(rse_factory, did_factory, download_client):
    rse, _ = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    did_str = '%s:%s' % (did['scope'], did['name'])

    mocks_get = []

    # Wraps PosixProtocol and allows to verify with which parameters get() was called
    class CallCounterPosixProtocol(PosixProtocol):
        def __init__(self, *args, mocks_get=mocks_get, **kwargs):
            super(CallCounterPosixProtocol, self).__init__(*args, **kwargs)
            # Every instance of the class will now have its `get` method wrapped in a MagicMock
            self.get = MagicMock(wraps=self.get)
            mocks_get.append(self.get)

    with patch('rucio.rse.protocols.posix.Default', CallCounterPosixProtocol):
        # if none of timeout parameters set, the default value is used
        with TemporaryDirectory() as tmp_dir:
            mocks_get.clear()
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir}])
            mocks_get[0].assert_called_with(ANY, ANY, transfer_timeout=360)

        with TemporaryDirectory() as tmp_dir:
            mocks_get.clear()
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir, 'transfer_timeout': 10}])
            mocks_get[0].assert_called_with(ANY, ANY, transfer_timeout=10)

        # transfer_timeout set. transfer_speed_timeout is ignored.
        with TemporaryDirectory() as tmp_dir:
            mocks_get.clear()
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir, 'transfer_timeout': 5, 'transfer_speed_timeout': 1}])
            mocks_get[0].assert_called_with(ANY, ANY, transfer_timeout=5)

        # 60s static + 2bytes(file size) at 1Bps = 62s
        with TemporaryDirectory() as tmp_dir:
            mocks_get.clear()
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir, 'transfer_speed_timeout': 0.001}])
            mocks_get[0].assert_called_with(ANY, ANY, transfer_timeout=62)

        # 60s static + 2bytes(file size) at high speed = 60s
        with TemporaryDirectory() as tmp_dir:
            mocks_get.clear()
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir, 'transfer_speed_timeout': 10000}])
            mocks_get[0].assert_called_with(ANY, ANY, transfer_timeout=60)

        # transfer_timeout=0 means no timeout
        with TemporaryDirectory() as tmp_dir:
            mocks_get.clear()
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir, 'transfer_timeout': 0}])
            mocks_get[0].assert_called_with(ANY, ANY, transfer_timeout=0)

        # transfer_speed_timeout=0 is ignored
        with TemporaryDirectory() as tmp_dir:
            mocks_get.clear()
            download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir, 'transfer_speed_timeout': 0}])
            mocks_get[0].assert_called_with(ANY, ANY, transfer_timeout=60)


def test_download_file_with_impl(rse_factory, did_factory, download_client, mock_scope):
    """ Download (CLIENT): Ensure the module associated to the impl value is called """

    impl = 'xrootd'
    rse, rse_id = rse_factory.make_rse()
    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 1, 'write': 1, 'delete': 1},
                              'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_id, {'scheme': 'root',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.xrootd.Default',
                          'domains': {
                              'lan': {'read': 2, 'write': 2, 'delete': 2},
                              'wan': {'read': 2, 'write': 2, 'delete': 2}}})
    path = file_generator()
    name = os.path.basename(path)
    item = {
        'path': path,
        'rse': rse,
        'did_scope': str(mock_scope),
        'did_name': name,
        'guid': generate_uuid(),
    }
    did_factory.upload_client.upload([item])
    did_str = '%s:%s' % (mock_scope, name)
    with patch('rucio.rse.protocols.%s.Default.get' % impl, side_effect=lambda pfn, dest, **kw: shutil.copy(path, dest)) as mock_get, \
            patch('rucio.rse.protocols.%s.Default.connect' % impl),\
            patch('rucio.rse.protocols.%s.Default.close' % impl):
        download_client.download_dids([{'did': did_str, 'impl': impl}])
        mock_get.assert_called()


def test_download_file_with_supported_protocol_from_config(rse_factory, did_factory, download_client, mock_scope):
    """ Download (CLIENT): Ensure the module associated to the first protocol supported by both the remote and local config read from rucio.cfg is called """

    rse, rse_id = rse_factory.make_rse()

    # FIXME:
    # The correct order to test should actually be scp,file,root
    # However the preferred_impl is not working correctly.
    # Once preferred_impl is fixed, this should be changed back
    add_protocol(rse_id, {'scheme': 'scp',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.posix.Default',
                          'domains': {
                              'lan': {'read': 1, 'write': 1, 'delete': 1},
                              'wan': {'read': 1, 'write': 1, 'delete': 1}}})
    add_protocol(rse_id, {'scheme': 'file',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.scp.Default',
                          'domains': {
                              'lan': {'read': 2, 'write': 2, 'delete': 2},
                              'wan': {'read': 2, 'write': 2, 'delete': 2}}})
    add_protocol(rse_id, {'scheme': 'root',
                          'hostname': '%s.cern.ch' % rse_id,
                          'port': 0,
                          'prefix': '/test/',
                          'impl': 'rucio.rse.protocols.xrootd.Default',
                          'domains': {
                              'lan': {'read': 3, 'write': 3, 'delete': 3},
                              'wan': {'read': 3, 'write': 3, 'delete': 3}}})

    config_add_section('download')
    config_set('download', 'preferred_impl', 'rclone, xrootd')

    supported_impl = 'xrootd'

    path = file_generator()
    name = os.path.basename(path)
    item = {
        'path': path,
        'rse': rse,
        'did_scope': str(mock_scope),
        'did_name': name,
        'guid': generate_uuid(),
    }
    did_factory.upload_client.upload([item])
    did_str = '%s:%s' % (mock_scope, name)

    with patch('rucio.rse.protocols.%s.Default.get' % supported_impl, side_effect=lambda pfn, dest, **kw: shutil.copy(path, dest)) as mock_get, \
            patch('rucio.rse.protocols.%s.Default.connect' % supported_impl),\
            patch('rucio.rse.protocols.%s.Default.close' % supported_impl):
        download_client.download_dids([{'did': did_str, 'impl': supported_impl}])
        mock_get.assert_called()


def test_download_exclude_tape(rse_factory, did_factory, download_client):
    """Client: Do not download from a tape rse."""
    rse, rse_id = rse_factory.make_posix_rse()
    did = did_factory.upload_test_file(rse)
    did_str = '%s:%s' % (did['scope'], did['name'])

    # We can not mock the server core code here, so mock the API
    with patch('rucio.client.rseclient.RSEClient.list_rses', return_value=[{'rse': rse}]), \
         TemporaryDirectory() as tmp_dir, \
         pytest.raises(NoFilesDownloaded):
        download_client.download_dids([{'did': did_str, 'base_dir': tmp_dir}])


def test_download_states():
    """ Tests the available download states. """
    FileDownloadState.PROCESSING
    FileDownloadState.DOWNLOAD_ATTEMPT
    FileDownloadState.DONE
    FileDownloadState.ALREADY_DONE
    FileDownloadState.FOUND_IN_PCACHE
    FileDownloadState.FILE_NOT_FOUND
    FileDownloadState.FAIL_VALIDATE
    FileDownloadState.FAILED

    assert len(FileDownloadState) == 8
