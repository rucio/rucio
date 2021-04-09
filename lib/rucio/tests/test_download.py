# -*- coding: utf-8 -*-
# Copyright 2019-2021 CERN
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
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Tobias Wegner <twegner@cern.ch>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021

import logging
import shutil
from unittest.mock import patch, MagicMock, ANY
from tempfile import TemporaryDirectory
from zipfile import ZipFile

import pytest

from rucio.client.downloadclient import DownloadClient
from rucio.common.exception import InputValidationError, NoFilesDownloaded
from rucio.common.utils import generate_uuid
from rucio.core import did as did_core
from rucio.rse import rsemanager as rsemgr
from rucio.rse.protocols.posix import Default as PosixProtocol


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


def test_download_without_base_dir(rse_factory, file_factory, download_client):
    scope = str(file_factory.default_scope)
    rse, _ = rse_factory.make_posix_rse()
    did = file_factory.upload_test_file(rse)
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


def test_download_to_two_paths(rse_factory, file_factory, download_client):
    scope = str(file_factory.default_scope)
    rse, _ = rse_factory.make_posix_rse()
    base_name = generate_uuid()
    item000 = file_factory.upload_test_file(rse, name=base_name + '.000', return_full_item=True)
    item001 = file_factory.upload_test_file(rse, name=base_name + '.001', return_full_item=True)
    item100 = file_factory.upload_test_file(rse, name=base_name + '.100', return_full_item=True)
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


def test_download_multiple(rse_factory, file_factory, download_client):
    scope = str(file_factory.default_scope)
    rse, _ = rse_factory.make_posix_rse()
    base_name = generate_uuid()
    item000 = file_factory.upload_test_file(rse, name=base_name + '.000', return_full_item=True)
    item001 = file_factory.upload_test_file(rse, name=base_name + '.001', return_full_item=True)
    item100 = file_factory.upload_test_file(rse, name=base_name + '.100', return_full_item=True)
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


@pytest.mark.xfail(reason='XRD1 must be initialized https://github.com/rucio/rucio/pull/4165/')
@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined XRD1 RSE, may fails when run in parallel')  # TODO: verify if it really fails
def test_download_from_archive_on_xrd(file_factory, download_client, did_client):
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
        file_factory.upload_test_file(rse, scope=scope, name=zip_name, path=zip_path)
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


@pytest.mark.dirty
def test_trace_copy_out_and_checksum_validation(vo, rse_factory, file_factory, download_client):
    rse, _ = rse_factory.make_posix_rse()
    scope = str(file_factory.default_scope)
    did = file_factory.upload_test_file(rse)
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


def test_norandom_respected(rse_factory, file_factory, download_client, root_account):
    rse, _ = rse_factory.make_posix_rse()
    did1 = file_factory.upload_test_file(rse)
    did2 = file_factory.upload_test_file(rse)
    dataset = file_factory.make_dataset()
    did_core.attach_dids(dids=[did1, did2], account=root_account, **dataset)

    dataset_did_str = '%s:%s' % (dataset['scope'], dataset['name'])

    with TemporaryDirectory() as tmp_dir:
        nrandom = 1
        result = download_client.download_dids([{'did': dataset_did_str, 'nrandom': nrandom, 'base_dir': tmp_dir}])
        assert len(result) == nrandom

        nrandom = 2
        result = download_client.download_dids([{'did': dataset_did_str, 'nrandom': nrandom, 'base_dir': tmp_dir}])
        assert len(result) == nrandom


def test_transfer_timeout(rse_factory, file_factory, download_client):
    rse, _ = rse_factory.make_posix_rse()
    did = file_factory.upload_test_file(rse)
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
