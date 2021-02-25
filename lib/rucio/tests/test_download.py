# Copyright 2019-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021
#
# PY3K COMPATIBLE
import logging
import shutil
import unittest
from tempfile import TemporaryDirectory
from zipfile import ZipFile

import pytest

from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.downloadclient import DownloadClient
from rucio.client.uploadclient import UploadClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import InputValidationError, NoFilesDownloaded
from rucio.common.utils import generate_uuid
from rucio.rse import rsemanager as rsemgr
from rucio.rse.protocols.posix import Default as PosixProtocol
from rucio.tests.common import file_generator


class TestDownloadClient(unittest.TestCase):
    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}

        logger = logging.getLogger('dlul_client')
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.DEBUG)
        self.client = Client()
        self.did_client = DIDClient()
        self.upload_client = UploadClient(_client=self.client, logger=logger)
        self.download_client = DownloadClient(client=self.client, logger=logger)

    def _upoad_test_file(self, rse, scope, name, path=None):
        item = {
            'path': path if path else file_generator(),
            'rse': rse,
            'did_scope': scope,
            'did_name': name,
            'guid': generate_uuid(),
        }
        assert self.upload_client.upload([item]) == 0
        return item

    @staticmethod
    def _check_download_result(actual_result, expected_result):
        assert len(expected_result) == len(actual_result)
        expected_result = sorted(expected_result, key=lambda x: x['did'])
        actual_result = sorted(actual_result, key=lambda x: x['did'])
        for i, expected in enumerate(expected_result):
            for param_name, expected_value in expected.items():
                assert param_name and actual_result[i][param_name] == expected[param_name]

    def test_download_without_base_dir(self):
        rse = 'MOCK4'
        scope = 'mock'
        item = self._upoad_test_file(rse, scope, 'testDownloadNoBasedir' + generate_uuid())
        did = '%s:%s' % (scope, item['did_name'])
        try:
            # download to the default location, i.e. to ./
            result = self.download_client.download_dids([{'did': did}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': did,
                        'clientState': 'DONE',
                    }
                ],
            )

            # re-downloading the same file again should not overwrite it
            result = self.download_client.download_dids([{'did': did}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': did,
                        'clientState': 'ALREADY_DONE',
                    }
                ],
            )
        finally:
            shutil.rmtree(scope)

    def test_download_multiple(self):
        rse = 'MOCK4'
        scope = 'mock'
        base_name = 'testDownloadItem' + generate_uuid()
        item000 = self._upoad_test_file(rse, scope, base_name + '.000')
        item001 = self._upoad_test_file(rse, scope, base_name + '.001')
        item100 = self._upoad_test_file(rse, scope, base_name + '.100')

        with TemporaryDirectory() as tmp_dir:
            # Download specific DID
            result = self.download_client.download_dids([{'did': '%s:%s' % (scope, item000['did_name']), 'base_dir': tmp_dir}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': '%s:%s' % (scope, item000['did_name']),
                        'clientState': 'DONE',
                    }
                ],
            )

            # Download multiple files with wildcard. One file already exists on the file system. Will not be re-downloaded.
            result = self.download_client.download_dids([{'did': '%s:%s.0*' % (scope, base_name), 'base_dir': tmp_dir}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': '%s:%s' % (scope, item000['did_name']),
                        'clientState': 'ALREADY_DONE',
                    },
                    {
                        'did': '%s:%s' % (scope, item001['did_name']),
                        'clientState': 'DONE',
                    },
                ],
            )

            # Download with filter
            result = self.download_client.download_dids([{'filters': {'guid': item000['guid'], 'scope': scope}, 'base_dir': tmp_dir}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': '%s:%s' % (scope, item000['did_name']),
                    }
                ],
            )

            # Download with wildcard and name
            result = self.download_client.download_dids([{'did': '%s:*' % scope, 'filters': {'guid': item100['guid']}, 'base_dir': tmp_dir}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': '%s:%s' % (scope, item100['did_name']),
                        'clientState': 'DONE',
                    }
                ],
            )

            # Don't create subdirectories by scope
            result = self.download_client.download_dids([{'did': '%s:%s.*' % (scope, base_name), 'base_dir': tmp_dir, 'no_subdir': True}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': '%s:%s' % (scope, item000['did_name']),
                        'clientState': 'DONE',
                        'dest_file_paths': ['%s/%s' % (tmp_dir, item000['did_name'])],
                    },
                    {
                        'did': '%s:%s' % (scope, item001['did_name']),
                        'clientState': 'DONE',
                        'dest_file_paths': ['%s/%s' % (tmp_dir, item001['did_name'])],
                    },
                    {
                        'did': '%s:%s' % (scope, item100['did_name']),
                        'clientState': 'DONE',
                        'dest_file_paths': ['%s/%s' % (tmp_dir, item100['did_name'])],
                    },
                ],
            )

            # Re-download file existing on the file system with no-subdir set. It must be overwritten.
            result = self.download_client.download_dids([{'did': '%s:%s' % (scope, item100['did_name']), 'base_dir': tmp_dir, 'no_subdir': True}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': '%s:%s' % (scope, item100['did_name']),
                        'clientState': 'ALREADY_DONE',
                        'dest_file_paths': ['%s/%s' % (tmp_dir, item100['did_name'])],
                    }
                ],
            )

    @pytest.mark.xfail(reason='XRD1 must be initialized https://github.com/rucio/rucio/pull/4165/')
    def test_download_from_archive_on_xrd(self):
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
            self._upoad_test_file(rse, scope, zip_name, path=zip_path)
            self.did_client.add_files_to_archive(
                scope,
                zip_name,
                [
                    {'scope': scope, 'name': name000, 'bytes': len(data000), 'type': 'FILE', 'adler32': adler000, 'meta': {'guid': str(generate_uuid())}},
                    {'scope': scope, 'name': name001, 'bytes': len(data001), 'type': 'FILE', 'adler32': adler001, 'meta': {'guid': str(generate_uuid())}},
                ],
            )

            # Download one file from the archive
            result = self.download_client.download_dids([{'did': '%s:%s' % (scope, name000), 'base_dir': tmp_dir}])
            self._check_download_result(
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
            result = self.download_client.download_dids([{'did': '%s:%s.00*' % (scope, base_name), 'base_dir': tmp_dir}])
            self._check_download_result(
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
            result = self.download_client.download_pfns([{'did': '%s:%s' % (scope, name001), 'pfn': pfn, 'rse': rse, 'base_dir': tmp_dir, 'no_subdir': True}])
            self._check_download_result(
                actual_result=result,
                expected_result=[
                    {
                        'did': '%s:%s' % (scope, name001),
                        'clientState': 'DONE',
                    },
                ],
            )

    def test_trace_copy_out_and_checksum_validation(self):
        rse = 'MOCK4'
        scope = 'mock'
        name = 'testDownloadTraces' + generate_uuid()
        self._upoad_test_file(rse, scope, name)

        with TemporaryDirectory() as tmp_dir:
            # Try downloading non-existing did
            traces = []
            with pytest.raises(NoFilesDownloaded):
                self.download_client.download_dids([{'did': 'some:randomNonExistingDid', 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'FILE_NOT_FOUND'

            # Download specific DID
            traces = []
            self.download_client.download_dids([{'did': '%s:%s' % (scope, name), 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'DONE'

            # Download same DID again
            traces = []
            result = self.download_client.download_dids([{'did': '%s:%s' % (scope, name), 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'ALREADY_DONE'

            # Change the local file and download the same file again. Checksum validation should fail and it must be re-downloaded
            with open(result[0]['dest_file_paths'][0], 'a') as f:
                f.write("more data")
            traces = []
            result = self.download_client.download_dids([{'did': '%s:%s' % (scope, name), 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'DONE'

            pfn = result[0]['sources'][0]['pfn']

        # Switch to a new empty directory
        with TemporaryDirectory() as tmp_dir:
            # Wildcards in did name are not allowed on pfn downloads
            traces = []
            with pytest.raises(InputValidationError):
                self.download_client.download_pfns([{'did': '%s:*' % scope, 'pfn': pfn, 'rse': rse, 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert not traces

            # Same pfn, but without wildcard in the did should work
            traces = []
            self.download_client.download_pfns([{'did': '%s:%s' % (scope, name), 'pfn': pfn, 'rse': rse, 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'DONE'

            # Same pfn. Local file already present. Shouldn't be overwritten.
            traces = []
            self.download_client.download_pfns([{'did': '%s:%s' % (scope, name), 'pfn': pfn, 'rse': rse, 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'ALREADY_DONE'

            # Provide wrong checksum for validation, the file will be re-downloaded but checksum validation fails
            traces = []
            with pytest.raises(NoFilesDownloaded):
                self.download_client.download_pfns([{'did': '%s:%s' % (scope, name), 'pfn': pfn, 'rse': rse, 'adler32': 'wrong', 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'FAIL_VALIDATE'

        # Switch to a new empty directory
        with TemporaryDirectory() as tmp_dir:
            # Simulate checksum corruption by changing the source file. We rely on the particularity
            # that the MOCK4 rse uses the posix protocol: files are stored on the local file system
            protocol = rsemgr.create_protocol(rsemgr.get_rse_info(rse, vo=self.client.vo), operation='read')
            assert isinstance(protocol, PosixProtocol)
            mock_rse_local_path = protocol.pfn2path(pfn)
            with open(mock_rse_local_path, 'w') as f:
                f.write('some completely other data')

            # Download fails checksum validation
            traces = []
            with pytest.raises(NoFilesDownloaded):
                self.download_client.download_dids([{'did': '%s:%s' % (scope, name), 'base_dir': tmp_dir}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'FAIL_VALIDATE'

            # Ignore_checksum set. Download works.
            traces = []
            self.download_client.download_dids([{'did': '%s:%s' % (scope, name), 'base_dir': tmp_dir, 'ignore_checksum': True}], traces_copy_out=traces)
            assert len(traces) == 1 and traces[0]['clientState'] == 'DONE'
