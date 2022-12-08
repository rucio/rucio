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

from os import path
import re

import pytest

from rucio.common.utils import generate_uuid as uuid, execute
from rucio.tests.common import skip_rse_tests_with_accounts


@pytest.fixture(scope='class')
def scope_and_rse(mock_scope, test_scope):
    """
    Check if xrd containers rses for xrootd are available in the testing environment.
    :return: A tuple (scope, rses) for the rucio client where scope is mock/test and rses is a list.
    """
    cmd = "rucio list-rses --rses 'test_container_xrd=True'"
    print(cmd)
    exitcode, out, err = execute(cmd)
    print(out, err)
    rses = out.split()
    if len(rses) == 0:
        return mock_scope, 'MOCK-POSIX'
    return test_scope, rses[0]


@pytest.fixture(scope='class')
def scope(scope_and_rse):
    scope, rse = scope_and_rse
    return scope


@pytest.fixture(scope='class')
def rse(scope_and_rse):
    scope, rse = scope_and_rse
    return rse


@skip_rse_tests_with_accounts
class TestImplUploadDownload:

    marker = '$ > '

    def test_upload_download_file_using_impl(self, did_factory, file_factory, scope, rse):
        """CLIENT(USER): rucio upload/download file"""
        tmp_file1 = file_factory.file_generator()
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        impl = 'xrootd'

        # Uploading file
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(rse, scope, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(scope, tmp_file1.name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(scope, tmp_file1.name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # Downloading the file
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_file1.name, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The file should be there
        cmd = 'find /tmp/{0}/{1}'.format(scope, tmp_file1.name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        assert exitcode == 0

    def test_upload_download_datasets_using_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): rucio upload files to dataset/download dataset"""
        tmp_file1 = file_factory.file_generator()
        tmp_file2 = file_factory.file_generator()
        tmp_file3 = file_factory.file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        did_factory.register_dids([{'scope': scope, 'name': n} for n in (tmp_file1.name, tmp_file2.name, tmp_file3.name, tmp_dsn)])
        impl = 'xrootd'

        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3} {4} {5} {1}:{6}'.format(rse, scope, impl, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # Downloading dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_dsn, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The files should be there
        cmd = 'ls /tmp/{0}/*'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        assert exitcode == 0
        assert tmp_file1.name in out
        assert tmp_file2.name in out
        assert tmp_file3.name in out

    def test_repeat_upload_file_using_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): rucio re-upload file after deleting physical file"""
        tmp_file1 = file_factory.file_generator()
        tmp_file2 = file_factory.file_generator()
        tmp_file3 = file_factory.file_generator()
        did_factory.register_dids([{'scope': scope, 'name': n} for n in (tmp_file1.name, tmp_file2.name, tmp_file3.name)])
        impl = 'xrootd'

        # Upload the file
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(rse, scope, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # get the rule for the file
        cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(scope, tmp_file1.name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        rule = out
        # delete the file from the catalog
        cmd = "rucio delete-rule {0}".format(rule)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # delete the physical file
        cmd = 'rucio list-file-replicas --pfn {0}:{1}'.format(scope, tmp_file1.name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        url = out
        cmd = 'gfal-rm {0}'.format(url)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(r'DELETED', out) is not None
        # upload the files to the dataset
        cmd = 'rucio -v upload --rse {0} --scope {1} --impl {2} {3} {4} {5}'.format(rse, scope, impl, tmp_file1, tmp_file2, tmp_file3)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        upload_string_1 = ('Successfully uploaded file %s' % tmp_file1.name)
        assert re.search(upload_string_1, err) is not None

    def test_repeat_upload_download_file_using_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): rucio upload/download file already existing on RSE"""
        tmp_file1 = file_factory.file_generator()
        tmp_file1_name = tmp_file1.name
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        impl = 'xrootd'

        # Upload the file
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(rse, scope, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # List the file
        cmd = 'rucio list-files {0}:{1}'.format(scope, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(scope, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # Re-Upload the file
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(rse, scope, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert re.search(r'File already exists on RSE. Skipping upload', err) is not None

        # Downloading the file
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_file1_name, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The file should be there
        cmd = 'find /tmp/{0}/{1}'.format(scope, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        assert exitcode == 0

        # Re-download file
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_file1_name, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert re.search(r'Downloaded files:\s+0', out) is not None
        assert re.search(r'Files already found locally:\s+1', out) is not None

    def test_repeat_upload_download_dataset_using_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): rucio upload files to dataset/download dataset"""
        tmp_file1 = file_factory.file_generator()
        tmp_file2 = file_factory.file_generator()
        tmp_file3 = file_factory.file_generator()
        tmp_file1_name = tmp_file1.name
        tmp_file3_name = tmp_file3.name
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        did_factory.register_dids([{'scope': scope, 'name': n} for n in (tmp_file1.name, tmp_file2.name, tmp_file3.name, tmp_dsn)])
        impl = 'xrootd'

        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(rse, scope, impl, tmp_file1, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # upload the files to the dataset
        cmd = 'rucio -v upload --rse {0} --scope {1} --impl {2} {3} {4} {5} {1}:{6}'.format(rse, scope, impl, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        assert re.search("{0}:{1}".format(scope, tmp_file1_name), out) is not None
        assert re.search("{0}:{1}".format(scope, tmp_file3_name), out) is not None

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0

        # Downloading dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_dsn, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The files should be there
        cmd = 'ls /tmp/{0}/*'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        assert exitcode == 0
        assert tmp_file1.name in out
        assert tmp_file2.name in out
        assert tmp_file3.name in out

        # Re-download dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_dsn, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        assert re.search(r'Downloaded files:\s+0', out) is not None
        assert re.search(r'Files already found locally:\s+3', out) is not None

    def test_upload_file_guid_with_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): Rucio upload file with guid"""
        tmp_file1 = file_factory.file_generator()
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        tmp_guid = uuid()
        impl = 'xrootd'
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(rse, scope, impl, tmp_guid, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        upload_string_1 = ('Successfully uploaded file %s' % path.basename(tmp_file1))
        assert re.search(upload_string_1, err) is not None

    def test_download_filter_using_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): rucio download with filter options"""

        impl = 'xrootd'
        # Use filter option to download file with wildcarded name
        tmp_file1 = file_factory.file_generator()
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        tmp_guid = uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(rse, scope, impl, tmp_guid, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        wrong_guid = uuid()
        cmd = 'rucio -v download --dir /tmp {0}:{1} --impl {2} --filter guid={3}'.format(scope, '*', impl, wrong_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1.name, out) is None
        cmd = 'rucio -v download --dir /tmp {0}:{1} --impl {2} --filter guid={3}'.format(scope, '*', impl, tmp_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        cmd = 'ls /tmp/{0}'.format(scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1.name, out) is not None

        # Only use filter option to download file
        tmp_file1 = file_factory.file_generator()
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        tmp_guid = uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(rse, scope, impl, tmp_guid, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        wrong_guid = uuid()
        cmd = 'rucio -v download --dir /tmp --scope {0} --impl {1} --filter guid={2}'.format(scope, impl, wrong_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1.name, out) is None
        cmd = 'rucio -v download --dir /tmp --scope {0} --impl {1} --filter guid={2}'.format(scope, impl, tmp_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert exitcode == 0
        cmd = 'ls /tmp/{0}'.format(scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1.name, out) is not None

        # Use filter option to download dataset with wildcarded name
        tmp_file1 = file_factory.file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        did_factory.register_dids([{'scope': scope, 'name': n} for n in (tmp_file1.name, tmp_dsn)])
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(rse, scope, impl, tmp_file1, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        cmd = 'rucio download --dir /tmp --scope {0} --filter created_before=1900-01-01T00:00:00.000Z'.format(scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1.name, out) is None
        cmd = 'rucio download --dir /tmp --scope {0} --filter created_after=1900-01-01T00:00:00.000Z'.format(scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # assert re.search(tmp_file1[5:], out) is not None

        # Use filter option to download dataset with wildcarded name
        tmp_file1 = file_factory.file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        did_factory.register_dids([{'scope': scope, 'name': n} for n in (tmp_file1.name, tmp_dsn)])
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(rse, scope, impl, tmp_file1, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        assert exitcode == 0
        cmd = 'rucio download --dir /tmp {0}:{1} --filter created_before=1900-01-01T00:00:00.000Z'.format(scope, tmp_dsn[0:-1] + '*')
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1.name, out) is None
        cmd = 'rucio download --dir /tmp {0}:{1} --filter created_after=1900-01-01T00:00:00.000Z'.format(scope, tmp_dsn[0:-1] + '*')
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        assert re.search(tmp_file1.name, out) is not None
