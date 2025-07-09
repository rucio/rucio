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

import re
from os import path

import pytest

from rucio.common.utils import execute
from rucio.common.utils import generate_uuid as uuid
from rucio.tests.common import skip_rse_tests_with_accounts


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
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} {3}'.format(rse, scope, impl, tmp_file1)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(scope, tmp_file1.name)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(scope, tmp_file1.name)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List file replicas failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # Downloading the file
        cmd = 'rucio download --legacy --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_file1.name, impl)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # The file should be there
        cmd = 'find /tmp/{0}/{1}'.format(scope, tmp_file1.name)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"File not found after download: {self.marker} {cmd}. Error: {err}. Output: {out}"

    def test_upload_download_datasets_using_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): rucio upload files to dataset/download dataset"""
        tmp_file1 = file_factory.file_generator()
        tmp_file2 = file_factory.file_generator()
        tmp_file3 = file_factory.file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        did_factory.register_dids([{'scope': scope, 'name': n} for n in (tmp_file1.name, tmp_file2.name, tmp_file3.name, tmp_dsn)])
        impl = 'xrootd'

        # Adding files to a new dataset
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} {3} {4} {5} {1}:{6}'.format(rse, scope, impl, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(scope, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(scope, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List file replicas failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # Downloading dataset
        cmd = 'rucio download --legacy --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_dsn, impl)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # The files should be there
        cmd = 'ls /tmp/{0}/*'.format(tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Files not found after download: {self.marker} {cmd}. Error: {err}. Output: {out}"
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
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} {3}'.format(rse, scope, impl, tmp_file1)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # get the rule for the file
        cmd = f"rucio rule list --json {scope}:{tmp_file1.name}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0 and out.strip(), f"Get rule failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        import json
        rules = json.loads(out)
        assert rules, f"No rule found for {scope}:{tmp_file1.name}"
        rule_id = rules[0]["id"]
        # delete the file from the catalog
        cmd = f"rucio rule remove {rule_id}"
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Delete rule failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # delete the physical file
        cmd = 'rucio replica list file --pfns {0}:{1}'.format(scope, tmp_file1.name)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List replicas failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        url = out
        cmd = 'gfal-rm {0}'.format(url)
        exitcode, out, err = execute(cmd)
        assert re.search(r'DELETED', out) is not None, f"File deletion failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # upload the files to the dataset
        cmd = 'rucio -v upload --legacy --rse {0} --scope {1} --impl {2} {3} {4} {5}'.format(rse, scope, impl, tmp_file1, tmp_file2, tmp_file3)
        exitcode, out, err = execute(cmd)
        upload_string_1 = ('Successfully uploaded file %s' % tmp_file1.name)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(upload_string_1, err) is not None

    def test_repeat_upload_download_file_using_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): rucio upload/download file already existing on RSE"""
        tmp_file1 = file_factory.file_generator()
        tmp_file1_name = tmp_file1.name
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        impl = 'xrootd'

        # Upload the file
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} {3}'.format(rse, scope, impl, tmp_file1)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # List the file
        cmd = 'rucio list-files {0}:{1}'.format(scope, tmp_file1_name)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(scope, tmp_file1_name)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List file replicas failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # Re-Upload the file
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} {3}'.format(rse, scope, impl, tmp_file1)
        exitcode, out, err = execute(cmd)
        assert re.search(r'File already exists on RSE. Skipping upload', err) is not None, f"Re-upload should have been skipped: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # Downloading the file
        cmd = 'rucio download --legacy --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_file1_name, impl)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # The file should be there
        cmd = 'find /tmp/{0}/{1}'.format(scope, tmp_file1_name)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"File not found after download: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # Re-download file
        cmd = 'rucio download --legacy --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_file1_name, impl)
        exitcode, out, err = execute(cmd)
        assert re.search(r'Downloaded files:\s+0', out) is not None, f"Re-download should have been skipped: {self.marker} {cmd}. Error: {err}. Output: {out}"
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
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(rse, scope, impl, tmp_file1, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # upload the files to the dataset
        cmd = 'rucio -v upload --legacy --rse {0} --scope {1} --impl {2} {3} {4} {5} {1}:{6}'.format(rse, scope, impl, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode != 0, f"Upload should have failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(scope, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search("{0}:{1}".format(scope, tmp_file1_name), out) is not None
        assert re.search("{0}:{1}".format(scope, tmp_file3_name), out) is not None

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(scope, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List file replicas failed: {self.marker} {cmd}. Error: {err}. Output: {out}"

        # Downloading dataset
        cmd = 'rucio download --legacy --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_dsn, impl)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # The files should be there
        cmd = 'ls /tmp/{0}/*'.format(tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Files not found after download: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert tmp_file1.name in out
        assert tmp_file2.name in out
        assert tmp_file3.name in out

        # Re-download dataset
        cmd = 'rucio download --legacy --dir /tmp/ {0}:{1} --impl {2}'.format(scope, tmp_dsn, impl)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Re-download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(r'Downloaded files:\s+0', out) is not None
        assert re.search(r'Files already found locally:\s+3', out) is not None

    def test_upload_file_guid_with_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): Rucio upload file with guid"""
        tmp_file1 = file_factory.file_generator()
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        tmp_guid = uuid()
        impl = 'xrootd'
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(rse, scope, impl, tmp_guid, tmp_file1)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        upload_string_1 = ('Successfully uploaded file %s' % path.basename(tmp_file1))
        assert re.search(upload_string_1, err) is not None

    def test_download_filter_using_impl(self, file_factory, did_factory, scope, rse):
        """CLIENT(USER): rucio download with filter options"""

        impl = 'xrootd'
        # Use filter option to download file with wildcarded name
        tmp_file1 = file_factory.file_generator()
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        tmp_guid = uuid()
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(rse, scope, impl, tmp_guid, tmp_file1)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        wrong_guid = uuid()
        cmd = 'rucio -v download --legacy --dir /tmp {0}:{1} --impl {2} --filter guid={3}'.format(scope, '*', impl, wrong_guid)
        exitcode, out, err = execute(cmd)
        assert exitcode != 0, f"Download succeeded with wrong guid: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'ls /tmp/{0}'.format(scope)
        exitcode, out, err = execute(cmd)
        assert exitcode != 0, f"List files should fail: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(tmp_file1.name, out) is None
        cmd = 'rucio -v download --legacy --dir /tmp {0}:{1} --impl {2} --filter guid={3}'.format(scope, '*', impl, tmp_guid)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'ls /tmp/{0}'.format(scope)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(tmp_file1.name, out) is not None

        # Only use filter option to download file
        tmp_file1 = file_factory.file_generator()
        did_factory.register_dids([{'scope': scope, 'name': tmp_file1.name}])
        tmp_guid = uuid()
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(rse, scope, impl, tmp_guid, tmp_file1)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        wrong_guid = uuid()
        cmd = 'rucio -v download --legacy --dir /tmp --scope {0} --impl {1} --filter guid={2}'.format(scope, impl, wrong_guid)
        exitcode, out, err = execute(cmd)
        assert exitcode != 0, f"Download succeeded with wrong guid: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'ls /tmp/{0}'.format(scope)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(tmp_file1.name, out) is None
        cmd = 'rucio -v download --legacy --dir /tmp --scope {0} --impl {1} --filter guid={2}'.format(scope, impl, tmp_guid)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'ls /tmp/{0}'.format(scope)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(tmp_file1.name, out) is not None

        # Use filter option to download dataset with wildcarded name
        tmp_file1 = file_factory.file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        did_factory.register_dids([{'scope': scope, 'name': n} for n in (tmp_file1.name, tmp_dsn)])
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(rse, scope, impl, tmp_file1, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'rucio download --legacy --dir /tmp --scope {0} --filter created_before=1900-01-01T00:00:00.000Z'.format(scope)
        exitcode, out, err = execute(cmd)
        assert exitcode != 0, f"Download should fail: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode != 0, f"List files should fail: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(tmp_file1.name, out) is None
        cmd = 'rucio download --legacy --dir /tmp --scope {0} --filter created_after=1900-01-01T00:00:00.000Z'.format(scope)
        exitcode, out, err = execute(cmd)
        assert exitcode != 0, f"Download should fail: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        # assert re.search(tmp_file1[5:], out) is not None

        # Use filter option to download dataset with wildcarded name
        tmp_file1 = file_factory.file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        did_factory.register_dids([{'scope': scope, 'name': n} for n in (tmp_file1.name, tmp_dsn)])
        cmd = 'rucio upload --legacy --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(rse, scope, impl, tmp_file1, tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Upload failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'rucio download --legacy --dir /tmp {0}:{1} --filter created_before=1900-01-01T00:00:00.000Z'.format(scope, tmp_dsn[0:-1] + '*')
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(tmp_file1.name, out) is None
        cmd = 'rucio download --legacy --dir /tmp {0}:{1} --filter created_after=1900-01-01T00:00:00.000Z'.format(scope, tmp_dsn[0:-1] + '*')
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"Download failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        exitcode, out, err = execute(cmd)
        assert exitcode == 0, f"List files failed: {self.marker} {cmd}. Error: {err}. Output: {out}"
        assert re.search(tmp_file1.name, out) is not None
