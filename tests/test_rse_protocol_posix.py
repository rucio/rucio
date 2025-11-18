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

import os
import shutil
import tempfile

import pytest

from rucio.rse import rsemanager as mgr
from rucio.tests.common import load_test_conf_file, skip_rse_tests_with_accounts

from .rsemgr_api_test import MgrTestCases


def setup_posix_test_env(rse_name, rse_settings, user):
    """POSIX (RSE/PROTOCOLS): Creating necessary directories and files """

    data = load_test_conf_file('rse_repository.json')
    prefix = data[rse_name]['protocols']['supported']['file']['prefix']
    os.makedirs(prefix, exist_ok=True)
    # Use tempfile for file creation in the same directory
    fd, temp_data_file = tempfile.mkstemp(dir=prefix, suffix='.raw', prefix='data_')
    os.close(fd)
    os.system('dd if=/dev/urandom of=%s bs=1024 count=1024' % temp_data_file)
    data_file = os.path.join(prefix, 'data.raw')
    shutil.move(temp_data_file, data_file)
    for f in MgrTestCases.files_remote:
        protocol = mgr.create_protocol(rse_settings, 'write')
        pfn = next(iter(mgr.lfns2pfns(rse_settings, {'name': f, 'scope': 'user.%s' % user}).values()))
        path = protocol.pfn2path(pfn)
        dirs = os.path.dirname(path)
        os.makedirs(dirs, exist_ok=True)
        shutil.copy(data_file, path)


@skip_rse_tests_with_accounts
class TestRsePOSIX(MgrTestCases):
    """
    Test the posix protocol
    """
    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, tmp_path_factory, vo):
        """POSIX (RSE/PROTOCOLS): Removing created directorie s and files """
        rse_name = 'MOCK-POSIX'
        rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)
        setup_posix_test_env(rse_name, rse_settings, user)

        yield rse_settings, tmpdir, user

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo)


@skip_rse_tests_with_accounts
@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
class TestRsePOSIXSymlink(MgrTestCases):
    """
    Test the posix protocol using Symlink implementation
    """
    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, tmp_path_factory, vo):
        """POSIX-SYMLINK (RSE/PROTOCOLS): Creating necessary directories and files """
        rse_name = 'MOCK-POSIX-SYMLINK'
        rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)
        setup_posix_test_env(rse_name, rse_settings, user)

        yield rse_settings, tmpdir, user

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo)
