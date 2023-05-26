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

import os

import pytest

from rucio.common.utils import execute, PREFERRED_CHECKSUM, set_preferred_checksum
from rucio.rse import rsemanager
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from .rsemgr_api_test import MgrTestCases


@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
@skip_rse_tests_with_accounts
class TestRseRCLONE(MgrTestCases):
    original_prefchecksum = PREFERRED_CHECKSUM

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, containerized_rses, vo, tmp_path_factory):
        """rclone (RSE/PROTOCOLS): Creating necessary directories and files """

        # Getting info for the test environment
        rses = [rse for rse in containerized_rses if rse[0] == 'SSH1']

        data = load_test_conf_file('rse_repository.json')
        prefix = data['SSH-DISK']['protocols']['supported']['rclone']['prefix']

        if len(rses) == 0:
            rse_name = 'SSH-RSE'
            hostname = data['SSH-RSE']['protocols']['supported']['rclone']['hostname']
        else:
            rse_name = 'SSH1'
            hostname = 'ssh_rclone_rse'
            prefix = '/rucio/'

        try:
            os.mkdir(prefix)
        except Exception as e:
            print(e)

        rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)

        set_preferred_checksum('md5')
        cmd = 'ssh-keygen -R %s' % (hostname)
        execute(cmd)
        cmd = 'ssh-keyscan %s  >> /root/.ssh/known_hosts' % (hostname)
        execute(cmd)

        protocol = rsemanager.create_protocol(rse_settings, 'write', impl='rucio.rse.protocols.rclone.Default')
        protocol.connect()

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)

        for f in MgrTestCases.files_remote:
            path = str(prefix + protocol._get_path('user.%s' % user, f))
            cmd = 'rclone copyto %s/data.raw %s:%s' % (prefix, hostname, path)
            execute(cmd)

        for f in MgrTestCases.files_local_and_remote:
            path = str(prefix + protocol._get_path('user.%s' % user, f))
            cmd = 'rclone copyto {0}/{1} {2}:{3}'.format(str(tmpdir), str(f), hostname, path)
            execute(cmd)

        yield rse_settings, tmpdir, user

        clean_raw = 'rclone delete %s/data.raw' % prefix
        execute(clean_raw)
        list_files_cmd_user = 'rclone purge %s:%s/user/%s' % (hostname, prefix, user)
        execute(list_files_cmd_user)
        list_files_cmd_group = 'rclone purge %s:%s/group/%s' % (hostname, prefix, user)
        execute(list_files_cmd_group)

        set_preferred_checksum(cls.original_prefchecksum)
        cmd = 'ssh-keygen -R %s' % (hostname)
        execute(cmd)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo, impl='rclone')

    def test_delete_mgr_ok_dir(self):
        pass
