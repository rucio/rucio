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

from rucio.common.utils import execute
from rucio.rse import rsemanager
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from .rsemgr_api_test import MgrTestCases


@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
@skip_rse_tests_with_accounts
class TestRseGFAL2Impl(MgrTestCases):

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, vo, tmp_path_factory):
        """GFAL2 (RSE/PROTOCOLS): Creating necessary directories and files """

        cmd = "rucio list-rses --rses 'test_container_xrd=True'"
        exitcode, out, err = execute(cmd)
        rses = out.split()

        data = load_test_conf_file('rse_repository.json')
        prefix = data['WJ-XROOTD']['protocols']['supported']['xroot']['prefix']

        if len(rses) == 0:
            rse_name = 'WJ-XROOTD'
            hostname = data['WJ-XROOTD']['protocols']['supported']['xroot']['hostname']
        else:
            rse_name = 'XRD1'
            hostname = 'xrd1'
            prefix = '//rucio/'

        try:
            os.mkdir(prefix)
        except Exception as e:
            print(e)

        rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)
        rse_settings['protocols'][0]['impl'] = 'rucio.rse.protocols.gfal.Default'

        protocol = rsemanager.create_protocol(rse_settings, 'write')
        protocol.connect()

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)

        for f in cls.files_remote:
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % user, f))
            cmd = 'xrdcp %s/data.raw %s' % (prefix, path)
            execute(cmd)

        for f in MgrTestCases.files_local_and_remote:
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % user, f))
            cmd = 'xrdcp %s/%s %s' % (tmpdir, f, path)
            execute(cmd)

        yield rse_settings, tmpdir, user

        clean_raw = '%s/data.raw' % prefix
        list_files_cmd_user = 'xrdfs %s ls %s/user.%s' % (hostname, prefix, user)
        clean_files = str(execute(list_files_cmd_user)[1]).split('\n')
        list_files_cmd_group = 'xrdfs %s ls %s/group.%s' % (hostname, prefix, user)
        clean_files += str(execute(list_files_cmd_group)[1]).split('\n')
        clean_files.append(clean_raw)
        for files in clean_files:
            clean_cmd = 'xrdfs %s rm %s' % (hostname, files)
            execute(clean_cmd)

        clean_prefix = '%s' % prefix
        list_directory = 'xrdfs %s ls %s' % (hostname, prefix)
        clean_directory = str(execute(list_directory)[1]).split('\n')
        clean_directory.append(clean_prefix)
        for directory in clean_directory:
            clean_cmd = 'xrdfs %s rmdir %s' % (hostname, directory)
            execute(clean_cmd)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo)

    def test_delete_mgr_ok_dir(self):
        raise pytest.skip("Not implemented")
