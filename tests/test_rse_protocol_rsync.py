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
class TestRseRSYNC(MgrTestCases):
    original_prefchecksum = PREFERRED_CHECKSUM

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, containerized_rses, vo, tmp_path_factory):
        """rsync (RSE/PROTOCOLS): Creating necessary directories and files """

        rses = [rse for rse in containerized_rses if rse[0] == 'SSH1']

        data = load_test_conf_file('rse_repository.json')
        prefix = data['SSH-DISK']['protocols']['supported']['rsync']['prefix']
        port = data['SSH-DISK']['protocols']['supported']['rsync']['port']
        sshuser = data['SSH-DISK']['protocols']['supported']['rsync']['extended_attributes']['user']

        if len(rses) == 0:
            rse_name = 'SSH-RSE'
            hostname = data['SSH-RSE']['protocols']['supported']['rsync']['hostname']
        else:
            rse_name = 'SSH1'
            hostname = 'ssh1'
            prefix = '/rucio/'
            port = 22
            sshuser = 'root'

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

        protocol = rsemanager.create_protocol(rse_settings, 'write')
        protocol.connect()

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)

        for f in MgrTestCases.files_remote:
            path = str(prefix + protocol._get_path('user.%s' % user, f))
            pathdir = os.path.dirname(path)
            cmd = 'rsync -az -e "ssh -p %s" --rsync-path="mkdir -p %s && rsync" --append-verify %s/data.raw %s@%s:%s' % (port, str(pathdir), prefix, sshuser, hostname, path)
            execute(cmd)

        for f in MgrTestCases.files_local_and_remote:
            path = str(prefix + protocol._get_path('user.%s' % user, f))
            pathdir = os.path.dirname(path)
            cmd = 'rsync -az -e "ssh -p {0}" --rsync-path="mkdir -p {1} && rsync" --append-verify {2}/{3} {4}@{5}:{6}'.format(port, str(pathdir), str(tmpdir), str(f), sshuser, hostname, path)
            execute(cmd)

        yield rse_settings, tmpdir, user

        clean_raw = '%s/data.raw' % prefix
        list_files_cmd_user = 'ssh %s@%s find %s/user/%s' % (sshuser, hostname, prefix, user)
        clean_files = str(execute(list_files_cmd_user)[1]).split('\n')
        list_files_cmd_group = 'ssh %s@%s find %s/group/%s' % (sshuser, hostname, prefix, user)
        clean_files += str(execute(list_files_cmd_group)[1]).split('\n')
        clean_files.append(clean_raw)
        for files in clean_files:
            clean_cmd = 'ssh %s@%s rm %s' % (sshuser, hostname, files)

        list_directory = 'ssh %s@%s find %s/user/%s' % (sshuser, hostname, prefix, user)
        clean_directory = str(execute(list_directory)[1]).split('\n')
        list_directory_group = 'ssh %s@%s find %s/group/%s' % (sshuser, hostname, prefix, user)
        clean_directory += str(execute(list_directory_group)[1]).split('\n')
        for directory in clean_directory:
            clean_cmd = 'ssh %s@%s rm -r %s' % (sshuser, hostname, directory)
            execute(clean_cmd)

        set_preferred_checksum(cls.original_prefchecksum)
        cmd = 'ssh-keygen -R %s' % (hostname)
        execute(cmd)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo, impl='ssh.Rsync')

    def test_delete_mgr_ok_dir(self):
        raise pytest.skip("Not implemented")
