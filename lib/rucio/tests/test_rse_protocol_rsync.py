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
import shutil
import tempfile
import unittest
from uuid import uuid4 as uuid

import pytest

from rucio.common import exception
from rucio.common.utils import execute, PREFERRED_CHECKSUM, set_preferred_checksum
from rucio.rse import rsemanager
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from rucio.tests.rsemgr_api_test import MgrTestCases


@pytest.fixture(autouse=True, scope='class')
def load_rse_info(request, containerized_rses):
    """
    Detects if containerized rses for ssh are available in the testing environment.
    :return: A tuple (rse, prefix, hostname, port, user).
    """
    rses = [rse for rse in containerized_rses if rse[0] == 'SSH1']

    data = load_test_conf_file('rse_repository.json')
    request.cls.prefix = data['SSH-DISK']['protocols']['supported']['rsync']['prefix']
    request.cls.port = data['SSH-DISK']['protocols']['supported']['rsync']['port']
    request.cls.sshuser = data['SSH-DISK']['protocols']['supported']['rsync']['extended_attributes']['user']

    if len(rses) == 0:
        request.cls.rse_id = 'SSH-RSE'
        request.cls.hostname = data['SSH-RSE']['protocols']['supported']['rsync']['hostname']
    else:
        request.cls.rse_id = 'SSH1'
        request.cls.hostname = 'ssh1'
        request.cls.prefix = '/rucio/'
        request.cls.port = 22
        request.cls.sshuser = 'root'


@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
@skip_rse_tests_with_accounts
class TestRseRSYNC(unittest.TestCase):
    tmpdir = None
    user = None
    rse_id = None
    prefix = None
    hostname = None
    port = None
    sshuser = None
    impl = 'ssh.Rsync'
    original_prefchecksum = PREFERRED_CHECKSUM

    @classmethod
    def get_rse_info(cls):
        return cls.rse_id, cls.prefix, cls.hostname, cls.port, cls.sshuser

    @classmethod
    def setUpClass(cls):
        """rsync (RSE/PROTOCOLS): Creating necessary directories and files """

        # Getting info for the test environment
        rse_id, prefix, hostname, port, sshuser = cls.get_rse_info()

        try:
            os.mkdir(prefix)
        except Exception as e:
            print(e)

        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()
        cls.user = uuid()

        set_preferred_checksum('md5')
        cmd = 'ssh-keygen -R %s' % (hostname)
        execute(cmd)
        cmd = 'ssh-keyscan %s  >> /root/.ssh/known_hosts' % (hostname)
        execute(cmd)

        with open("%s/data.raw" % cls.tmpdir, "wb") as out:
            out.seek((1024 * 1024) - 1)  # 1 MB
            out.write(b'\0')
        for f in MgrTestCases.files_local:
            shutil.copy('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))

        protocol = rsemanager.create_protocol(rsemanager.get_rse_info(rse_id), 'write')
        protocol.connect()

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)
        cls.static_file = '%s@%s:/%s/data.raw' % (sshuser, hostname, prefix)
        pathdir = os.path.dirname(prefix)
        cmd = 'rsync -az -e "ssh -p %s" --rsync-path="mkdir -p %s && rsync" --append-verify %s/data.raw %s' % (port, str(pathdir), prefix, cls.static_file)
        execute(cmd)

        for f in MgrTestCases.files_remote:
            path = str(prefix + protocol._get_path('user.%s' % cls.user, f))
            pathdir = os.path.dirname(path)
            cmd = 'rsync -az -e "ssh -p %s" --rsync-path="mkdir -p %s && rsync" --append-verify %s/data.raw %s@%s:%s' % (port, str(pathdir), prefix, sshuser, hostname, path)
            execute(cmd)

        for f in MgrTestCases.files_local_and_remote:
            shutil.copy('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))
            path = str(prefix + protocol._get_path('user.%s' % cls.user, f))
            pathdir = os.path.dirname(path)
            cmd = 'rsync -az -e "ssh -p {0}" --rsync-path="mkdir -p {1} && rsync" --append-verify {2}/{3} {4}@{5}:{6}'.format(port, str(pathdir), str(cls.tmpdir), str(f), sshuser, hostname, path)
            execute(cmd)

    @classmethod
    def tearDownClass(cls):
        """rsync (RSE/PROTOCOLS): Removing created directories and files"""
        rse_id, prefix, hostname, port, sshuser = cls.get_rse_info()
        shutil.rmtree(prefix)
        shutil.rmtree(cls.tmpdir)

        clean_raw = '%s/data.raw' % prefix
        list_files_cmd_user = 'ssh %s@%s find %s/user/%s' % (sshuser, hostname, prefix, cls.user)
        clean_files = str(execute(list_files_cmd_user)[1]).split('\n')
        list_files_cmd_group = 'ssh %s@%s find %s/group/%s' % (sshuser, hostname, prefix, cls.user)
        clean_files += str(execute(list_files_cmd_group)[1]).split('\n')
        clean_files.append(clean_raw)
        for files in clean_files:
            clean_cmd = 'ssh %s@%s rm %s' % (sshuser, hostname, files)

        list_directory = 'ssh %s@%s find %s/user/%s' % (sshuser, hostname, prefix, cls.user)
        clean_directory = str(execute(list_directory)[1]).split('\n')
        list_directory_group = 'ssh %s@%s find %s/group/%s' % (sshuser, hostname, prefix, cls.user)
        clean_directory += str(execute(list_directory_group)[1]).split('\n')
        for directory in clean_directory:
            clean_cmd = 'ssh %s@%s rm -r %s' % (sshuser, hostname, directory)
            execute(clean_cmd)

        set_preferred_checksum(cls.original_prefchecksum)
        cmd = 'ssh-keygen -R %s' % (hostname)
        execute(cmd)

    def setUp(self):
        """rsync (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseRSYNC.tmpdir
        self.rse_id, self.prefix, self.hostname, self.port, self.sshuser = TestRseRSYNC.get_rse_info()
        self.mtc = MgrTestCases(self.tmpdir, self.rse_id, TestRseRSYNC.user, TestRseRSYNC.static_file, impl=TestRseRSYNC.impl)

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """rsync (RSE/PROTOCOLS): Put multiple files to storage providing LFNs and PFNs (Success)"""
        self.mtc.test_put_mgr_ok_multi()

    def test_put_mgr_ok_single(self):
        """rsync (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    def test_put_mgr_SourceNotFound_multi(self):
        """rsync (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_put_mgr_SourceNotFound_multi()

    def test_put_mgr_SourceNotFound_single(self):
        """rsync (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_put_mgr_SourceNotFound_single()

    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """rsync (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_put_mgr_FileReplicaAlreadyExists_multi()

    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """rsync (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_put_mgr_FileReplicaAlreadyExists_single()

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """rsync (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        self.mtc.test_delete_mgr_ok_multi()

    def test_delete_mgr_ok_single(self):
        """rsync (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mtc.test_delete_mgr_ok_single()

    def test_delete_mgr_SourceNotFound_multi(self):
        """rsync (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_delete_mgr_SourceNotFound_multi()

    def test_delete_mgr_SourceNotFound_single(self):
        """rsync (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_delete_mgr_SourceNotFound_single()

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """rsync (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        self.mtc.test_exists_mgr_ok_multi()

    def test_exists_mgr_ok_single_lfn(self):
        """rsync (RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_lfn()

    def test_exists_mgr_ok_single_pfn(self):
        """rsync (RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_pfn()

    def test_exists_mgr_false_multi(self):
        """rsync (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        self.mtc.test_exists_mgr_false_multi()

    def test_exists_mgr_false_single(self):
        """rsync (RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_lfn()

    def test_exists_mgr_false_single_pfn(self):
        """rsync (RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_pfn()

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """rsync (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        self.mtc.test_rename_mgr_ok_multi()

    def test_rename_mgr_ok_single_lfn(self):
        """rsync (RSE/PROTOCOLS): Rename a single file on storage using LFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_lfn()

    def test_rename_mgr_ok_single_pfn(self):
        """rsync (RSE/PROTOCOLS): Rename a single file on storage using PFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_pfn()

    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """rsync (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_multi()

    def test_rename_mgr_FileReplicaAlreadyExists_single_lfn(self):
        """rsync (RSE/PROTOCOLS): Rename a single file on storage using LFN(FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_lfn()

    def test_rename_mgr_FileReplicaAlreadyExists_single_pfn(self):
        """rsync (RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_pfn()

    def test_rename_mgr_SourceNotFound_multi(self):
        """rsync (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_multi()

    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """rsync (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """rsync (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_pfn()

    def test_change_scope_mgr_ok_single_lfn(self):
        """rsync (RSE/PROTOCOLS): Change the scope of a single file on storage using LFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_lfn()

    def test_change_scope_mgr_ok_single_pfn(self):
        """rsync (RSE/PROTOCOLS): Change the scope of a single file on storage using PFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_pfn()
