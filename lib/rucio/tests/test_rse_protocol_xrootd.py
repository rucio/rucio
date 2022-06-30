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
from rucio.common.utils import execute
from rucio.rse import rsemanager
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from rucio.tests.rsemgr_api_test import MgrTestCases


@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
@skip_rse_tests_with_accounts
class TestRseXROOTD(unittest.TestCase):
    tmpdir = None
    user = None

    @classmethod
    def get_rse_info(cls):
        """
        Detects if containerized rses for xrootd are available in the testing environment.
        :return: A tuple (rse, prefix, hostname, port).
        """
        cmd = "rucio list-rses --rses 'test_container_xrd=True'"
        print(cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        rses = out.split()

        data = load_test_conf_file('rse_repository.json')
        prefix = data['WJ-XROOTD']['protocols']['supported']['xroot']['prefix']
        port = data['WJ-XROOTD']['protocols']['supported']['xroot']['port']

        if len(rses) == 0:
            rse_id = 'WJ-XROOTD'
            hostname = data['WJ-XROOTD']['protocols']['supported']['xroot']['hostname']
        else:
            rse_id = 'XRD1'
            hostname = 'xrd1'
            prefix = '/rucio/'
        # TODO should read container info from a config file
        return rse_id, prefix, hostname, port

    @classmethod
    def setUpClass(cls):
        """XROOTD (RSE/PROTOCOLS): Creating necessary directories and files """

        # Getting info for the test environment
        rse_id, prefix, hostname, port = cls.get_rse_info()

        try:
            os.mkdir(prefix)
        except Exception as e:
            print(e)

        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()
        cls.user = uuid()

        with open("%s/data.raw" % cls.tmpdir, "wb") as out:
            out.seek((1024 * 1024) - 1)  # 1 MB
            out.write(b'\0')
        for f in MgrTestCases.files_local:
            shutil.copy('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))

        protocol = rsemanager.create_protocol(rsemanager.get_rse_info(rse_id), 'write')
        protocol.connect()

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)
        cls.static_file = 'xroot://%s:%d/%s/data.raw' % (hostname, port, prefix)
        cmd = 'xrdcp %s/data.raw %s' % (prefix, cls.static_file)
        execute(cmd)

        for f in MgrTestCases.files_remote:
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % cls.user, f))
            cmd = 'xrdcp %s/data.raw %s' % (prefix, path)
            execute(cmd)

        for f in MgrTestCases.files_local_and_remote:
            shutil.copy('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % cls.user, f))
            cmd = 'xrdcp %s/%s %s' % (cls.tmpdir, f, path)
            execute(cmd)

    @classmethod
    def tearDownClass(cls):
        """XROOTD (RSE/PROTOCOLS): Removing created directorie s and files"""
        rse_id, prefix, hostname, port = cls.get_rse_info()

        shutil.rmtree(prefix)
        shutil.rmtree(cls.tmpdir)

        clean_raw = '%s/data.raw' % prefix
        list_files_cmd_user = 'xrdfs %s ls %s/user.%s' % (hostname, prefix, cls.user)
        clean_files = str(execute(list_files_cmd_user)[1]).split('\n')
        list_files_cmd_group = 'xrdfs %s ls %s/group.%s' % (hostname, prefix, cls.user)
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

    def setUp(self):
        """XROOTD (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseXROOTD.tmpdir
        self.rse_id, self.prefix, self.hostname, self.port = TestRseXROOTD.get_rse_info()
        self.mtc = MgrTestCases(self.tmpdir, self.rse_id, TestRseXROOTD.user, TestRseXROOTD.static_file)

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """XROOTD (RSE/PROTOCOLS): Put multiple files to storage providing LFNs and PFNs (Success)"""
        self.mtc.test_put_mgr_ok_multi()

    def test_put_mgr_ok_single(self):
        """XROOTD (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    def test_put_mgr_SourceNotFound_multi(self):
        """XROOTD (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_put_mgr_SourceNotFound_multi()

    def test_put_mgr_SourceNotFound_single(self):
        """XROOTD (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_put_mgr_SourceNotFound_single()

    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """XROOTD (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_put_mgr_FileReplicaAlreadyExists_multi()

    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """XROOTD (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_put_mgr_FileReplicaAlreadyExists_single()

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """XROOTD (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        self.mtc.test_delete_mgr_ok_multi()

    def test_delete_mgr_ok_single(self):
        """XROOTD (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mtc.test_delete_mgr_ok_single()

    def test_delete_mgr_SourceNotFound_multi(self):
        """XROOTD (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_delete_mgr_SourceNotFound_multi()

    def test_delete_mgr_SourceNotFound_single(self):
        """XROOTD (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_delete_mgr_SourceNotFound_single()

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """XROOTD (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        self.mtc.test_exists_mgr_ok_multi()

    def test_exists_mgr_ok_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_lfn()

    def test_exists_mgr_ok_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_pfn()

    def test_exists_mgr_false_multi(self):
        """XROOTD (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        self.mtc.test_exists_mgr_false_multi()

    def test_exists_mgr_false_single(self):
        """XROOTD (RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_lfn()

    def test_exists_mgr_false_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_pfn()

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """XROOTD (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        self.mtc.test_rename_mgr_ok_multi()

    def test_rename_mgr_ok_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using LFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_lfn()

    def test_rename_mgr_ok_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using PFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_pfn()

    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """XROOTD (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_multi()

    def test_rename_mgr_FileReplicaAlreadyExists_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using LFN(FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_lfn()

    def test_rename_mgr_FileReplicaAlreadyExists_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_pfn()

    def test_rename_mgr_SourceNotFound_multi(self):
        """XROOTD (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_multi()

    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_pfn()

    def test_change_scope_mgr_ok_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Change the scope of a single file on storage using LFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_lfn()

    def test_change_scope_mgr_ok_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Change the scope of a single file on storage using PFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_pfn()
