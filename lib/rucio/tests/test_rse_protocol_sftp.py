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

import pysftp
import pytest

from rucio.common import exception
from rucio.rse import rsemanager as mgr
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from rucio.tests.rsemgr_api_test import MgrTestCases


@skip_rse_tests_with_accounts
class TestRseSFTP(unittest.TestCase):
    tmpdir = None
    user = None

    @classmethod
    def setUpClass(cls):
        """SFTP (RSE/PROTOCOLS): Creating necessary directories and files """
        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()
        cls.user = uuid()

        with open("%s/data.raw" % cls.tmpdir, "wb") as out:
            out.seek((1024 * 1024) - 1)  # 1 MB
            out.write(b'\0')
        for fil in MgrTestCases.files_local:
            os.symlink('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, fil))

        # Load local credentials from file
        data = load_test_conf_file('rse-accounts.cfg')
        credentials = data['LXPLUS']
        lxplus = pysftp.Connection(**credentials)
        prefix = load_test_conf_file('rse_repository.json')['LXPLUS']['protocols']['supported']['sftp']['prefix']
        lxplus.execute('mkdir %s' % prefix)
        lxplus.execute('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)
        cls.static_file = 'sftp://lxplus.cern.ch:22%sdata.raw' % prefix
        protocol = mgr.create_protocol(mgr.get_rse_info('LXPLUS'), 'write')
        for fil in MgrTestCases.files_remote:
            tmp = protocol.parse_pfns(protocol.lfns2pfns({'name': fil, 'scope': 'user.%s' % cls.user}).values()[0]).values()[0]
            for cmd in ['mkdir -p %s' % ''.join([tmp['prefix'], tmp['path']]), 'ln -s %sdata.raw %s' % (prefix, ''.join([tmp['prefix'], tmp['path'], tmp['name']]))]:
                lxplus.execute(cmd)
        lxplus.close()

    @classmethod
    def tearDownClass(cls):
        """SFTP (RSE/PROTOCOLS): Removing created directorie s and files """
        # Load local creditentials from file
        credentials = {}
        data = load_test_conf_file('rse-accounts.cfg')
        credentials = data['LXPLUS']
        lxplus = pysftp.Connection(**credentials)
        prefix = load_test_conf_file('rse_repository.json')['LXPLUS']['protocols']['supported']['sftp']['prefix']
        lxplus.execute('rm -rf %s' % prefix)
        lxplus.close()
        shutil.rmtree(cls.tmpdir)

    def setUp(self):
        """SFTP (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseSFTP.tmpdir
        self.static_file = TestRseSFTP.static_file
        self.mtc = MgrTestCases(self.tmpdir, 'LXPLUS', TestRseSFTP.user, self.static_file)

    # Mgr-Tests: GET
    def test_multi_get_mgr_ok(self):
        """SFTP (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (Success)"""
        self.mtc.test_multi_get_mgr_ok()

    def test_get_mgr_ok_single_lfn(self):
        """SFTP (RSE/PROTOCOLS): Get a single file from storage providing LFN (Success)"""
        self.mtc.test_get_mgr_ok_single_lfn()

    def test_get_mgr_ok_single_pfn(self):
        """SFTP (RSE/PROTOCOLS): Get a single file from storage providing PFN (Success)"""
        self.mtc.test_get_mgr_ok_single_pfn()

    def test_get_mgr_SourceNotFound_multi(self):
        """SFTP (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_multi()

    def test_get_mgr_SourceNotFound_single_lfn(self):
        """SFTP (RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_single_lfn()

    def test_get_mgr_SourceNotFound_single_pfn(self):
        """SFTP (RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_single_pfn()

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Put multiple files to storage (Success)"""
        self.mtc.test_put_mgr_ok_multi()

    def test_put_mgr_ok_single(self):
        """SFTP (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    def test_put_mgr_SourceNotFound_multi(self):
        """SFTP (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_put_mgr_SourceNotFound_multi()

    def test_put_mgr_SourceNotFound_single(self):
        """SFTP (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_put_mgr_SourceNotFound_single()

    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """SFTP (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_put_mgr_FileReplicaAlreadyExists_multi()

    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """SFTP (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_put_mgr_FileReplicaAlreadyExists_single()

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        self.mtc.test_delete_mgr_ok_multi()

    def test_delete_mgr_ok_single(self):
        """SFTP (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mtc.test_delete_mgr_ok_single()

    def test_delete_mgr_SourceNotFound_multi(self):
        """SFTP (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_delete_mgr_SourceNotFound_multi()

    def test_delete_mgr_SourceNotFound_single(self):
        """SFTP (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_delete_mgr_SourceNotFound_single()

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        self.mtc.test_exists_mgr_ok_multi()

    def test_exists_mgr_ok_single_lfn(self):
        """SFTP (RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_lfn()

    def test_exists_mgr_ok_single_pfn(self):
        """SFTP (RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_pfn()

    def test_exists_mgr_false_multi(self):
        """SFTP (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        self.mtc.test_exists_mgr_false_multi()

    def test_exists_mgr_false_single_lfn(self):
        """SFTP (RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_lfn()

    def test_exists_mgr_false_single_pfn(self):
        """SFTP (RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_pfn()

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        self.mtc.test_rename_mgr_ok_multi()

    def test_rename_mgr_ok_single_lfn(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage using LFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_lfn()

    def test_rename_mgr_ok_single_pfn(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage using PFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_pfn()

    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """SFTP (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_multi()

    def test_rename_mgr_FileReplicaAlreadyExists_single_lfn(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage using LFN (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_lfn()

    def test_rename_mgr_FileReplicaAlreadyExists_single_pfn(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_pfn()

    def test_rename_mgr_SourceNotFound_multi(self):
        """SFTP (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_multi()

    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_pfn()

    def test_change_scope_mgr_ok_single_lfn(self):
        """SFTP (RSE/PROTOCOLS): Change the scope of a single file on storage using LFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_lfn()

    def test_change_scope_mgr_ok_single_pfn(self):
        """SFTP (RSE/PROTOCOLS): Change the scope of a single file on storage using PFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_pfn()
