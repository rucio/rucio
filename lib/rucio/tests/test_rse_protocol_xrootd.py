# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - WeiJen Chang <e4523744@gmail.com>, 2013
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Cheng-Hsi Chao <cheng-hsi.chao@cern.ch>, 2014
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Vincent Garonne <vgaronne@gmail.com>, 2018

from __future__ import print_function

import json
import os
import shutil
import tempfile

from uuid import uuid4 as uuid

from nose.tools import raises

from rucio.common import exception
from rucio.rse import rsemanager
from rsemgr_api_test import MgrTestCases
from rucio.common.utils import execute


class TestRseXROOTD():
    tmpdir = None
    user = None

    @classmethod
    def setupClass(cls):
        """XROOTD (RSE/PROTOCOLS): Creating necessary directories and files """
        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()
        cls.user = uuid()

        with open("%s/data.raw" % cls.tmpdir, "wb") as out:
            out.seek((1024 * 1024) - 1)  # 1 MB
            out.write('\0')
        for f in MgrTestCases.files_local:
            shutil.copy('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))

        protocol = rsemanager.create_protocol(rsemanager.get_rse_info('WJ-XROOTD'), 'write')
        protocol.connect()

        with open('etc/rse_repository.json') as f:
            data = json.load(f)
        prefix = data['WJ-XROOTD']['protocols']['supported']['xroot']['prefix']
        hostname = data['WJ-XROOTD']['protocols']['supported']['xroot']['hostname']
        port = data['WJ-XROOTD']['protocols']['supported']['xroot']['port']

        try:
            os.mkdir(prefix)
        except Exception as e:
            print(e)

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)
        cls.static_file = 'xroot://%s:%d/%s/data.raw' % (hostname, port, prefix)
        cmd = 'xrdcp %s/data.raw %s' % (prefix, cls.static_file)
        execute(cmd)

        for f in MgrTestCases.files_remote:
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % cls.user, f))
            cmd = 'xrdcp %s/data.raw %s' % (prefix, path)
            execute(cmd)

    @classmethod
    def teardownClass(cls):
        """XROOTD (RSE/PROTOCOLS): Removing created directorie s and files"""
        with open('etc/rse_repository.json') as f:
            data = json.load(f)
        prefix = data['WJ-XROOTD']['protocols']['supported']['xroot']['prefix']
        hostname = data['WJ-XROOTD']['protocols']['supported']['xroot']['hostname']

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

    def setup(self):
        """XROOTD (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseXROOTD.tmpdir
        self.rse_id = 'WJ-XROOTD'
        self.mtc = MgrTestCases(self.tmpdir, 'WJ-XROOTD', TestRseXROOTD.user, TestRseXROOTD.static_file)

    # Mgr-Tests: GET
    def test_multi_get_mgr_ok(self):
        """XROOTD (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (Success)"""
        self.mtc.test_multi_get_mgr_ok()

    def test_get_mgr_ok_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Get a single file from storage providing LFN (Success)"""
        self.mtc.test_get_mgr_ok_single_lfn()

    def test_get_mgr_ok_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Get a single file from storage providing PFN (Success)"""
        self.mtc.test_get_mgr_ok_single_pfn()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_multi(self):
        """XROOTD (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_single_lfn()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_single_pfn()

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """XROOTD (RSE/PROTOCOLS): Put multiple files to storage providing LFNs and PFNs (Success)"""
        self.mtc.test_put_mgr_ok_multi()

    def test_put_mgr_ok_single(self):
        """XROOTD (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    @raises(exception.SourceNotFound)
    def test_put_mgr_SourceNotFound_multi(self):
        """XROOTD (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        self.mtc.test_put_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_put_mgr_SourceNotFound_single(self):
        """XROOTD (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        self.mtc.test_put_mgr_SourceNotFound_single()

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """XROOTD (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        self.mtc.test_put_mgr_FileReplicaAlreadyExists_multi()

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """XROOTD (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        self.mtc.test_put_mgr_FileReplicaAlreadyExists_single()

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """XROOTD (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        self.mtc.test_delete_mgr_ok_multi()

    def test_delete_mgr_ok_single(self):
        """XROOTD (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mtc.test_delete_mgr_ok_single()

    @raises(exception.SourceNotFound)
    def test_delete_mgr_SourceNotFound_multi(self):
        """XROOTD (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        self.mtc.test_delete_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_delete_mgr_SourceNotFound_single(self):
        """XROOTD (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
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

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """XROOTD (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_multi()

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using LFN(FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_lfn()

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_pfn()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_multi(self):
        """XROOTD (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_single_pfn()

    def test_change_scope_mgr_ok_single_lfn(self):
        """XROOTD (RSE/PROTOCOLS): Change the scope of a single file on storage using LFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_lfn()

    def test_change_scope_mgr_ok_single_pfn(self):
        """XROOTD (RSE/PROTOCOLS): Change the scope of a single file on storage using PFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_pfn()
