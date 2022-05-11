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

import unittest

import pytest

from rucio.common import exception
from rucio.rse import rsemanager as mgr
from rucio.tests.common import skip_rse_tests_with_accounts
from rucio.tests.rsemgr_api_test import MgrTestCases


@skip_rse_tests_with_accounts
class TestRseMOCK(unittest.TestCase):
    tmpdir = '/tmp/'
    user = None
    static_file = 'mock:///tmp/rucio_rse/file1'

    def setUp(self):
        """MOCK (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseMOCK.tmpdir
        self.rse_id = 'MOCK'
        self.mtc = MgrTestCases(tmpdir=self.tmpdir, rse_tag='MOCK', user=TestRseMOCK.user, static_file=TestRseMOCK.static_file)

    # Mgr-Tests: GET
    def test_get_mgr_SourceNotFound_multi(self):
        """MOCK (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (SourceNotFound)"""
        for fichier in MgrTestCases.files_remote:
            mgr.upload(mgr.get_rse_info(self.rse_id), [{'name': fichier, 'scope': 'user.%s' % self.user}, ])
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_multi()

    def test_get_mgr_SourceNotFound_single_lfn(self):
        """MOCK (RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNotFound)"""
        for fichier in MgrTestCases.files_remote:
            mgr.upload(mgr.get_rse_info(self.rse_id), [{'name': fichier, 'scope': 'user.%s' % self.user}, ])
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_single_lfn()

    def test_get_mgr_SourceNotFound_single_pfn(self):
        """MOCK (RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotFound)"""
        for fichier in MgrTestCases.files_remote:
            mgr.upload(mgr.get_rse_info(self.rse_id), [{'name': fichier, 'scope': 'user.%s' % self.user}, ])
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_single_pfn()

    # Mgr-Tests: PUT
    def test_put_mgr_ok_single(self):
        """MOCK (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """MOCK (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        for fichier in MgrTestCases.files_remote:
            mgr.upload(mgr.get_rse_info(self.rse_id), [{'name': fichier, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_delete_mgr_ok_multi()

    def test_delete_mgr_ok_single(self):
        """MOCK (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        for fichier in MgrTestCases.files_remote:
            mgr.upload(mgr.get_rse_info(self.rse_id), [{'name': fichier, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_delete_mgr_ok_single()

    # MGR-Tests: EXISTS
    # ATTENTION: this tests won't work no more with the new RSEMgr as the protocol object is no longer cached and therefore the list of files is also not 'persisted'
    # def test_exists_mgr_ok_multi(self):
    #    """MOCK (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
    #    for f in MgrTestCases.files_remote:
    #        mgr.upload(mgr.get_rse_info(self.rse_id), [{'name': f, 'scope': 'user.%s' % self.user}, ])
    #    self.mtc.test_exists_mgr_ok_multi()

    def test_exists_mgr_ok_single_lfn(self):
        """MOCK (RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_lfn()

    def test_exists_mgr_ok_single_pfn(self):
        """MOCK (RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_pfn()

    # ATTENTION: this tests won't work no more with the new RSEMgr as the protocol object is no longer cached and therefore the list of files is also not 'persisted'
    # def test_exists_mgr_false_multi(self):
    #    """MOCK (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
    #    for f in MgrTestCases.files_remote:
    #        mgr.upload(mgr.get_rse_info(self.rse_id), [{'name': f, 'scope': 'user.%s' % self.user}, ])
    #    self.mtc.test_exists_mgr_false_multi()

    def test_exists_mgr_false_single(self):
        """MOCK (RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_lfn()

    def test_exists_mgr_false_single_pfn(self):
        """MOCK (RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_pfn()

    # MGR-Tests: RENAME

    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """MOCK (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """MOCK (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_pfn()
