# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from nose.tools import raises

from rucio.common import exception
from rsemgr_api_test import MgrTestCases


class TestRseMOCK():
    tmpdir = '/tmp/'
    user = None
    static_file = 'mock:///tmp/rucio_rse/file1'

    def setup(self):
        """MOCK (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseMOCK.tmpdir
        self.rse_id = 'MOCK'
        self.mtc = MgrTestCases(tmpdir=self.tmpdir, rse_tag='MOCK', user=TestRseMOCK.user, static_file=TestRseMOCK.static_file)

    # Mgr-Tests: GET
    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_multi(self):
        """MOCK (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (SourceNotFound)"""
        for f in MgrTestCases.files_remote:
            self.mtc.mgr.upload(self.rse_id, [{'filename': f, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_get_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single_lfn(self):
        """MOCK (RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNotFound)"""
        for f in MgrTestCases.files_remote:
            self.mtc.mgr.upload(self.rse_id, [{'filename': f, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_get_mgr_SourceNotFound_single_lfn()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single_pfn(self):
        """MOCK (RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotFound)"""
        for f in MgrTestCases.files_remote:
            self.mtc.mgr.upload(self.rse_id, [{'filename': f, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_get_mgr_SourceNotFound_single_pfn()

    # Mgr-Tests: PUT
    def test_put_mgr_ok_single(self):
        """MOCK (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """MOCK (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        for f in MgrTestCases.files_remote:
            self.mtc.mgr.upload(self.rse_id, [{'filename': f, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_delete_mgr_ok_multi()

    def test_delete_mgr_ok_single(self):
        """MOCK (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        for f in MgrTestCases.files_remote:
            self.mtc.mgr.upload(self.rse_id, [{'filename': f, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_delete_mgr_ok_single()

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """MOCK (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        for f in MgrTestCases.files_remote:
            self.mtc.mgr.upload(self.rse_id, [{'filename': f, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_exists_mgr_ok_multi()

    def test_exists_mgr_ok_single_lfn(self):
        """MOCK (RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_lfn()

    def test_exists_mgr_ok_single_pfn(self):
        """MOCK (RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_pfn()

    def test_exists_mgr_false_multi(self):
        """MOCK (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        for f in MgrTestCases.files_remote:
            self.mtc.mgr.upload(self.rse_id, [{'filename': f, 'scope': 'user.%s' % self.user}, ])
        self.mtc.test_exists_mgr_false_multi()

    def test_exists_mgr_false_single(self):
        """MOCK (RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_lfn()

    def test_exists_mgr_false_single_pfn(self):
        """MOCK (RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_pfn()

    # MGR-Tests: RENAME

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """MOCK (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """MOCK (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_single_pfn()
