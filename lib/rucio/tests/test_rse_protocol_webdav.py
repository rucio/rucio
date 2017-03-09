# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2012
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

"""
Test the WebDAV protocol
"""

import json
import os
import tempfile

import requests
from nose.tools import raises

from rucio.common import exception
from rucio.rse import rsemanager
from rucio.tests.rsemgr_api_test import MgrTestCases
from rucio.common.exception import FileReplicaAlreadyExists


class TestRseWebDAV(object):
    """
    Test the WebDAV protocol
    """

    tmpdir = None
    user = None

    # The setupClass and tearDownClass need some fixing, but can be ignored for this patch

    @classmethod
    def setupClass(cls):
        """WebDAV (RSE/PROTOCOLS): Creating necessary directories and files """
        session = requests.Session()
        session.cert = os.getenv('X509_USER_PROXY')
        session.verify = False
        cls.site = 'FZK-LCG2_SCRATCHDISK'
        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()
        cls.user = 'jdoe'
        with open('etc/rse_repository.json') as f:
            data = json.load(f)
        scheme = data[cls.site]['protocols']['supported']['https']['scheme']
        prefix = data[cls.site]['protocols']['supported']['https']['prefix']
        hostname = data[cls.site]['protocols']['supported']['https']['hostname']
        port = data[cls.site]['protocols']['supported']['https']['port']

        with open("%s/data.raw" % cls.tmpdir, "wb") as out:
            out.seek((1024) - 1)  # 1 kB
            out.write('\0')
        for f in MgrTestCases.files_local:
            os.symlink('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))

        cls.static_file = '%s://%s:%s%sdata.raw' % (scheme, hostname, port, prefix)

        rse_settings = rsemanager.get_rse_info(cls.site)
        storage = rsemanager.create_protocol(rse_settings, operation='write', scheme='https')
        storage.connect()
        for f in MgrTestCases.files_remote:
            os.symlink('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))
            destfile = rsemanager.lfns2pfns(rse_settings, [{'name': f, 'scope': 'user.%s' % (cls.user)}, ], operation='write', scheme='https').values()[0]
            try:
                storage.put('%s/%s' % (cls.tmpdir, f), destfile)
            except FileReplicaAlreadyExists, e:
                print e
        with open('%s/data.raw' % cls.tmpdir, 'rb') as f_file:
            session.put(cls.static_file, data=f_file.read(), verify=False, allow_redirects=True)

    @classmethod
    def tearDownClass(cls):
        """WebDAV (RSE/PROTOCOLS): Removing created directories and files """
        rse_settings = rsemanager.get_rse_info(cls.site)
        with open('etc/rse_repository.json') as f:
            data = json.load(f)
        scheme = data[cls.site]['protocols']['supported']['https']['scheme']
        prefix = data[cls.site]['protocols']['supported']['https']['prefix']
        hostname = data[cls.site]['protocols']['supported']['https']['hostname']
        port = data[cls.site]['protocols']['supported']['https']['port']
        storage = rsemanager.create_protocol(rse_settings, operation='write', scheme='https')
        print rse_settings
        storage.connect()
        status1 = storage.delete('%s://%s:%s%suser/%s' % (scheme, hostname, port, prefix, cls.user))
        print status1
        status2 = storage.delete('%s://%s:%s%sgroup/%s' % (scheme, hostname, port, prefix, cls.user))
        print status2

    def setup(self):
        """WebDAV (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseWebDAV.tmpdir
        self.rse_id = 'FZK-LCG2_SCRATCHDISK'
        self.mtc = MgrTestCases(self.tmpdir, 'FZK-LCG2_SCRATCHDISK', TestRseWebDAV.user, TestRseWebDAV.static_file)

    # Mgr-Tests: GET
    def test_multi_get_mgr_ok(self):
        """WebDAV (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (Success)"""
        self.mtc.test_multi_get_mgr_ok()

    def test_get_mgr_ok_single_lfn(self):
        """WebDAV (RSE/PROTOCOLS): Get a single file from storage providing LFN (Success)"""
        self.mtc.test_get_mgr_ok_single_lfn()

    def test_get_mgr_ok_single_pfn(self):
        """WebDAV (RSE/PROTOCOLS): Get a single file from storage providing PFN (Success)"""
        self.mtc.test_get_mgr_ok_single_pfn()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_multi(self):
        """WebDAV (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single_lfn(self):
        """WebDAV (RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_single_lfn()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single_pfn(self):
        """WebDAV (RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_single_pfn()

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """WebDAV (RSE/PROTOCOLS): Put multiple files to storage (Success)"""
        self.mtc.test_put_mgr_ok_multi()

    def test_put_mgr_ok_single(self):
        """WebDAV (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    @raises(exception.SourceNotFound)
    def test_put_mgr_SourceNotFound_multi(self):
        """WebDAV (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        self.mtc.test_put_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_put_mgr_SourceNotFound_single(self):
        """WebDAV (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        self.mtc.test_put_mgr_SourceNotFound_single()

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """WebDAV (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        self.mtc.test_put_mgr_FileReplicaAlreadyExists_multi()

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """WebDAV (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        self.mtc.test_put_mgr_FileReplicaAlreadyExists_single()

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """WebDAV (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        self.mtc.test_delete_mgr_ok_multi()

    def test_delete_mgr_ok_single(self):
        """WebDAV (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mtc.test_delete_mgr_ok_single()

    @raises(exception.SourceNotFound)
    def test_delete_mgr_SourceNotFound_multi(self):
        """WebDAV (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        self.mtc.test_delete_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_delete_mgr_SourceNotFound_single(self):
        """WebDAV (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        self.mtc.test_delete_mgr_SourceNotFound_single()

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """WebDAV (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        self.mtc.test_exists_mgr_ok_multi()

    def test_exists_mgr_ok_single_lfn(self):
        """WebDAV (RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_lfn()

    def test_exists_mgr_ok_single_pfn(self):
        """WebDAV (RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_pfn()

    def test_exists_mgr_false_multi(self):
        """WebDAV (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        self.mtc.test_exists_mgr_false_multi()

    def test_exists_mgr_false_single_lfn(self):
        """WebDAV (RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_lfn()

    def test_exists_mgr_false_single_pfn(self):
        """WebDAV (RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_pfn()

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """WebDAV (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        self.mtc.test_rename_mgr_ok_multi()

    def test_rename_mgr_ok_single_lfn(self):
        """WebDAV (RSE/PROTOCOLS): Rename a single file on storage using LFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_lfn()

    def test_rename_mgr_ok_single_pfn(self):
        """WebDAV (RSE/PROTOCOLS): Rename a single file on storage using PFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_pfn()

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """WebDAV (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_multi()

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_single_lfn(self):
        """WebDAV (RSE/PROTOCOLS): Rename a single file on storage using LFN (FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_lfn()

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_single_pfn(self):
        """WebDAV (RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_pfn()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_multi(self):
        """WebDAV (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """WebDAV (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """WebDAV (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_single_pfn()

    def test_change_scope_mgr_ok_single_lfn(self):
        """WebDAV (RSE/PROTOCOLS): Change the scope of a single file on storage using LFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_lfn()

    def test_change_scope_mgr_ok_single_pfn(self):
        """WebDAV (RSE/PROTOCOLS): Change the scope of a single file on storage using PFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_pfn()
