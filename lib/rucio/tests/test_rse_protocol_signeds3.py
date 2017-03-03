'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Wen Guan, <wen.guan@cern.ch>, 2016
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
'''
import json
import os
import tempfile

from nose.tools import raises

from rucio.common import exception
from rucio.rse import rsemanager
from rsemgr_api_test import MgrTestCases
from rucio.common.exception import FileReplicaAlreadyExists


class TestRseSignedS3(object):
    '''
    TestRseSignedS3
    '''
    tmpdir = None
    user = None

    # The setupClass and tearDownClass need some fixing, but can be ignored for this patch

    @classmethod
    def setupClass(cls):
        """SignedS3 (RSE/PROTOCOLS): Creating necessary directories and files """
        cls.site = 'BNL-OSG2_ES'
        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()
        cls.user = 'jdoe'
        with open('etc/rse_repository.json') as f:
            data = json.load(f)
        scheme = data[cls.site]['protocols']['supported']['s3+https']['scheme']
        prefix = data[cls.site]['protocols']['supported']['s3+https']['prefix']
        hostname = data[cls.site]['protocols']['supported']['s3+https']['hostname']
        port = data[cls.site]['protocols']['supported']['s3+https']['port']

        with open("%s/data.raw" % cls.tmpdir, "wb") as out:
            out.seek((1024) - 1)  # 1 kB
            out.write('\0')
        for f in MgrTestCases.files_local:
            os.symlink('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))

        cls.static_file = '%s://%s:%s/%s/user.%s/data.raw' % (scheme, hostname, port, prefix, cls.user)

        rse_settings = rsemanager.get_rse_info(cls.site)
        storage = rsemanager.create_protocol(rse_settings, operation='write', scheme='s3+https')
        storage.connect()
        for f in MgrTestCases.files_remote:
            os.symlink('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))
            destfile = rsemanager.lfns2pfns(rse_settings, [{'name': f, 'scope': 'user.%s' % (cls.user)}, ], operation='write', scheme='s3+https').values()[0]
            try:
                storage.put('%s/%s' % (cls.tmpdir, f), destfile)
            except FileReplicaAlreadyExists, e:
                print e
        f = 'data.raw'
        destfile = rsemanager.lfns2pfns(rse_settings, [{'name': f, 'scope': 'user.%s' % (cls.user)}, ], operation='write', scheme='s3+https').values()[0]
        try:
            storage.put('%s/%s' % (cls.tmpdir, f), destfile)
        except FileReplicaAlreadyExists, e:
            print e

    @classmethod
    def tearDownClass(cls):
        """SignedS3 (RSE/PROTOCOLS): Removing created directories and files """
        rse_settings = rsemanager.get_rse_info(cls.site)
        with open('etc/rse_repository.json') as f:
            data = json.load(f)
        scheme = data[cls.site]['protocols']['supported']['s3+https']['scheme']
        prefix = data[cls.site]['protocols']['supported']['s3+https']['prefix']
        hostname = data[cls.site]['protocols']['supported']['s3+https']['hostname']
        port = data[cls.site]['protocols']['supported']['s3+https']['port']
        storage = rsemanager.create_protocol(rse_settings, operation='write', scheme='s3+https')
        storage.connect()
        try:
            storage.delete('%s://%s:%s/%s/%s' % (scheme, hostname, port, prefix, 'user'))
        except Exception, e:
            print e
        try:
            storage.delete('%s://%s:%s/%s/%s' % (scheme, hostname, port, prefix, 'group'))
        except Exception, e:
            print e

    def setup(self):
        """SignedS3 (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseSignedS3.tmpdir
        self.rse_id = 'BNL-OSG2_ES'
        self.mtc = MgrTestCases(self.tmpdir, 'BNL-OSG2_ES', TestRseSignedS3.user, TestRseSignedS3.static_file)

    # Mgr-Tests: GET
    def test_multi_get_mgr_ok(self):
        """SignedS3 (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (Success)"""
        self.mtc.test_multi_get_mgr_ok()

    def test_get_mgr_ok_single_lfn(self):
        """SignedS3 (RSE/PROTOCOLS): Get a single file from storage providing LFN (Success)"""
        self.mtc.test_get_mgr_ok_single_lfn()

    def test_get_mgr_ok_single_pfn(self):
        """SignedS3 (RSE/PROTOCOLS): Get a single file from storage providing PFN (Success)"""
        self.mtc.test_get_mgr_ok_single_pfn()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_multi(self):
        """SignedS3 (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single_lfn(self):
        """SignedS3 (RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_single_lfn()

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single_pfn(self):
        """SignedS3 (RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotFound)"""
        self.mtc.test_get_mgr_SourceNotFound_single_pfn()

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """SignedS3 (RSE/PROTOCOLS): Put multiple files to storage (Success)"""
        self.mtc.test_put_mgr_ok_multi()

    def test_put_mgr_ok_single(self):
        """SignedS3 (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    @raises(exception.SourceNotFound)
    def test_put_mgr_SourceNotFound_multi(self):
        """SignedS3 (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        self.mtc.test_put_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_put_mgr_SourceNotFound_single(self):
        """SignedS3 (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        self.mtc.test_put_mgr_SourceNotFound_single()

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """SignedS3 (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        self.mtc.test_put_mgr_FileReplicaAlreadyExists_multi()

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """SignedS3 (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        self.mtc.test_put_mgr_FileReplicaAlreadyExists_single()

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """SignedS3 (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        self.mtc.test_exists_mgr_ok_multi()

    def test_exists_mgr_ok_single_lfn(self):
        """SignedS3 (RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_lfn()

    def test_exists_mgr_ok_single_pfn(self):
        """SignedS3 (RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_pfn()

    def test_exists_mgr_false_multi(self):
        """SignedS3 (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        self.mtc.test_exists_mgr_false_multi()

    def test_exists_mgr_false_single_lfn(self):
        """SignedS3 (RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_lfn()

    def test_exists_mgr_false_single_pfn(self):
        """SignedS3 (RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_pfn()

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """S3Http (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        self.mtc.test_rename_mgr_ok_multi()

    def test_rename_mgr_ok_single_lfn(self):
        """S3Http (RSE/PROTOCOLS): Rename a single file on storage using LFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_lfn()

    def test_rename_mgr_ok_single_pfn(self):
        """S3Http (RSE/PROTOCOLS): Rename a single file on storage using PFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_pfn()

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """S3Http (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_multi()

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_single_lfn(self):
        """S3Http (RSE/PROTOCOLS): Rename a single file on storage using LFN (FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_lfn()

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_single_pfn(self):
        """S3Http (RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_pfn()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_multi(self):
        """S3Http (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_multi()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """S3Http (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """S3Http (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        self.mtc.test_rename_mgr_SourceNotFound_single_pfn()
