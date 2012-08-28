# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

import os
import subprocess

from nose.tools import raises
from S3.Exceptions import S3Error

from rucio.common import exception
from rucio.rse import rsemanager


class TestRseS3():

    @classmethod
    def setUpClass(cls):
        """S3 (RSE/PROTOCOLS): Creating necessary directories and files """
        # Creating local files
        subprocess.call(["mkdir", "/tmp/rucio"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["mkdir", "/tmp/rucio/local"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["mkdir", "/tmp/rucio/remote"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        subprocess.call(["dd", "if=/dev/urandom", "of=/tmp/rucio/local/data.raw", "bs=1024", "count=1024"], stdout=open(os.devnull, "w"), stderr=subprocess.STDOUT)
        files = ["/tmp/rucio/local/1_rse_local_put.raw", "/tmp/rucio/local/2_rse_local_put.raw", "/tmp/rucio/local/3_rse_local_put.raw", "/tmp/rucio/local/4_rse_local_put.raw",
                 "/tmp/rucio/local/1_rse_remote_get.raw", "/tmp/rucio/local/2_rse_remote_get.raw", "/tmp/rucio/local/3_rse_remote_get.raw"]
        for f in files:
            #subprocess.call(['cp', '/tmp/rucio/local/data.raw', f])
            subprocess.call(['ln', '-s', '/tmp/rucio/local/data.raw', f])

        storage = rsemanager.RSE('swift.cern.ch')

        # Create test files on storage
        fnull = open(os.devnull, 'w')
        try:
            subprocess.call(["s3cmd", "mb", "s3://RSETEST"], stdout=fnull, stderr=fnull)
        except S3Error:
            pass
        files = ['1_rse_remote_get.raw', '2_rse_remote_get.raw',
                 '1_rse_remote_delete.raw', '2_rse_remote_delete.raw', '3_rse_remote_delete.raw', '4_rse_remote_delete.raw',
                 '1_rse_remote_exists.raw', '2_rse_remote_exists.raw',
                 '1_rse_remote_rename.raw', '2_rse_remote_rename.raw', '3_rse_remote_rename.raw', '4_rse_remote_rename.raw', '5_rse_remote_rename.raw', '6_rse_remote_rename.raw']
        subprocess.call(["s3cmd", "put", "/tmp/rucio/local/data.raw", storage.lfn2uri('data.raw'), "--no-progress"], stdout=fnull, stderr=fnull)
        for f in files:
            print ["s3cmd", "cp", storage.lfn2uri('data.raw'), storage.lfn2uri(f), "--no-progress"]
            subprocess.call(["s3cmd", "cp", storage.lfn2uri('data.raw'), storage.lfn2uri(f), "--no-progress"], stdout=fnull, stderr=fnull)
        fnull.close()

    def setUp(self):
        """S3 (RSE/PROTOCOLS): Creating Mgr-instance """
        # Load local creditentials from file
        self.rse_tag = 'swift.cern.ch'
        self.mgr = rsemanager.RSEMgr()

    @classmethod
    def tearDownClass(cls):
        """S3 (RSE/PROTOCOLS): Removing created directories and files """
        # Remove test files from storage
        fnull = open(os.devnull, 'w')
        subprocess.call(["s3cmd", "rb", "s3://RSETEST", "--no-progress", "--force"], stdout=fnull, stderr=fnull)
        fnull.close()
        os.system('rm -rf /tmp/rucio')

    # Mgr-Tests: GET
    def test_multi_get_mgr_ok(self):
        """S3 (RSE/PROTOCOLS): Get multiple files from storage (Success)"""
        status, details = self.mgr.download(self.rse_tag, ['1_rse_remote_get.raw', '2_rse_remote_get.raw'], '/tmp/rucio/remote')
        if not (status and details['1_rse_remote_get.raw'] and details['2_rse_remote_get.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_get_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage (Success)"""
        self.mgr.download(self.rse_tag, '1_rse_remote_get.raw', '/tmp/rucio/remote')

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Get multiple files from storage (SourceNotFound)"""
        status, details = self.mgr.download(self.rse_tag, ['not_existing_data.raw', '1_rse_remote_get.raw'], '/tmp/rucio/remote')
        if details['1_rse_remote_get.raw']:
            raise details['not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.SourceNotFound)
    def test_get_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage (SourceNotFound)"""
        self.mgr.download(self.rse_tag, 'not_existing_data.raw')

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (Success)"""
        status, details = self.mgr.upload(self.rse_tag, ['1_rse_local_put.raw', '2_rse_local_put.raw'], '/tmp/rucio/local')
        if not (status and details['1_rse_local_put.raw'] and details['2_rse_local_put.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_put_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mgr.upload(self.rse_tag, '3_rse_local_put.raw', '/tmp/rucio/local')

    @raises(exception.SourceNotFound)
    def test_put_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        status, details = self.mgr.upload(self.rse_tag, ['not_existing_data.raw', '4_rse_local_put.raw'], '/tmp/rucio/local')
        if details['4_rse_local_put.raw']:
            raise details['not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.SourceNotFound)
    def test_put_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        self.mgr.upload(self.rse_tag, 'not_existing_data2.raw', '/tmp/rucio/local')

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        status, details = self.mgr.upload(self.rse_tag, ['1_rse_remote_get.raw', '2_rse_remote_get.raw'], '/tmp/rucio/local')
        if details['1_rse_remote_get.raw']:
            raise details['2_rse_remote_get.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        self.mgr.upload(self.rse_tag, '1_rse_remote_get.raw', '/tmp/rucio/local')

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        status, details = self.mgr.delete(self.rse_tag, ['1_rse_remote_delete.raw', '2_rse_remote_delete.raw'])
        if not (status and details['1_rse_remote_delete.raw'] and details['2_rse_remote_delete.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_delete_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mgr.delete(self.rse_tag, '3_rse_remote_delete.raw')

    @raises(exception.SourceNotFound)
    def test_delete_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        status, details = self.mgr.delete(self.rse_tag, ['not_existing_data.raw', '4_rse_remote_delete.raw'])
        if details['4_rse_remote_delete.raw']:
            raise details['not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.SourceNotFound)
    def test_delete_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        self.mgr.delete(self.rse_tag, 'not_existing_data.raw')

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        status, details = self.mgr.exists(self.rse_tag, ['1_rse_remote_get.raw', '2_rse_remote_get.raw'])
        if not (status and details['1_rse_remote_get.raw'] and details['2_rse_remote_get.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_exists_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Check a single file on storage (Success)"""
        self.mgr.exists(self.rse_tag, '1_rse_remote_get.raw')

    def test_exists_mgr_false_multi(self):
        """S3 (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        status, details = self.mgr.exists(self.rse_tag, ['1_rse_remote_get.raw', 'not_existing_data.raw'])
        if status or not details['1_rse_remote_get.raw'] or details['not_existing_data.raw']:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_exists_mgr_fals_single(self):
        """S3 (RSE/PROTOCOLS): Check a single file on storage (Fail)"""
        not self.mgr.exists(self.rse_tag, 'not_existing_data.raw')

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        status, details = self.mgr.rename(self.rse_tag, {'1_rse_remote_rename.raw': '1_rse_new.raw', '2_rse_remote_rename.raw': '2_rse_new.raw'})
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_remote.raw, 4_rse_remote.raw
        if not status or not (details['1_rse_remote_rename.raw'] and details['2_rse_remote_rename.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_rename_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage (Success)"""
        self.mgr.rename(self.rse_tag, {'3_rse_remote_rename.raw': '3_rse_new.raw'})

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        status, details = self.mgr.rename(self.rse_tag, {'4_rse_remote_rename.raw': '1_rse_remote_get.raw', '5_rse_remote_rename.raw': '5_rse_new.raw'})
        if not status and details['5_rse_remote_rename.raw']:
            raise details['4_rse_remote_rename.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_mgr_FileReplicaAlreadyExists_single(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage (FileReplicaAlreadyExists)"""
        self.mgr.rename(self.rse_tag, {'6_rse_remote_rename.raw': '1_rse_remote_get.raw'})

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        status, details = self.mgr.rename(self.rse_tag, {'1_rse_not_existing.raw': '1_rse_new_not_created.raw', '2_rse_not_existing.raw': '2_rse_new_not_created.raw'})
        if not status:
            raise details['1_rse_not_existing.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.SourceNotFound)
    def test_rename_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage (SourceNotFound)"""
        self.mgr.rename(self.rse_tag, {'1_rse_not_existing.raw': '1_rse_new_not_created.raw'})
