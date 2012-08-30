# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

import json
import os
import pysftp
import shutil
import tempfile

from nose.tools import raises

from rucio.common import exception
from rucio.rse import rsemanager


class TestRseSFTP():
    tmpdir = None

    @classmethod
    def setUpClass(cls):
        """SFTP (RSE/PROTOCOLS): Creating necessary directories and files """
        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()

        with open("%s/data.raw" % cls.tmpdir, "wb") as out:
            out.seek((1024 * 1024) - 1)  # 1 MB
            out.write('\0')
        files = ["1_rse_local_put.raw", "2_rse_local_put.raw", "3_rse_local_put.raw", "4_rse_local_put.raw",
                 "1_rse_remote_get.raw", "2_rse_remote_get.raw", "3_rse_remote_get.raw"]
        for f in files:
            os.symlink('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))

        storage = rsemanager.RSE('lxplus.cern.ch')
        # Load local creditentials from file
        data = json.load(open('etc/rse-accounts.cfg'))
        credentials = data['lxplus.cern.ch']
        lxplus = pysftp.Connection(**credentials)
        lxplus.execute('mkdir ~/rse_test')
        files = ['1_rse_remote_get.raw', '2_rse_remote_get.raw',
                 '1_rse_remote_delete.raw', '2_rse_remote_delete.raw', '3_rse_remote_delete.raw', '4_rse_remote_delete.raw',
                 '1_rse_remote_exists.raw', '2_rse_remote_exists.raw',
                 '1_rse_remote_rename.raw', '2_rse_remote_rename.raw', '3_rse_remote_rename.raw', '4_rse_remote_rename.raw', '5_rse_remote_rename.raw', '6_rse_remote_rename.raw']
        lxplus.execute('dd if=/dev/urandom of=~/rse_test/data.raw bs=1024 count=1024')
        for f in files:
            lxplus.execute('ln -s ~/rse_test/data.raw %s' % storage.lfn2uri(f))
        lxplus.close()

    @classmethod
    def tearDownClass(cls):
        """SFTP (RSE/PROTOCOLS): Removing created directorie s and files """
        # Load local creditentials from file
        credentials = {}
        data = json.load(open('etc/rse-accounts.cfg'))
        credentials['username'] = str(data['lxplus.cern.ch']['username'])
        credentials['password'] = str(data['lxplus.cern.ch']['password'])
        credentials['host'] = 'lxplus.cern.ch'
        lxplus = pysftp.Connection(**credentials)
        lxplus.execute('rm -rf ~/rse_test')
        lxplus.close()
        shutil.rmtree(cls.tmpdir)

    def setUp(self):
        """SFTP (RSE/PROTOCOLS): Creating Mgr-instance """
        self.rse_tag = 'lxplus.cern.ch'
        self.mgr = rsemanager.RSEMgr()

    # Mgr-Tests: GET
    def test_get_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Get multiple files from storage (Success)"""
        status, details = self.mgr.download(self.rse_tag, ['1_rse_remote_get.raw', '2_rse_remote_get.raw'], self.tmpdir)
        if not (status and details['1_rse_remote_get.raw'] and details['2_rse_remote_get.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_get_ok_single(self):
        """SFTP (RSE/PROTOCOLS): Get a single file from storage (Success)"""
        self.mgr.download(self.rse_tag, '1_rse_remote_get.raw', self.tmpdir)

    @raises(exception.SourceNotFound)
    def test_get_SourceNotFound_multi(self):
        """SFTP (RSE/PROTOCOLS): Get multiple files from storage (SourceNotFound)"""
        status, details = self.mgr.download(self.rse_tag, ['not_existing_data.raw', '1_rse_remote_get.raw'], self.tmpdir)
        if details['1_rse_remote_get.raw']:
            raise details['not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.SourceNotFound)
    def test_get_SourceNotFound_single(self):
        """SFTP (RSE/PROTOCOLS): Get a single file from storage (SourceNotFound)"""
        self.mgr.download(self.rse_tag, 'not_existing_data.raw')

    # Mgr-Tests: PUT
    def test_put_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Put multiple files to storage (Success)"""
        status, details = self.mgr.upload(self.rse_tag, ['1_rse_local_put.raw', '2_rse_local_put.raw'], self.tmpdir)
        if not (status and details['1_rse_local_put.raw'] and details['2_rse_local_put.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_put_ok_single(self):
        """SFTP (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mgr.upload(self.rse_tag, '3_rse_local_put.raw', self.tmpdir)

    @raises(exception.SourceNotFound)
    def test_put_SourceNotFound_multi(self):
        """SFTP (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        status, details = self.mgr.upload(self.rse_tag, ['not_existing_data.raw', '4_rse_local_put.raw'], self.tmpdir)
        if details['4_rse_local_put.raw']:
            raise details['not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.SourceNotFound)
    def test_put_SourceNotFound_single(self):
        """SFTP (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        self.mgr.upload(self.rse_tag, 'not_existing_data2.raw', self.tmpdir)

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_FileReplicaAlreadyExists_multi(self):
        """SFTP (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        status, details = self.mgr.upload(self.rse_tag, ['1_rse_remote_get.raw', '2_rse_remote_get.raw'], self.tmpdir)
        if details['1_rse_remote_get.raw']:
            raise details['2_rse_remote_get.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.FileReplicaAlreadyExists)
    def test_put_FileReplicaAlreadyExists_single(self):
        """SFTP (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        self.mgr.upload(self.rse_tag, '1_rse_remote_get.raw', self.tmpdir)

    # MGR-Tests: DELETE
    def test_delete_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        status, details = self.mgr.delete(self.rse_tag, ['1_rse_remote_delete.raw', '2_rse_remote_delete.raw'])
        if not (status and details['1_rse_remote_delete.raw'] and details['2_rse_remote_delete.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_delete_ok_single(self):
        """SFTP (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mgr.delete(self.rse_tag, '3_rse_remote_delete.raw')

    @raises(exception.SourceNotFound)
    def test_delete_SourceNotFound_multi(self):
        """SFTP (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        status, details = self.mgr.delete(self.rse_tag, ['not_existing_data.raw', '4_rse_remote_delete.raw'])
        if details['4_rse_remote_delete.raw']:
            raise details['not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.SourceNotFound)
    def test_delete_SourceNotFound_single(self):
        """SFTP (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        self.mgr.delete(self.rse_tag, 'not_existing_data.raw')

    # MGR-Tests: EXISTS
    def test_exists_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        status, details = self.mgr.exists(self.rse_tag, ['1_rse_remote_get.raw', '2_rse_remote_get.raw'])
        if not (status and details['1_rse_remote_get.raw'] and details['2_rse_remote_get.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_exists_ok_single(self):
        """SFTP (RSE/PROTOCOLS): Check a single file on storage (Success)"""
        self.mgr.exists(self.rse_tag, '1_rse_remote_get.raw')

    def test_exists_false_multi(self):
        """SFTP (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        status, details = self.mgr.exists(self.rse_tag, ['1_rse_remote_get.raw', 'not_existing_data.raw'])
        if status or not details['1_rse_remote_get.raw'] or details['not_existing_data.raw']:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_exists_false_single(self):
        """SFTP (RSE/PROTOCOLS): Check a single file on storage (Fail)"""
        not self.mgr.exists(self.rse_tag, 'not_existing_data.raw')

    # MGR-Tests: RENAME
    def test_rename_ok_multi(self):
        """SFTP (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        status, details = self.mgr.rename(self.rse_tag, {'1_rse_remote_rename.raw': '1_rse_new.raw', '2_rse_remote_rename.raw': '2_rse_new.raw'})
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_remote.raw, 4_rse_remote.raw
        if not status or not (details['1_rse_remote_rename.raw'] and details['2_rse_remote_rename.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_rename_ok_single(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage (Success)"""
        self.mgr.rename(self.rse_tag, {'3_rse_remote_rename.raw': '3_rse_new.raw'})

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_FileReplicaAlreadyExists_multi(self):
        """SFTP (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        status, details = self.mgr.rename(self.rse_tag, {'4_rse_remote_rename.raw': '1_rse_remote_get.raw', '5_rse_remote_rename.raw': '5_rse_new.raw'})
        if not status and details['5_rse_remote_rename.raw']:
            raise details['4_rse_remote_rename.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.FileReplicaAlreadyExists)
    def test_rename_FileReplicaAlreadyExists_single(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage (FileReplicaAlreadyExists)"""
        self.mgr.rename(self.rse_tag, {'6_rse_remote_rename.raw': '1_rse_remote_get.raw'})

    @raises(exception.SourceNotFound)
    def test_rename_SourceNotFound_multi(self):
        """SFTP (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        status, details = self.mgr.rename(self.rse_tag, {'1_rse_not_existing.raw': '1_rse_new_not_created.raw', '2_rse_not_existing.raw': '2_rse_new_not_created.raw'})
        if not status:
            raise details['1_rse_not_existing.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    @raises(exception.SourceNotFound)
    def test_rename_SourceNotFound_single(self):
        """SFTP (RSE/PROTOCOLS): Rename a single file on storage (SourceNotFound)"""
        self.mgr.rename(self.rse_tag, {'1_rse_not_existing.raw': '1_rse_new_not_created.raw'})
