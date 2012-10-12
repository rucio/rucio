# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012

from rucio.rse import rsemanager


class MgrTestCases():
    files_local = ["1_rse_local_put.raw", "2_rse_local_put.raw", "3_rse_local_put.raw", "4_rse_local_put.raw",
                   "1_rse_remote_get.raw", "2_rse_remote_get.raw", "3_rse_remote_get.raw"]
    files_remote = ['1_rse_remote_get.raw', '2_rse_remote_get.raw', '3_rse_remote_get.raw', '4_rse_remote_get.raw',
                    '1_rse_remote_delete.raw', '2_rse_remote_delete.raw', '3_rse_remote_delete.raw', '4_rse_remote_delete.raw',
                    '1_rse_remote_exists.raw', '2_rse_remote_exists.raw',
                    '1_rse_remote_rename.raw', '2_rse_remote_rename.raw', '3_rse_remote_rename.raw', '4_rse_remote_rename.raw', '5_rse_remote_rename.raw', '6_rse_remote_rename.raw',
                    '1_rse_remote_change_scope.raw']

    def __init__(self, tmpdir, rse_tag):
        self.rse_tag = rse_tag
        self.mgr = rsemanager.RSEMgr()
        self.tmpdir = tmpdir

    # Mgr-Tests: GET
    def test_multi_get_mgr_ok(self):
        """S3 (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (Success)"""
        status, details = self.mgr.download(self.rse_tag,
                                            {'lfns': [{'filename':'1_rse_remote_get.raw', 'scope': 'test'}, {'filename': '2_rse_remote_get.raw', 'scope': 'test'}],
                                             'pfns': ['test:3_rse_remote_get.raw', 'test:4_rse_remote_get.raw']},
                                            self.tmpdir)
        if not (status and details['test:1_rse_remote_get.raw'] and details['test:2_rse_remote_get.raw'] and details['test:3_rse_remote_get.raw'] and details['test:4_rse_remote_get.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_get_mgr_ok_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage provding the LFN (Success)"""
        self.mgr.download(self.rse_tag, {'lfns': [{'filename': '1_rse_remote_get.raw', 'scope': 'test'}]}, self.tmpdir)

    def test_get_mgr_ok_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage providing the PFN (Success)"""
        self.mgr.download(self.rse_tag, {'pfns': ['test:2_rse_remote_get.raw']}, self.tmpdir)

    def test_get_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Get multiple files from storage providing LFNs  and PFNs (SourceNotFound)"""
        status, details = self.mgr.download(self.rse_tag,
                                            {'lfns': [{'filename': '1_not_existing_data.raw', 'scope': 'test'}, {'filename': '1_rse_remote_get.raw', 'scope': 'test'}],
                                             'pfns': ['test:2_not_existing_data.raw', 'test:2_rse_remote_get.raw']},
                                            self.tmpdir)
        if details['test:1_rse_remote_get.raw'] and details['test:2_rse_remote_get.raw'] and details['test:1_not_existing_data.raw'].__class__.__name__ == 'SourceNotFound' and details['test:2_not_existing_data.raw'].__class__.__name__ == 'SourceNotFound':
            raise details['test:1_not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_get_mgr_SourceNotFound_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNotFound)"""
        self.mgr.download(self.rse_tag, {'lfns': [{'filename': 'not_existing_data.raw', 'scope': 'test'}]})

    def test_get_mgr_SourceNotFound_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotFound)"""
        self.mgr.download(self.rse_tag, {'pfns': ['test:not_existing_data.raw']})

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (Success)"""
        status, details = self.mgr.upload(self.rse_tag, [{'filename': '1_rse_local_put.raw', 'scope': 'test'}, {'filename': '2_rse_local_put.raw', 'scope': 'test'}], self.tmpdir)
        if not (status and details['test:1_rse_local_put.raw'] and details['test:2_rse_local_put.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_put_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mgr.upload(self.rse_tag, {'filename': '3_rse_local_put.raw', 'scope': 'test'}, self.tmpdir)

    def test_put_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        status, details = self.mgr.upload(self.rse_tag, [{'filename': 'not_existing_data.raw', 'scope': 'test'}, {'filename': '4_rse_local_put.raw', 'scope': 'test'}], self.tmpdir)
        if details['test:4_rse_local_put.raw']:
            raise details['test:not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_put_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        self.mgr.upload(self.rse_tag, {'filename': 'not_existing_data2.raw', 'scope': 'test'}, self.tmpdir)

    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        status, details = self.mgr.upload(self.rse_tag, [{'filename': '1_rse_remote_get.raw', 'scope': 'test'}, {'filename': '2_rse_remote_get.raw', 'scope': 'test'}], self.tmpdir)
        if details['test:1_rse_remote_get.raw']:
            raise details['test:2_rse_remote_get.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        self.mgr.upload(self.rse_tag, {'filename': '1_rse_remote_get.raw', 'scope': 'test'}, self.tmpdir)

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        status, details = self.mgr.delete(self.rse_tag, [{'filename': '1_rse_remote_delete.raw', 'scope': 'test'}, {'filename': '2_rse_remote_delete.raw', 'scope': 'test'}])
        if not (status and details['test:1_rse_remote_delete.raw'] and details['test:2_rse_remote_delete.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_delete_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mgr.delete(self.rse_tag, {'filename': '3_rse_remote_delete.raw', 'scope': 'test'})

    def test_delete_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        status, details = self.mgr.delete(self.rse_tag, [{'filename': 'not_existing_data.raw', 'scope': 'test'}, {'filename': '4_rse_remote_delete.raw', 'scope': 'test'}])
        if details['test:4_rse_remote_delete.raw']:
            raise details['test:not_existing_data.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_delete_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        self.mgr.delete(self.rse_tag, {'filename': 'not_existing_data.raw', 'scope': 'test'})

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        status, details = self.mgr.exists(self.rse_tag, [{'filename': '1_rse_remote_get.raw', 'scope': 'test'}, {'filename': '2_rse_remote_get.raw', 'scope': 'test'}])
        if not (status and details['test:1_rse_remote_get.raw'] and details['test:2_rse_remote_get.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_exists_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Check a single file on storage (Success)"""
        self.mgr.exists(self.rse_tag, {'filename': '1_rse_remote_get.raw', 'scope': 'test'})

    def test_exists_mgr_false_multi(self):
        """S3 (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        status, details = self.mgr.exists(self.rse_tag, [{'filename': '1_rse_remote_get.raw', 'scope': 'test'}, {'filename': 'not_existing_data.raw', 'scope': 'test'}])
        if status or not details['test:1_rse_remote_get.raw'] or details['test:not_existing_data.raw']:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_exists_mgr_fals_single(self):
        """S3 (RSE/PROTOCOLS): Check a single file on storage (Fail)"""
        not self.mgr.exists(self.rse_tag, {'filename': 'not_existing_data.raw', 'scope': 'test'})

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        status, details = self.mgr.rename(self.rse_tag, [{'filename': '1_rse_remote_rename.raw', 'scope': 'test', 'new_filename': '1_rse_new.raw'}, {'filename': '2_rse_remote_rename.raw', 'scope': 'test', 'new_filename': '2_rse_new.raw'}])
        # Files after renaming: 1_rse_new.raw, 2_rse_new.raw, 3_rse_remote.raw, 4_rse_remote.raw
        if not status or not (details['test:1_rse_remote_rename.raw'] and details['test:2_rse_remote_rename.raw']):
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_rename_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage (Success)"""
        self.mgr.rename(self.rse_tag, {'filename': '3_rse_remote_rename.raw', 'scope': 'test', 'new_filename': '3_rse_new.raw', 'new_scope': 'test'})

    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        status, details = self.mgr.rename(self.rse_tag, [{'filename': '4_rse_remote_rename.raw', 'scope': 'test', 'new_filename': '1_rse_remote_get.raw', 'new_scope': 'test'},
                                          {'filename': '5_rse_remote_rename.raw', 'scope': 'test', 'new_filename': '5_rse_new.raw'}])
        if not status and details['test:5_rse_remote_rename.raw']:
            raise details['test:4_rse_remote_rename.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_rename_mgr_FileReplicaAlreadyExists_single(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage (FileReplicaAlreadyExists)"""
        self.mgr.rename(self.rse_tag, {'filename': '6_rse_remote_rename.raw', 'scope': 'test', 'new_filename': '1_rse_remote_get.raw', 'new_scope': 'test'})

    def test_rename_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        status, details = self.mgr.rename(self.rse_tag, [{'filename': '1_rse_not_existing.raw', 'scope': 'test', 'new_filename': '1_rse_new_not_created.raw'},
                                          {'filename': '2_rse_not_existing.raw', 'scope': 'test', 'new_filename': '2_rse_new_not_created.raw'}])
        if not status:
            raise details['test:1_rse_not_existing.raw']
        else:
            raise Exception('Return not as expected: %s, %s' % (status, details))

    def test_rename_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage (SourceNotFound)"""
        self.mgr.rename(self.rse_tag, {'filename': '1_rse_not_existing.raw', 'scope': 'test', 'new_filename': '1_rse_new_not_created.raw'})

    def test_change_scope_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Change the scope of a single file on storage (Success)"""
        self.mgr.rename(self.rse_tag, {'filename': '1_rse_remote_change_scope.raw', 'scope': 'test', 'new_filename': '1_rse_remote_change_scope.raw', 'new_scope': 'test_new'})
