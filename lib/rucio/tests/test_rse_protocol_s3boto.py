# -*- coding: utf-8 -*-
# Copyright CERN since 2012
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

from __future__ import print_function

import os
import tempfile
import unittest
from uuid import uuid4 as uuid

import boto
import boto.s3.connection
import pytest
from boto.s3.key import Key

from rucio.common import exception
from rucio.rse import rsemanager as mgr
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from rucio.tests.rsemgr_api_test import MgrTestCases

try:
    # PY2
    import urlparse
except ImportError:
    # PY3
    import urllib.parse as urlparse


def get_bucket_key_name(pfn):
    parsed = urlparse.urlparse(pfn)
    path = parsed.path.strip("/")

    pos = path.index("/")
    bucket_name = path[:pos]
    key_name = path[pos + 1:]
    return bucket_name, key_name


def get_bucket_key(pfn, conn, create=False):
    bucket_name, key_name = get_bucket_key_name(pfn)
    if create:
        bucket = conn.create_bucket(bucket_name)
        key = Key(bucket, key_name)
    else:
        bucket = conn.get_bucket(bucket_name)
        key = bucket.get_key(key_name)

    return key


@skip_rse_tests_with_accounts
class TestRseS3(unittest.TestCase):
    tmpdir = None
    user = None

    @classmethod
    def setUpClass(cls):
        """S3 (RSE/PROTOCOLS): Creating necessary directories and files """
        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()
        cls.user = uuid()
        # cls.user = 'jdoe'  # use again when latency issue with S3 storage is resolved

        with open("%s/data.raw" % cls.tmpdir, "wb") as out:
            out.seek((1024 * 1024) - 1)  # 1 MB
            out.write(b'\0')
        for f in MgrTestCases.files_local:
            os.symlink('%s/data.raw' % cls.tmpdir, '%s/%s' % (cls.tmpdir, f))

        rse_tag = 'BNL-BOTO'
        rse_settings = mgr.get_rse_info(rse_tag)
        try:
            data = load_test_conf_file('rse-accounts.cfg')
            rse_settings['credentials'] = data[rse_tag]
        except KeyError:
            print('No credentials found for this RSE.')
            pass

        for protocol in rse_settings['protocols']:
            if protocol['scheme'] == 's3':
                break

        conn = boto.connect_s3(host=protocol['hostname'],
                               port=int(protocol.get('port', 80)),
                               aws_access_key_id=rse_settings['credentials']['access_key'],
                               aws_secret_access_key=rse_settings['credentials']['secret_key'],
                               is_secure=rse_settings['credentials'].get('is_secure', False),
                               calling_format=boto.s3.connection.OrdinaryCallingFormat())

        cls.static_file = mgr.lfns2pfns(rse_settings, {'name': 'data.raw', 'scope': 'user.%s' % cls.user}).values()[0]
        key = get_bucket_key(cls.static_file, conn, create=True)
        key.set_contents_from_filename("%s/data.raw" % cls.tmpdir)
        for f in MgrTestCases.files_remote:
            pfn = mgr.lfns2pfns(rse_settings, {'name': f, 'scope': 'user.%s' % cls.user}).values()[0]
            bucket_name, key_name = get_bucket_key_name(pfn)
            key.copy(bucket_name, key_name)

    def setUp(self):
        """S3 (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseS3.tmpdir
        self.mtc = MgrTestCases(self.tmpdir, 'BNL-BOTO', TestRseS3.user, TestRseS3.static_file)

    @classmethod
    def tearDownClass(cls):
        """S3 (RSE/PROTOCOLS): Removing created directories and files """
        # Remove test files from storage
        # rse_tag = 'AMAZON-BOTO'
        rse_tag = 'BNL-BOTO'
        rse_settings = mgr.get_rse_info(rse_tag)
        try:
            data = load_test_conf_file('rse-accounts.cfg')
            rse_settings['credentials'] = data[rse_tag]
        except KeyError:
            print('No credentials found for this RSE.')
            pass

        for protocol in rse_settings['protocols']:
            if protocol['scheme'] == 's3':
                break

        conn = boto.connect_s3(host=protocol['hostname'],
                               port=int(protocol.get('port', 80)),
                               aws_access_key_id=rse_settings['credentials']['access_key'],
                               aws_secret_access_key=rse_settings['credentials']['secret_key'],
                               is_secure=rse_settings['credentials'].get('is_secure', False),
                               calling_format=boto.s3.connection.OrdinaryCallingFormat())
        for protocol in rse_settings['protocols']:
            if protocol['scheme'] == 's3':
                break

        bucket_name = protocol['prefix']
        bucket = conn.get_bucket(bucket_name)
        keys = bucket.list()
        for key in keys:
            key.delete()

    # Mgr-Tests: GET
    def test_multi_get_mgr_ok(self):
        """S3 (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (Success)"""
        self.mtc.test_multi_get_mgr_ok()

    def test_get_mgr_ok_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage providing LFN (Success)"""
        self.mtc.test_get_mgr_ok_single_lfn()

    def test_get_mgr_ok_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage providing PFN (Success)"""
        self.mtc.test_get_mgr_ok_single_pfn()

    def test_get_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Get multiple files from storage providing LFNs and PFNs (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_multi()

    def test_get_mgr_SourceNotFound_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage providing LFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_single_lfn()

    def test_get_mgr_SourceNotFound_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Get a single file from storage providing PFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_get_mgr_SourceNotFound_single_pfn()

    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (Success)"""
        self.mtc.test_put_mgr_ok_multi()

    def test_put_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (Success)"""
        self.mtc.test_put_mgr_ok_single()

    def test_put_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_put_mgr_SourceNotFound_multi()

    def test_put_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_put_mgr_SourceNotFound_single()

    def test_put_mgr_FileReplicaAlreadyExists_multi(self):
        """S3 (RSE/PROTOCOLS): Put multiple files to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_put_mgr_FileReplicaAlreadyExists_multi()

    def test_put_mgr_FileReplicaAlreadyExists_single(self):
        """S3 (RSE/PROTOCOLS): Put a single file to storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_put_mgr_FileReplicaAlreadyExists_single()

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        self.mtc.test_delete_mgr_ok_multi()

    def test_delete_mgr_ok_single(self):
        """S3 (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        self.mtc.test_delete_mgr_ok_single()

    def test_delete_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Delete multiple files from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_delete_mgr_SourceNotFound_multi()

    def test_delete_mgr_SourceNotFound_single(self):
        """S3 (RSE/PROTOCOLS): Delete a single file from storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_delete_mgr_SourceNotFound_single()

    # MGR-Tests: EXISTS
    def test_exists_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Check multiple files on storage (Success)"""
        self.mtc.test_exists_mgr_ok_multi()

    def test_exists_mgr_ok_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Check a single file on storage using LFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_lfn()

    def test_exists_mgr_ok_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Check a single file on storage using PFN (Success)"""
        self.mtc.test_exists_mgr_ok_single_pfn()

    def test_exists_mgr_false_multi(self):
        """S3 (RSE/PROTOCOLS): Check multiple files on storage (Fail)"""
        self.mtc.test_exists_mgr_false_multi()

    def test_exists_mgr_false_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Check a single file on storage using LFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_lfn()

    def test_exists_mgr_false_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Check a single file on storage using PFN (Fail)"""
        self.mtc.test_exists_mgr_false_single_pfn()

    # MGR-Tests: RENAME
    def test_rename_mgr_ok_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (Success)"""
        self.mtc.test_rename_mgr_ok_multi()

    def test_rename_mgr_ok_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage using LFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_lfn()

    def test_rename_mgr_ok_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage using PFN (Success)"""
        self.mtc.test_rename_mgr_ok_single_pfn()

    def test_rename_mgr_FileReplicaAlreadyExists_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_multi()

    def test_rename_mgr_FileReplicaAlreadyExists_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage using LFN (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_lfn()

    def test_rename_mgr_FileReplicaAlreadyExists_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage using PFN (FileReplicaAlreadyExists)"""
        with pytest.raises(exception.FileReplicaAlreadyExists):
            self.mtc.test_rename_mgr_FileReplicaAlreadyExists_single_pfn()

    def test_rename_mgr_SourceNotFound_multi(self):
        """S3 (RSE/PROTOCOLS): Rename multiple files on storage (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_multi()

    def test_rename_mgr_SourceNotFound_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage using LFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_lfn()

    def test_rename_mgr_SourceNotFound_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Rename a single file on storage using PFN (SourceNotFound)"""
        with pytest.raises(exception.SourceNotFound):
            self.mtc.test_rename_mgr_SourceNotFound_single_pfn()

    def test_change_scope_mgr_ok_single_lfn(self):
        """S3 (RSE/PROTOCOLS): Change the scope of a single file on storage using LFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_lfn()

    def test_change_scope_mgr_ok_single_pfn(self):
        """S3 (RSE/PROTOCOLS): Change the scope of a single file on storage using PFN (Success)"""
        self.mtc.test_change_scope_mgr_ok_single_pfn()
