# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2014-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021

from __future__ import print_function

import unittest
from os import remove, path
import re

from rucio.common.utils import generate_uuid as uuid, execute


def file_generator(size=2048, namelen=10):
    """ Create a bogus file and returns it's name.
    :param size: size in bytes
    :returns: The name of the generated file.
    """
    fn = '/tmp/rucio_testfile_' + uuid()
    execute('dd if=/dev/urandom of={0} count={1} bs=1'.format(fn, size))
    return fn


def get_scope_and_rses():
    """
    Check if xrd containers rses for xrootd are available in the testing environment.
    :return: A tuple (scope, rses) for the rucio client where scope is mock/test and rses is a list.
    """
    cmd = "rucio list-rses --expression 'test_container_xrd=True'"
    print(cmd)
    exitcode, out, err = execute(cmd)
    print(out, err)
    rses = out.split()
    if len(rses) == 0:
        return 'mock', ['MOCK-POSIX']
    return 'test', rses


def delete_rules(did):
    # get the rules for the file
    print('Deleting rules')
    cmd = "rucio list-rules --did {0} | grep {0} | cut -f1 -d\\ ".format(did)
    print(cmd)
    exitcode, out, err = execute(cmd)
    print(out, err)
    rules = out.split()
    # delete the rules for the file
    for rule in rules:
        cmd = "rucio delete-rule {0}".format(rule)
        print(cmd)
        exitcode, out, err = execute(cmd)


class TestRucioServer(unittest.TestCase):

    def setUp(self):
        self.marker = '$ > '
        self.scope, self.rses = get_scope_and_rses()
        self.rse = self.rses[0]
        self.generated_dids = []

    def tearDown(self):
        for did in self.generated_dids:
            delete_rules(did)
            self.generated_dids.remove(did)

    def test_ping(self):
        """CLIENT (USER): rucio ping"""
        cmd = 'rucio ping'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertEqual(exitcode, 0)

    def test_whoami(self):
        """CLIENT (USER): rucio whoami"""
        cmd = 'rucio whoami'
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertEqual(exitcode, 0)

    def test_upload_download(self):
        """CLIENT(USER): rucio upload files to dataset/download dataset"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_' + uuid()

        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} {2} {3} {4} {1}:{5}'.format(self.rse, self.scope, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        self.assertEqual(exitcode, 0)

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # Downloading dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The files should be there
        cmd = 'ls /tmp/{0}/rucio_testfile_*'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        self.assertEqual(exitcode, 0)

        # cleaning
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file1[5:])
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file2[5:])
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file3[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1, tmp_file2, tmp_file3, tmp_dsn)]
        self.generated_dids += added_dids

    def test_upload_download_file_using_impl(self):
        """CLIENT(USER): rucio upload/download file"""
        tmp_file1 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        impl = 'xrootd'

        # Uploading file
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(self.rse, self.scope, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        self.assertEqual(exitcode, 0)

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(self.scope, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(self.scope, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # Downloading the file
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(self.scope, tmp_file1_name, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The file should be there
        cmd = 'find /tmp/{0}/{1}'.format(self.scope, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        self.assertEqual(exitcode, 0)

        # cleaning
        remove('/tmp/{0}/'.format(self.scope) + tmp_file1[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1)]
        self.generated_dids += added_dids

    def test_upload_download_datasets_using_impl(self):
        """CLIENT(USER): rucio upload files to dataset/download dataset"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        impl = 'xrootd'

        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3} {4} {5} {1}:{6}'.format(self.rse, self.scope, impl, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        self.assertEqual(exitcode, 0)

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # Downloading dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(self.scope, tmp_dsn, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The files should be there
        cmd = 'ls /tmp/{0}/rucio_testfile_*'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        self.assertEqual(exitcode, 0)

        # cleaning
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file1[5:])
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file2[5:])
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file3[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1, tmp_file2, tmp_file3, tmp_dsn)]
        self.generated_dids += added_dids

    def test_repeat_upload_file_using_impl(self):
        """CLIENT(USER): rucio re-upload file after deleting physical file"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        impl = 'xrootd'

        # Upload the file
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(self.rse, self.scope, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # get the rule for the file
        cmd = r"rucio list-rules {0}:{1} | grep {0}:{1} | cut -f1 -d\ ".format(self.scope, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        rule = out
        # delete the file from the catalog
        cmd = "rucio delete-rule {0}".format(rule)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # delete the physical file
        cmd = "find /tmp/rucio_rse/ -name {0} |xargs rm".format(tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # upload the files to the dataset
        cmd = 'rucio -v upload --rse {0} --scope {1} --impl {2} {3} {4} {5}'.format(self.rse, self.scope, impl, tmp_file1, tmp_file2, tmp_file3)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        self.assertEqual(exitcode, 0)
        outputs = [out, err]
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        upload_string_1 = ('Successfully uploaded file %s' % tmp_file1_name)
        self.assertIn(upload_string_1, outputs) 

        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1, tmp_file2, tmp_file3)]
        self.generated_dids += added_dids

    def test_repeat_upload_download_file_using_impl(self):
        """CLIENT(USER): rucio upload/download file already existing on RSE"""
        tmp_file1 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        impl = 'xrootd'

        # Upload the file
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(self.rse, self.scope, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # List the file
        cmd = 'rucio list-files {0}:{1}'.format(self.scope, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(self.scope, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # Re-Upload the file
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3}'.format(self.rse, self.scope, impl, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        outputs = [out, err]
        remove(tmp_file1)
        self.assertEqual(exitcode, 0)
        upload_string_1 = ('File already exists on RSE. Skipping upload')
        self.assertIn(upload_string_1, outputs)

        # Downloading the file
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(self.scope, tmp_file1_name, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The file should be there
        cmd = 'find /tmp/{0}/{1}'.format(self.scope, tmp_file1_name)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        self.assertEqual(exitcode, 0)

        # Re-download file
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(self.scope, tmp_file1_name, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)
        self.assertIsNotNone(re.search(r'Downloaded files:\s+0', out))
        self.assertIsNotNone(re.search(r'Files already found locally:\s+1', out))

        # cleaning
        remove('/tmp/{0}/'.format(self.scope) + tmp_file1[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1)]
        self.generated_dids += added_dids

    def test_repeat_upload_download_dataset_using_impl(self):
        """CLIENT(USER): rucio upload files to dataset/download dataset"""
        tmp_file1 = file_generator()
        tmp_file2 = file_generator()
        tmp_file3 = file_generator()
        tmp_file1_name = path.basename(tmp_file1)
        tmp_file3_name = path.basename(tmp_file3)
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        impl = 'xrootd'

        # Adding files to a new dataset
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(self.rse, self.scope, impl, tmp_file1, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # upload the files to the dataset
        cmd = 'rucio -v upload --rse {0} --scope {1} --impl {2} {3} {4} {5} {1}:{6}'.format(self.rse, self.scope, impl, tmp_file1, tmp_file2, tmp_file3, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        remove(tmp_file1)
        remove(tmp_file2)
        remove(tmp_file3)
        self.assertEqual(exitcode, 0)

        # List the files
        cmd = 'rucio list-files {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)
        self.assertIsNotNone(re.search("{0}:{1}".format(self.scope, tmp_file1_name), out))
        self.assertIsNotNone(re.search("{0}:{1}".format(self.scope, tmp_file3_name), out))

        # List the replicas
        cmd = 'rucio list-file-replicas {0}:{1}'.format(self.scope, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)

        # Downloading dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(self.scope, tmp_dsn, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        # The files should be there
        cmd = 'ls /tmp/{0}/rucio_testfile_*'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(err, out)
        self.assertEqual(exitcode, 0)

        # Re-download dataset
        cmd = 'rucio download --dir /tmp/ {0}:{1} --impl {2}'.format(self.scope, tmp_dsn, impl)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        self.assertEqual(exitcode, 0)
        self.assertIsNotNone(re.search(r'Downloaded files:\s+0', out))
        self.assertIsNotNone(re.search(r'Files already found locally:\s+3', out))

        # cleaning
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file1[5:])
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file2[5:])
        remove('/tmp/{0}/'.format(tmp_dsn) + tmp_file3[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1, tmp_file2, tmp_file3, tmp_dsn)]
        self.generated_dids += added_dids

    def test_upload_file_guid_with_impl(self):
        """CLIENT(USER): Rucio upload file with guid"""
        tmp_file1 = file_generator()
        tmp_guid = uuid()
        impl = 'xrootd'
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(self.rse, self.scope, impl, tmp_guid, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        outputs = [out, err]
        remove(tmp_file1)
        self.assertEqual(exitcode, 0)
        upload_string_1 = ('Successfully uploaded file %s' % path.basename(tmp_file1))
        self.assertIn(upload_string_1, outputs)

        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1)]
        self.generated_dids += added_dids

    def test_download_filter_using_impl(self):
        """CLIENT(USER): rucio download with filter options"""

        impl = 'xrootd'
        # Use filter option to download file with wildcarded name
        tmp_file1 = file_generator()
        tmp_guid = uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(self.rse, self.scope, impl, tmp_guid, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        self.assertEqual(exitcode, 0)
        wrong_guid = uuid()
        cmd = 'rucio -v download --dir /tmp {0}:{1} --impl {2} --filter guid={3}'.format(self.scope, '*', impl, wrong_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertEqual(exitcode, 0)
        cmd = 'ls /tmp/{0}'.format(self.scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertIsNone(re.search(tmp_file1[5:], out))
        cmd = 'rucio -v download --dir /tmp {0}:{1} --impl {2} --filter guid={3}'.format(self.scope, '*', impl, tmp_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertEqual(exitcode, 0)
        cmd = 'ls /tmp/{0}'.format(self.scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertIsNotNone(re.search(tmp_file1[5:], out))
        # cleaning
        remove('/tmp/{0}/'.format(self.scope) + tmp_file1[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1)]
        self.generated_dids += added_dids

        # Only use filter option to download file
        tmp_file1 = file_generator()
        tmp_guid = uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} --guid {3} {4}'.format(self.rse, self.scope, impl, tmp_guid, tmp_file1)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        self.assertEqual(exitcode, 0)
        wrong_guid = uuid()
        cmd = 'rucio -v download --dir /tmp --scope {0} --impl {1} --filter guid={2}'.format(self.scope, impl, wrong_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertEqual(exitcode, 0)
        cmd = 'ls /tmp/{0}'.format(self.scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertIsNone(re.search(tmp_file1[5:], out))
        cmd = 'rucio -v download --dir /tmp --scope {0} --impl {1} --filter guid={2}'.format(self.scope, impl, tmp_guid)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertEqual(exitcode, 0)
        cmd = 'ls /tmp/{0}'.format(self.scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertIsNotNone(re.search(tmp_file1[5:], out))
        # cleaning
        remove('/tmp/{0}/'.format(self.scope) + tmp_file1[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1)]
        self.generated_dids += added_dids

        # Use filter option to download dataset with wildcarded name
        tmp_file1 = file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(self.rse, self.scope, impl, tmp_file1, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        self.assertEqual(exitcode, 0)
        cmd = 'rucio download --dir /tmp --scope {0} --filter created_before=1900-01-01T00:00:00.000Z'.format(self.scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertIsNone(re.search(tmp_file1[5:], out))
        cmd = 'rucio download --dir /tmp --scope {0} --filter created_after=1900-01-01T00:00:00.000Z'.format(self.scope)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        # self.assertIsNotNone(re.search(tmp_file1[5:], out))
        # cleaning
        # remove('/tmp/{0}/'.format(self.scope) + tmp_file1[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1)]
        self.generated_dids += added_dids

        # Use filter option to download dataset with wildcarded name
        tmp_file1 = file_generator()
        tmp_dsn = 'tests.rucio_client_test_server_impl_check' + uuid()
        cmd = 'rucio upload --rse {0} --scope {1} --impl {2} {3} {1}:{4}'.format(self.rse, self.scope, impl, tmp_file1, tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out)
        print(err)
        remove(tmp_file1)
        self.assertEqual(exitcode, 0)
        cmd = 'rucio download --dir /tmp {0}:{1} --filter created_before=1900-01-01T00:00:00.000Z'.format(self.scope, tmp_dsn[0:-1] + '*')
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertIsNone(re.search(tmp_file1[5:], out))
        cmd = 'rucio download --dir /tmp {0}:{1} --filter created_after=1900-01-01T00:00:00.000Z'.format(self.scope, tmp_dsn[0:-1] + '*')
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        cmd = 'ls /tmp/{0}'.format(tmp_dsn)
        print(self.marker + cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        self.assertIsNotNone(re.search(tmp_file1[5:], out))
        # cleaning
        remove('/tmp/{0}/'.format(self.scope) + tmp_file1[5:])
        added_dids = ['{0}:{1}'.format(self.scope, did) for did in (tmp_file1)]
        self.generated_dids += added_dids
