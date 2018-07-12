# Copyright 2016-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Wen Guan <wguan.icedew@gmail.com>, 2016
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Vincent Garonne <vgaronne@gmail.com>, 2018

from __future__ import print_function

import json
import os
import tempfile

from rucio.rse import rsemanager
from rsemgr_api_test import MgrTestCases
from rucio.common.exception import FileReplicaAlreadyExists


class TestRseS3ES():
    tmpdir = None
    user = None

    # The setupClass and tearDownClass need some fixing, but can be ignored for this patch

    @classmethod
    def setupClass(cls):
        """S3ES (RSE/PROTOCOLS): Creating necessary directories and files """
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
            except FileReplicaAlreadyExists as e:
                print(e)
        f = 'data.raw'
        destfile = rsemanager.lfns2pfns(rse_settings, [{'name': f, 'scope': 'user.%s' % (cls.user)}, ], operation='write', scheme='s3+https').values()[0]
        try:
            storage.put('%s/%s' % (cls.tmpdir, f), destfile)
        except FileReplicaAlreadyExists as e:
            print(e)

    @classmethod
    def tearDownClass(cls):
        """S3ES (RSE/PROTOCOLS): Removing created directories and files """
        rse_settings = rsemanager.get_rse_info(cls.site)
        with open('etc/rse_repository.json') as f:
            data = json.load(f)
        scheme = data[cls.site]['protocols']['supported']['s3+https']['scheme']
        prefix = data[cls.site]['protocols']['supported']['s3+https']['prefix']
        hostname = data[cls.site]['protocols']['supported']['s3+https']['hostname']
        port = data[cls.site]['protocols']['supported']['s3+https']['port']
        for protocol in rse_settings['protocols']:
            if protocol['impl'] == 'rucio.rse.protocols.signeds3.Default':
                protocol['impl'] = 'rucio.rse.protocols.s3es.Default'

        storage = rsemanager.create_protocol(rse_settings, operation='write', scheme='s3+https')
        storage.connect()
        try:
            storage.delete('%s://%s:%s/%s/%s' % (scheme, hostname, port, prefix, 'user'))
        except Exception as e:
            print(e)
        try:
            storage.delete('%s://%s:%s/%s/%s' % (scheme, hostname, port, prefix, 'group'))
        except Exception as e:
            print(e)

    def setup(self):
        """S3ES (RSE/PROTOCOLS): Creating Mgr-instance """
        self.tmpdir = TestRseS3ES.tmpdir
        self.rse_id = 'BNL-OSG2_ES'
        self.mtc = MgrTestCases(self.tmpdir, 'BNL-OSG2_ES', TestRseS3ES.user, TestRseS3ES.static_file)
        self.mtc.setup_scheme('s3+https', 's3es')

    # MGR-Tests: DELETE
    def test_delete_mgr_ok_multi(self):
        """S3ES (RSE/PROTOCOLS): Delete multiple files from storage (Success)"""
        try:
            self.mtc.test_delete_mgr_ok_multi()
        except NotImplementedError:
            pass

    def test_delete_mgr_ok_single(self):
        """S3ES (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        try:
            self.mtc.test_delete_mgr_ok_single()
        except NotImplementedError:
            pass

    def test_delete_mgr_ok_dir(self):
        """S3ES (RSE/PROTOCOLS): Delete a single file from storage (Success)"""
        try:
            self.mtc.test_delete_mgr_ok_dir()
        except NotImplementedError:
            pass
