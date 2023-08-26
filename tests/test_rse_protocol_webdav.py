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

import os

import pytest
import requests

from rucio.common.exception import FileReplicaAlreadyExists
from rucio.rse import rsemanager
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from .rsemgr_api_test import MgrTestCases


@skip_rse_tests_with_accounts
class TestRseWebDAV(MgrTestCases):
    """
    Test the WebDAV protocol
    """

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, vo, tmp_path_factory):
        """WebDAV (RSE/PROTOCOLS): Creating necessary directories and files """
        session = requests.Session()
        session.cert = os.getenv('X509_USER_PROXY')
        session.verify = False
        rse_name = 'FZK-LCG2_SCRATCHDISK'
        rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)
        user = 'jdoe'
        data = load_test_conf_file('rse_repository.json')
        scheme = data[rse_name]['protocols']['supported']['https']['scheme']
        prefix = data[rse_name]['protocols']['supported']['https']['prefix']
        hostname = data[rse_name]['protocols']['supported']['https']['hostname']
        port = data[rse_name]['protocols']['supported']['https']['port']

        storage = rsemanager.create_protocol(rse_settings, operation='write', scheme='https')
        storage.connect()
        for f in MgrTestCases.files_remote:
            os.symlink('%s/data.raw' % tmpdir, '%s/%s' % (tmpdir, f))
            destfile = rsemanager.lfns2pfns(rse_settings, [{'name': f, 'scope': 'user.%s' % (user)}, ], operation='write', scheme='https').values()[0]
            try:
                storage.put('%s/%s' % (tmpdir, f), destfile)
            except FileReplicaAlreadyExists as e:
                print(e)

        yield rse_settings, tmpdir, user

        storage = rsemanager.create_protocol(rse_settings, operation='write', scheme='https')
        print(rse_settings)
        storage.connect()
        status1 = storage.delete('%s://%s:%s%suser/%s' % (scheme, hostname, port, prefix, user))
        print(status1)
        status2 = storage.delete('%s://%s:%s%sgroup/%s' % (scheme, hostname, port, prefix, user))
        print(status2)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo)
