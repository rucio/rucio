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

from rucio.common.utils import execute
from rucio.rse import rsemanager as mgr
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from .rsemgr_api_test import MgrTestCases


@skip_rse_tests_with_accounts
class TestRseGFAL2(MgrTestCases):

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, vo, tmp_path_factory):
        """GFAL2 (RSE/PROTOCOLS): Creating necessary directories and files """
        rse_name = 'FZK-LCG2_SCRATCHDISK'
        rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)

        data = load_test_conf_file('rse_repository.json')
        prefix = data[rse_name]['protocols']['supported']['srm']['prefix']
        hostname = data[rse_name]['protocols']['supported']['srm']['hostname']
        if hostname.count("://"):
            hostname = hostname.split("://")[1]
        if 'port' in data[rse_name]['protocols']['supported']['srm'].keys():
            port = int(data[rse_name]['protocols']['supported']['srm']['port'])
        else:
            port = 0
        if 'extended_attributes' in data[rse_name]['protocols']['supported']['srm'].keys() and 'web_service_path' in data[rse_name]['protocols']['supported']['srm']['extended_attributes'].keys():
            web_service_path = data[rse_name]['protocols']['supported']['srm']['extended_attributes']['web_service_path']
        else:
            web_service_path = ''

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % tmpdir)

        for protocol in rse_settings['protocols']:
            if protocol['scheme'] != "srm":
                rse_settings['protocols'].remove(protocol)
        if len(rse_settings['protocols']) > 0:
            rse_settings['protocols'][0]['impl'] = 'rucio.rse.protocols.gfal.Default'

        for f in MgrTestCases.files_remote:
            tmp = next(iter(mgr.lfns2pfns(rse_settings, {'name': f, 'scope': 'user.%s' % user}, scheme='srm').values()))
            cmd = 'srmcp -2 --debug=false -retry_num=0  file:///%s/data.raw %s' % (tmpdir, tmp)
            execute(cmd)

        yield rse_settings, tmpdir, user

        clean_raw = '%s/data.raw' % prefix
        if int(port) > 0:
            srm_path = ''.join(["srm://", hostname, ":", port, web_service_path])
        else:
            srm_path = ''.join(["srm://", hostname, web_service_path])

        list_files_cmd_user = 'srmls -2 --debug=false -retry_num=0 -recursion_depth=3 %s%s/user/%s' % (srm_path, prefix, user)
        clean_files = str(execute(list_files_cmd_user)[1]).split('\n')
        list_files_cmd_user = 'srmls -2 --debug=false -retry_num=0 -recursion_depth=3 %s%s/group/%s' % (srm_path, prefix, user)
        clean_files += str(execute(list_files_cmd_user)[1]).split('\n')
        clean_files.append("1024  " + clean_raw)
        for files in clean_files:
            if len(files.strip()) > 0:
                file = files.split()[1]
                if not file.endswith("/"):
                    clean_cmd = 'srmrm -2 --debug=false -retry_num=0 %s/%s' % (srm_path, file)
                    execute(clean_cmd)

        clean_directory = ['user', 'group']
        for directory in clean_directory:
            clean_cmd = 'srmrmdir -2 --debug=false -retry_num=0 -recursive %s%s/%s/%s' % (srm_path, prefix, directory, user)
            execute(clean_cmd)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo, impl='gfal')
        self.setup_scheme('srm')
