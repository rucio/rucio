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
import shutil
import tempfile
import unittest
from uuid import uuid4 as uuid
from uuid import UUID

from typing import Tuple

import pytest  # type: ignore

from rucio.rse import rsemanager
from rucio.common.utils import execute
from rucio.tests.common import skip_rse_tests_with_accounts, load_test_conf_file
from rucio.tests.rsemgr_api_test import MgrTestCases


@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
@skip_rse_tests_with_accounts
class TestRseGFAL2(unittest.TestCase):
    tmpdir: str
    static_file: str
    prefix: str
    hostname: str
    web_service_path: str
    port: int
    user: UUID
    impl = 'gfal'
    rse_id = 'FZK-LCG2_SCRATCHDISK'

    @classmethod
    def setUpClass(cls) -> None:
        """
        GFAL2 (RSE/PROTOCOLS): Creating necessary directories and files
        """

        # Getting info for the test environment
        (cls.prefix, cls.hostname, cls.web_service_path,
            cls.port) = cls.sample_conffile(cls.rse_id)

        try:
            os.mkdir(cls.prefix)
        except Exception as e:
            print(e)

        # Creating local files
        cls.tmpdir = tempfile.mkdtemp()
        cls.user = uuid()

        # TODO: this function appears in all tests, reduce repeated code
        # create empty large files for testing
        with open(f"{cls.tmpdir}/data.raw", "wb") as out:
            out.seek((1024 * 1024) - 1)  # 1 MB
            out.write(b'\0')
        for f in MgrTestCases.files_local:
            shutil.copy(f"{cls.tmpdir}/data.raw", f"{cls.tmpdir}/{f}")

        os.system(
            f'dd if=/dev/urandom of={cls.tmpdir}'
            '/data.raw bs=1024 count=1024'
        )
        if cls.port > 0:
            cls.static_file = (f'srm://{cls.hostname}:{cls.port}'
                               f'{cls.web_service_path}{cls.prefix}'
                               '/data.raw')
        else:
            cls.static_file = (f'srm://{cls.hostname}'
                               f'{cls.web_service_path}{cls.prefix}'
                               '/data.raw')
        cmd = (f'srmcp -2 --debug=false -retry_num=0 '
               f'file:///{cls.tmpdir}/data.raw {cls.static_file}')
        execute(cmd)

        rse_settings = cls.make_rse_settings(cls.rse_id)

        for f in MgrTestCases.files_remote:
            pfns = rsemanager.lfns2pfns(
                rse_settings,
                {'name': f, 'scope': f'user.{cls.user}'},
                scheme='srm'
            )
            tmp = next(iter(pfns.values()))
            cmd = (f'srmcp -2 --debug=false -retry_num=0 '
                   f'file:///{cls.tmpdir}/data.raw {tmp}')
            execute(cmd)

    @staticmethod
    def sample_conffile(rse_id: str) -> Tuple[str, str, str, int]:
        """
        GFAL2 (RSE/PROTOCOLS): Sample Config file
        :return: Tuple (prefix, hostname, web_service_path, port)
        """
        data = load_test_conf_file('rse_repository.json')
        srm_protocols = data[rse_id]['protocols']['supported']['srm']

        # prefix
        prefix = str(srm_protocols['prefix'])

        # hostname
        hostname = str(srm_protocols['hostname'])
        if '://' in hostname:
            hostname = hostname.split('://')[1]

        # web_service_path
        if_extended_attr = (
            'extended_attributes' in srm_protocols.keys()
        )
        if_web_service = (
            'web_service_path' in
            srm_protocols['extended_attributes'].keys()
        )
        if if_extended_attr and if_web_service:
            web_service_path = (
                srm_protocols['extended_attributes']['web_service_path']
            )
        else:
            web_service_path = ''

        # port
        if 'port' in srm_protocols.keys():
            port = int(srm_protocols['port'])
        else:
            port = 0

        return prefix, hostname, web_service_path, port

    @staticmethod
    def make_rse_settings(rse_id: str) -> dict:
        """
        GFAL2 (RSE/PROTOCOLS): make rse settings dict
        :return: dict
        """
        rse_settings = rsemanager.get_rse_info(rse_id)
        for protocol in rse_settings['protocols']:
            if protocol['scheme'] != "srm":
                rse_settings['protocols'].remove(protocol)
        if len(rse_settings['protocols']) > 0:
            protocolloc = 'rucio.rse.protocols.gfal.Default'
            rse_settings['protocols'][0]['impl'] = protocolloc
        return rse_settings

    @classmethod
    def tearDownClass(cls) -> None:
        """
        GFAL2 (RSE/PROTOCOLS): Removing created directories and files
        """
        # TODO: check if this line is necessary
        cls.sample_conffile(cls.rse_id)

        # clear tmpdir
        shutil.rmtree(cls.tmpdir)

        # TODO: find out what happens here
        clean_raw = f'{cls.prefix}/data.raw'
        if cls.port > 0:
            srm_path = (f"srm://{cls.hostname}:{cls.port}"
                        f"{cls.web_service_path}")
        else:
            srm_path = (f"srm://{cls.hostname}"
                        f"{cls.web_service_path}")

        # list files that need to be cleaned
        clean_files: list[str] = []
        for who in ["user", "group"]:
            list_files_cmd_user = (
                "srmls -2 --debug=false -retry_num=0 -recursion_depth=3 "
                f"{srm_path}{cls.prefix}/{who}/{cls.user}"
            )
            clean_files += str(execute(list_files_cmd_user)[1]).split('\n')

        clean_files.append(f"1024  {clean_raw}")

        # remove these files
        for files in clean_files:
            if len(files.strip()) > 0:
                file = files.split()[1]
                if not file.endswith("/"):
                    clean_cmd = ("srmrm -2 --debug=false -retry_num=0 "
                                 f"{srm_path}/{file}")
                    execute(clean_cmd)

        # remove directories
        for who in ["user", "group"]:
            clean_cmd = ("srmrmdir -2 --debug=false -retry_num=0 "
                         f"-recursive {srm_path}{cls.prefix}/{who}/{cls.user}")
            execute(clean_cmd)

    def setUp(self) -> None:
        """
        GFAL2 (RSE/PROTOCOLS): Creating Mgr-instance
        """
        self.mtc = MgrTestCases(
            TestRseGFAL2.tmpdir,
            TestRseGFAL2.rse_id,
            TestRseGFAL2.user,
            TestRseGFAL2.static_file,
            impl=TestRseGFAL2.impl
        )
        # why the next line??
        self.mtc.setup_scheme('srm')

    # Tests
    def test_simple(self):
        assert True

    # MORE TO FOLLOW
