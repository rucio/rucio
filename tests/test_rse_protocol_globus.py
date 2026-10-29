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
from random import choice
from string import ascii_uppercase

import pytest

from rucio.common.constants import RseAttr
from rucio.core import rse as rse_core
from rucio.tests.common import skip_rse_tests_with_accounts
from rucio.transfertool import globus_library

from .rsemgr_api_test import MgrTestCases


class RespObj:
    def __init__(self, code, text) -> None:
        self.http_status = code
        self.text = text


class MockTransferClient:
    def __init__(self) -> None:
        self.files = MgrTestCases.files_remote + MgrTestCases.files_local_and_remote  # + MgrTestCases.files_local

    def operation_ls(self, endpoint_id, path="", filter={}):

        name = filter['name']

        if name.endswith("raw"):
            return {"DATA": [os.path.basename(f) for f in self.files if name in f]}
        else:
            return {"DATA": [os.path.basename(f) for f in self.files]}

    def get_endpoint(self, endpoint_id):
        return RespObj(code=200, text='OK')

    def operation_rename(self, collection_id, path, new_path):
        self.files.remove(os.path.basename(path))
        self.files.append(os.path.basename(new_path))
        return RespObj(code=200, text='OK')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class MockGlobusTools:
    def __init__(self) -> None:
        self.tc = MockTransferClient()

    def transfer_client(self):
        return self.tc

    def build_delete_data(self, delete_items, endpoint_id):
        if not isinstance(delete_items, list):
            delete_items = [delete_items]
        return delete_items

    def submit_deletion(self, deletion_data):
        delete_all = False
        for data in deletion_data:
            if not data.endswith("raw"):
                delete_all = True
            else:
                self.tc.files.remove(os.path.basename(data))
        if delete_all:
            self.tc.files = []
        return {'code': "Accepted", "text": "Accepted"}


@skip_rse_tests_with_accounts
class TestRseGlobus(MgrTestCases):
    """
    Test the globus protocol
    """
    @classmethod
    def create_mock_rse(cls, vo):
        rse_name = "GLOBUS-" + "".join(choice(ascii_uppercase) for _ in range(6))
        rse_id = rse_core.add_rse(rse_name, vo=vo)
        protocol_parameters = {
            'scheme': "http",
            'hostname': '%s.cern.ch' % rse_id,
            'port': 0,
            'prefix': f"/test_{rse_id}/",
            'impl': "rucio.rse.protocols.globus.Default",
            'domains': {
                'wan': {
                    'read': 0,
                    'write': 0,
                    'delete': 0,
                    'third_party_copy_read': 0,
                    'third_party_copy_write': 0,
                },
                'lan': {
                    'read': 0,
                    'write': 0,
                    'delete': 0,
                }
            }
        }
        rse_core.add_protocol(rse_id=rse_id, parameter=protocol_parameters)
        rse_core.add_rse_attribute(rse_id, key=RseAttr.GLOBUS_ENDPOINT_ID, value='a')
        rse_core.add_rse_attribute(rse_id, key=RseAttr.GLOBUS_COLLECTION_ID, value='a')

        return rse_name, rse_id

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, tmp_path_factory, vo):

        rse_name, rse_id = cls.create_mock_rse(vo)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(globus_library, "GlobusTools", MockGlobusTools)
            rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)

            yield rse_settings, tmpdir, user

        rse_core.del_rse(rse_id)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo, impl='globus')

    # All of the put, get tests are invalid. Cannot do that through the protocol
    def test_put_mgr_ok_multi(self):
        pass

    def test_put_mgr_ok_single(self):
        pass

    def test_put_mgr_source_not_found_multi(self):
        pass

    def test_put_mgr_source_not_found_single(self):
        pass

    def test_put_mgr_file_replica_already_exists_multi(self):
        pass

    def test_put_mgr_file_replica_already_exists_single(self):
        pass

    def test_download_protocol_ok_single_pfn(self):
        pass

    def test_download_protocol_ok_single_pfn_timeout(self):
        pass

    # Scope change tests are skipped because of fixture limitations
    def test_change_scope_mgr_ok_single_lfn(self):
        pass

    def test_change_scope_mgr_ok_single_pfn(self):
        pass
