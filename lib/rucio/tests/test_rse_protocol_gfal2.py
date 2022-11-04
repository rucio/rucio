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
import unittest
from uuid import uuid4 as uuid
from uuid import UUID

from typing import Tuple

import pytest  # type: ignore

from rucio.tests.common import skip_rse_tests_with_accounts

@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
# @skip_rse_tests_with_accounts
class TestRseGFAL2(unittest.TestCase):
    tmpdir: str
    user: UUID

    @classmethod
    def get_rse_info(cls) -> Tuple[str, str, str, int]:
        """
        Detects if containerized rses for gfal2 are available in the
        testing environment.
        :return: A tuple (rse, prefix, hostname, port).
        """
        raise NotImplementedError

    @classmethod
    def setUpClass(cls) -> None:
        """
        GFAL2 (RSE/PROTOCOLS): Creating necessary directories and files
        """
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls) -> None:
        """
        GFAL2 (RSE/PROTOCOLS): Removing created directories and files
        """
        raise NotImplementedError

    def setUp(self) -> None:
        """
        GFAL2 (RSE/PROTOCOLS): Creating Mgr-instance
        """
        raise NotImplementedError

    # Tests
    # Mgr-Tests: PUT
    def test_put_mgr_ok_multi(self):
        """
        GFAL2 (RSE/PROTOCOLS): Put multiple files to storage providing
        LFNs and PFNs (Success)
        """
        raise NotImplementedError
        self.mtc.test_put_mgr_ok_multi()

    # MORE TO FOLLOW
