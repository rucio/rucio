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


import pytest

from rucio.common.exception import InsufficientAccountLimit, InsufficientTargetRSEs
from rucio.core.account_counter import update_account_counter, increase
from rucio.core.account_limit import set_local_account_limit, set_global_account_limit
from rucio.core.rse_selector import RSESelector


@pytest.fixture
def test_rses(rse_factory):
    rse1_name, rse1_id = rse_factory.make_mock_rse()
    rse2_name, rse2_id = rse_factory.make_mock_rse()

    rse1 = {'id': rse1_id, 'staging_area': False}
    rse2 = {'id': rse2_id, 'staging_area': False}

    return rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2


class TestRSESelectorInit:

    def test_1(self, random_account, test_rses):
        # more copies than RSEs -> error
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        rses = [rse1]
        copies = 2
        with pytest.raises(InsufficientTargetRSEs):
            RSESelector(random_account, rses, None, copies)

    def test_2(self, random_account, test_rses):
        # local quota not enough -> error
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        copies = 2
        rses = [rse1, rse2]
        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=10)
        increase(rse1_id, random_account, 10, 10)
        update_account_counter(account=random_account, rse_id=rse1_id)
        with pytest.raises(InsufficientAccountLimit):
            RSESelector(random_account, rses, None, copies)

    def test_3(self, random_account, test_rses):
        # global quota not enough -> error
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        copies = 2
        rses = [rse1, rse2]
        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=20)
        set_global_account_limit(account=random_account, rse_expression=rse1_name, bytes_=10)
        increase(rse1_id, random_account, 10, 10)
        update_account_counter(account=random_account, rse_id=rse1_id)
        with pytest.raises(InsufficientAccountLimit):
            RSESelector(random_account, rses, None, copies)

    def test_4(self, random_account, test_rses):
        # enough RSEs, local and global quota -> 2 RSEs
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        set_global_account_limit(account=random_account, rse_expression=rse1_name, bytes_=20)
        set_global_account_limit(account=random_account, rse_expression=rse2_name, bytes_=20)
        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=20)
        set_local_account_limit(account=random_account, rse_id=rse2_id, bytes_=20)
        copies = 2
        rses = [rse1, rse2]
        rse_selector = RSESelector(random_account, rses, None, copies)
        assert len(rse_selector.rses) == 2

    def test_5(self, random_account, test_rses):
        # enough RSEs and local quota, but global quota missing -> 1 RSE
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        copies = 1
        rses = [rse1, rse2]
        set_global_account_limit(account=random_account, rse_expression=rse1_name, bytes_=10)
        increase(rse1_id, random_account, 10, 10)
        update_account_counter(account=random_account, rse_id=rse1_id)
        set_local_account_limit(account=random_account, rse_id=rse2_id, bytes_=20)
        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=20)
        rse_selector = RSESelector(random_account, rses, None, copies)
        assert len(rse_selector.rses) == 1

    def test_6(self, random_account, test_rses):
        # enough RSEs and global quota, but local quota missing -> 1 RSE
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        rses = [rse1, rse2]
        copies = 1
        set_global_account_limit(account=random_account, rse_expression=rse1_name, bytes_=10)
        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=10)
        increase(rse1_id, random_account, 10, 10)
        update_account_counter(account=random_account, rse_id=rse1_id)
        set_local_account_limit(account=random_account, rse_id=rse2_id, bytes_=10)
        set_global_account_limit(account=random_account, rse_expression=rse2_name, bytes_=10)
        rse_selector = RSESelector(random_account, rses, None, copies)
        assert len(rse_selector.rses) == 1


class TestRSESelectorDynamic:

    def test_1(self, random_account, test_rses):
        # enough RSEs and global quota, but not enough local quota after change -> 1 RSE
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        set_global_account_limit(account=random_account, rse_expression=rse1_name, bytes_=20)
        set_global_account_limit(account=random_account, rse_expression=rse2_name, bytes_=20)
        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=10)
        set_local_account_limit(account=random_account, rse_id=rse2_id, bytes_=10)
        copies = 2
        rses = [rse1, rse2]
        rse_selector = RSESelector(random_account, rses, None, copies)
        assert len(rse_selector.rses) == 2
        rse_selector.select_rse(9, [rse1_id], copies=1)
        rses = rse_selector.select_rse(5, [], copies=1)
        assert len(rses) == 1
        assert rses[0][0] == rse2_id

    def test_2(self, random_account, test_rses):
        # enough RSEs and global quota, but not enough global quota after change -> 1 RSE
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        set_global_account_limit(account=random_account, rse_expression=rse1_name, bytes_=10)
        set_global_account_limit(account=random_account, rse_expression=rse2_name, bytes_=10)
        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=20)
        set_local_account_limit(account=random_account, rse_id=rse2_id, bytes_=20)
        copies = 2
        rses = [rse1, rse2]
        rse_selector = RSESelector(random_account, rses, None, copies)
        assert len(rse_selector.rses) == 2
        rse_selector.select_rse(10, [rse1_id], copies=1)
        rses = rse_selector.select_rse(5, [], copies=1)
        assert len(rses) == 1
        assert rses[0][0] == rse2_id

    def test_3(self, random_account, test_rses):
        # enough RSEs and global quota, also after after change -> 2 RSE
        rse1_name, rse1_id, rse1, rse2_name, rse2_id, rse2 = test_rses
        set_global_account_limit(account=random_account, rse_expression=rse1_name, bytes_=20)
        set_global_account_limit(account=random_account, rse_expression=rse2_name, bytes_=20)
        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=20)
        set_local_account_limit(account=random_account, rse_id=rse2_id, bytes_=20)
        copies = 2
        rses = [rse1, rse2]
        rse_selector = RSESelector(random_account, rses, None, copies)
        assert len(rse_selector.rses) == 2
        rse_selector.select_rse(10, [rse1_id], copies=1)
        rse_selector.select_rse(10, [rse2_id], copies=1)
        rses = rse_selector.select_rse(5, [], copies=2)
        assert len(rses) == 2
