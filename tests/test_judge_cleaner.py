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

from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_did, attach_dids
from rucio.core.lock import get_replica_locks
from rucio.core.rse import add_rse_attribute
from rucio.core.rule import add_rule, update_rule
from rucio.daemons.judge.cleaner import rule_cleaner
from rucio.db.sqla.constants import DIDType
from rucio.tests.common_server import get_vo
from .test_rule import create_files, tag_generator


@pytest.fixture(scope="class")
def setup_class(request, rse_factory_unittest):
    request.cls.setUpClass()


@pytest.mark.noparallel(reason='uses pre-defined RSE, sets account limits, adds global rse attributes')
@pytest.mark.usefixtures("setup_class")
class TestJudgeCleaner:

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        # Add test RSE
        cls.rse1, cls.rse1_id = cls.rse_factory.make_mock_rse()
        cls.rse3, cls.rse3_id = cls.rse_factory.make_mock_rse()
        cls.rse4, cls.rse4_id = cls.rse_factory.make_mock_rse()
        cls.rse5, cls.rse5_id = cls.rse_factory.make_mock_rse()

        # Add Tags
        cls.T1 = tag_generator()
        cls.T2 = tag_generator()
        add_rse_attribute(cls.rse1_id, cls.T1, True)
        add_rse_attribute(cls.rse3_id, cls.T1, True)
        add_rse_attribute(cls.rse4_id, cls.T2, True)
        add_rse_attribute(cls.rse5_id, cls.T1, True)

        # Add fake weights
        add_rse_attribute(cls.rse1_id, "fakeweight", 10)
        add_rse_attribute(cls.rse3_id, "fakeweight", 0)
        add_rse_attribute(cls.rse4_id, "fakeweight", 0)
        add_rse_attribute(cls.rse5_id, "fakeweight", 0)

        # Add quota
        cls.jdoe = InternalAccount('jdoe', **cls.vo)
        cls.root = InternalAccount('root', **cls.vo)
        set_local_account_limit(cls.jdoe, cls.rse1_id, -1)
        set_local_account_limit(cls.jdoe, cls.rse3_id, -1)
        set_local_account_limit(cls.jdoe, cls.rse4_id, -1)
        set_local_account_limit(cls.jdoe, cls.rse5_id, -1)

        set_local_account_limit(cls.root, cls.rse1_id, -1)
        set_local_account_limit(cls.root, cls.rse3_id, -1)
        set_local_account_limit(cls.root, cls.rse4_id, -1)
        set_local_account_limit(cls.root, cls.rse5_id, -1)

    def test_judge_expire_rule(self):
        """ JUDGE CLEANER: Test the judge when deleting expired rules"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=-3, locked=False, subscription_id=None)[0]
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=3, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        rule_cleaner(once=True)

        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'])
            assert (len(rse_locks) == 5)

    def test_judge_expire_rule_with_child_rule(self):
        """ JUDGE CLEANER: Test the judge when deleting expired rules with child rules"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        child_rule = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse3, grouping='NONE', weight='fakeweight', lifetime=-3, locked=False, subscription_id=None)[0]
        update_rule(rule_id, {'child_rule_id': child_rule})

        rule_cleaner(once=True)
