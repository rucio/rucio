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
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2015
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

import unittest

import pytest

from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_did, attach_dids
from rucio.core.lock import get_replica_locks
from rucio.core.rse import add_rse_attribute, get_rse_id
from rucio.core.rule import add_rule, update_rule
from rucio.daemons.judge.cleaner import rule_cleaner
from rucio.db.sqla.constants import DIDType
from rucio.tests.test_rule import create_files, tag_generator


@pytest.mark.noparallel(reason='uses pre-defined RSE, sets account limits, adds global rse attributes')
class TestJudgeCleaner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        # Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse3 = 'MOCK3'
        cls.rse4 = 'MOCK4'
        cls.rse5 = 'MOCK5'

        cls.rse1_id = get_rse_id(rse=cls.rse1, **cls.vo)
        cls.rse3_id = get_rse_id(rse=cls.rse3, **cls.vo)
        cls.rse4_id = get_rse_id(rse=cls.rse4, **cls.vo)
        cls.rse5_id = get_rse_id(rse=cls.rse5, **cls.vo)

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
            assert(len(rse_locks) == 5)

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
