# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Luc Goossens <luc.goossens@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

import pytest

import rucio.core.rule
from rucio.tests.test_rule import TestReplicationRuleCore


@pytest.mark.noparallel(reason='sets a global variable')
class TestReplicationRuleCoreNewAlgorithm(TestReplicationRuleCore):

    @classmethod
    def setUpClass(cls):
        TestReplicationRuleCore.setUpClass()
        rucio.core.rule.USE_NEW_RULE_ALGORITHM = True
        print('set rucio.core.rule.USE_NEW_RULE_ALGORITHM to True')

    @classmethod
    def tearDownClass(cls):
        rucio.core.rule.USE_NEW_RULE_ALGORITHM = False
        print('set rucio.core.rule.USE_NEW_RULE_ALGORITHM back to False')
