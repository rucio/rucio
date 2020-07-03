# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Luc Goossens <luc.goossens@cern.ch>, 2020
#
# PY3K COMPATIBLE

from rucio.tests.test_rule import TestReplicationRuleCore
import rucio.core.rule


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
