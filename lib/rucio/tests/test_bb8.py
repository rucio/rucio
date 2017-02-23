# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2016

from datetime import datetime

from nose.tools import assert_raises

from rucio.common.utils import generate_uuid as uuid
from rucio.core.account_limit import set_account_limit
from rucio.core.did import add_did, attach_dids
from rucio.core.rse import add_rse_attribute, get_rse
from rucio.core.rule import add_rule, get_rule, delete_rule
from rucio.core.lock import successful_transfer
from rucio.daemons.judge.cleaner import rule_cleaner
from rucio.daemons.bb8.common import rebalance_rule
from rucio.db.sqla.constants import DIDType, RuleState
from rucio.tests.test_rule import create_files, tag_generator
from rucio.common.exception import RuleNotFound, UnsupportedOperation


class TestJudgeCleaner():

    @classmethod
    def setUpClass(cls):
        # Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse3 = 'MOCK3'
        cls.rse4 = 'MOCK4'
        cls.rse5 = 'MOCK5'

        cls.rse1_id = get_rse(cls.rse1).id
        cls.rse3_id = get_rse(cls.rse3).id
        cls.rse4_id = get_rse(cls.rse4).id
        cls.rse5_id = get_rse(cls.rse5).id

        # Add Tags
        cls.T1 = tag_generator()
        cls.T2 = tag_generator()
        add_rse_attribute(cls.rse1, cls.T1, True)
        add_rse_attribute(cls.rse3, cls.T1, True)
        add_rse_attribute(cls.rse4, cls.T2, True)
        add_rse_attribute(cls.rse5, cls.T1, True)

        # Add fake weights
        add_rse_attribute(cls.rse1, "fakeweight", 10)
        add_rse_attribute(cls.rse3, "fakeweight", 0)
        add_rse_attribute(cls.rse4, "fakeweight", 0)
        add_rse_attribute(cls.rse5, "fakeweight", 0)

        # Add quota
        set_account_limit('jdoe', cls.rse1_id, -1)
        set_account_limit('jdoe', cls.rse3_id, -1)
        set_account_limit('jdoe', cls.rse4_id, -1)
        set_account_limit('jdoe', cls.rse5_id, -1)

        set_account_limit('root', cls.rse1_id, -1)
        set_account_limit('root', cls.rse3_id, -1)
        set_account_limit('root', cls.rse4_id, -1)
        set_account_limit('root', cls.rse5_id, -1)

    def test_bb8_rebalance_rule(self):
        """ BB8: Test the rebalance rule method"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        child_rule = rebalance_rule(rule_id, 'Rebalance', self.rse3, priority=3)

        rule_cleaner(once=True)

        assert(get_rule(rule_id)['expires_at'] <= datetime.utcnow())
        assert(get_rule(rule_id)['child_rule_id'] == child_rule)

        rule_cleaner(once=True)

        assert(get_rule(rule_id)['expires_at'] <= datetime.utcnow())

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=self.rse3_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=self.rse3_id, nowait=False)
        with assert_raises(UnsupportedOperation):
            delete_rule(rule_id)
        successful_transfer(scope=scope, name=files[2]['name'], rse_id=self.rse3_id, nowait=False)

        rule_cleaner(once=True)
        assert_raises(RuleNotFound, get_rule, rule_id)
        assert(get_rule(child_rule)['state'] == RuleState.OK)
