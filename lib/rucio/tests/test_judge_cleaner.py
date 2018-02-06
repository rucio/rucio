# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014-2018

from rucio.common.utils import generate_uuid as uuid
from rucio.core.account_limit import set_account_limit
from rucio.core.did import add_did, attach_dids
from rucio.core.lock import get_replica_locks
from rucio.core.rse import add_rse_attribute, get_rse
from rucio.core.rule import add_rule, update_rule
from rucio.daemons.judge.cleaner import rule_cleaner
from rucio.db.sqla.constants import DIDType
from rucio.tests.test_rule import create_files, tag_generator


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

    def test_judge_expire_rule(self):
        """ JUDGE CLEANER: Test the judge when deleting expired rules"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=-3, locked=False, subscription_id=None)[0]
        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=3, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        rule_cleaner(once=True)

        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'])
            assert(len(rse_locks) == 5)

    def test_judge_expire_rule_with_child_rule(self):
        """ JUDGE CLEANER: Test the judge when deleting expired rules with child rules"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        child_rule = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse3, grouping='NONE', weight='fakeweight', lifetime=-3, locked=False, subscription_id=None)[0]
        update_rule(rule_id, {'child_rule_id': child_rule})

        rule_cleaner(once=True)
