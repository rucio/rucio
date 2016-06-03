# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015-2016

from nose.tools import assert_raises

from rucio.common.exception import RuleNotFound
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account_limit import set_account_limit
from rucio.core.did import add_did, attach_dids
from rucio.core.lock import get_replica_locks
from rucio.core.rse import add_rse_attribute, get_rse
from rucio.core.rule import add_rule, get_rule, approve_rule, deny_rule, list_rules
from rucio.daemons.judge.injector import rule_injector
from rucio.db.sqla.constants import DIDType, RuleState
from rucio.tests.test_rule import create_files, tag_generator


class TestJudgeEvaluator():

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

    def test_judge_inject_rule(self):
        """ JUDGE INJECTOR: Test the judge when injecting a rule"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        # Add a first rule to the DS
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, asynchronous=True)[0]

        assert(get_rule(rule_id)['state'] == RuleState.INJECT)

        rule_injector(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)
        assert(get_rule(rule_id)['state'] == RuleState.REPLICATING)

    def test_judge_ask_approval(self):
        """ JUDGE INJECTOR: Test the judge when asking approval for a rule"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        # Add a first rule to the DS
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]

        assert(get_rule(rule_id)['state'] == RuleState.WAITING_APPROVAL)

        approve_rule(rule_id=rule_id)

        assert(get_rule(rule_id)['state'] == RuleState.INJECT)

        rule_injector(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)
        assert(get_rule(rule_id)['state'] == RuleState.REPLICATING)

    def test_judge_deny_rule(self):
        """ JUDGE INJECTOR: Test the judge when asking approval for a rule and denying it"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        # Add a first rule to the DS
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]

        assert(get_rule(rule_id)['state'] == RuleState.WAITING_APPROVAL)

        deny_rule(rule_id=rule_id)

        assert_raises(RuleNotFound, get_rule, rule_id)

    def test_add_rule_with_r2d2_container_treating(self):
        """ REPLICATION RULE (CORE): Add a replication rule with an r2d2 container treatment"""
        scope = 'mock'
        container = 'asdf.r2d2_request.2016-04-01-15-00-00.ads.' + str(uuid())
        add_did(scope, container, DIDType.from_sym('CONTAINER'), 'jdoe')
        datasets = []
        for i in xrange(3):
            files = create_files(3, scope, self.rse1)
            dataset = 'dataset_' + str(uuid())
            datasets.append(dataset)
            add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
            attach_dids(scope, dataset, files, 'jdoe')
            attach_dids(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')
        rule_id = add_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=100, locked=False, subscription_id=None, ask_approval=True)[0]
        approve_rule(rule_id)
        assert(get_rule(rule_id)['state'] == RuleState.INJECT)
        rule_injector(once=True)
        # Check if there is a rule for each file
        with assert_raises(RuleNotFound):
            get_rule(rule_id)
        for dataset in datasets:
            assert(len([r for r in list_rules({'scope': scope, 'name': dataset})]) > 0)
