# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014

from rucio.common.utils import generate_uuid as uuid
from rucio.core.did import add_did, attach_dids
from rucio.core.lock import successful_transfer, failed_transfer, get_replica_locks
from rucio.core.rse import add_rse_attribute, get_rse
from rucio.core.rule import get_rule, add_rule
from rucio.daemons.judge.repairer import rule_repairer
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.db.constants import DIDType, RuleState
from rucio.db.session import get_session
from rucio.db import models
from rucio.tests.test_rule import create_files, tag_generator


class TestJudgeRepairer():

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

    def test_to_repair_a_rule_with_NONE_grouping_whose_transfer_failed(self):
        """ JUDGE REPAIRER: Test to repair a rule with 1 failed transfer (lock)"""

        rule_repairer(once=True)  # Clean out the repairer
        scope = 'mock'
        files = create_files(3, scope, self.rse4, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=get_replica_locks(scope=files[0]['scope'], name=files[2]['name'])[0].rse_id)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=get_replica_locks(scope=files[1]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[2]['name'], rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)

        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)
        assert(RuleState.REPLICATING == get_rule(rule_id)['state'])

    def test_to_repair_a_rule_with_ALL_grouping_whose_transfer_failed(self):
        """ JUDGE REPAIRER: Test to repair a rule with 1 failed transfer (lock)"""

        rule_repairer(once=True)  # Clean out the repairer
        scope = 'mock'
        files = create_files(4, scope, self.rse4, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.T1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=get_replica_locks(scope=files[0]['scope'], name=files[2]['name'])[0].rse_id)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=get_replica_locks(scope=files[1]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[2]['name'], rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[3]['name'], rse_id=get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)
        assert(RuleState.REPLICATING == get_rule(rule_id)['state'])
        assert(get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id == get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

    def test_to_repair_a_rule_with_DATASET_grouping_whose_transfer_failed(self):
        """ JUDGE REPAIRER: Test to repair a rule with 1 failed transfer (lock)"""

        rule_repairer(once=True)  # Clean out the repairer
        scope = 'mock'
        files = create_files(4, scope, self.rse4, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=get_replica_locks(scope=files[0]['scope'], name=files[2]['name'])[0].rse_id)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=get_replica_locks(scope=files[1]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[2]['name'], rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[3]['name'], rse_id=get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)
        assert(RuleState.REPLICATING == get_rule(rule_id)['state'])
        assert(get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id == get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

    def test_repair_a_rule_with_missing_locks(self):
        """ JUDGE EVALUATOR: Test the judge when a rule gets STUCK from re_evaluating and there are missing locks"""
        scope = 'mock'
        files = create_files(3, scope, self.rse4)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')

        # Add a first rule to the DS
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        attach_dids(scope, dataset, files, 'jdoe')

        # Fake judge
        re_evaluator(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)

        # Add more files to the DID
        files2 = create_files(3, scope, self.rse4)
        attach_dids(scope, dataset, files2, 'jdoe')

        # Mark the rule STUCK to fake that the re-evaluation failed
        session = get_session()
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()
        rule.state = RuleState.STUCK
        session.commit()

        rule_repairer(once=True)

        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)
        for file in files2:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)
            assert(len(set([lock.rse_id for lock in get_replica_locks(scope=files[0]['scope'], name=files[0]['name'])]).intersection(set([lock.rse_id for lock in get_replica_locks(scope=file['scope'], name=file['name'])]))) == 2)
        assert(12 == get_rule(rule_id)['locks_replicating_cnt'])
