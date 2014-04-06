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
from rucio.core.lock import get_replica_locks
from rucio.core.rse import add_rse_attribute, get_rse
from rucio.core.rule import get_rule, add_rule
from rucio.daemons.judge.repairer import rule_repairer
from rucio.db import models
from rucio.db.constants import DIDType, RuleState, LockState  # , RuleGrouping
from rucio.db.session import get_session
from rucio.tests.test_rule import create_files, tag_generator


class TestJudgeRepairer():

    @classmethod
    def setUpClass(cls):
        #Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse3 = 'MOCK3'
        cls.rse4 = 'MOCK4'
        cls.rse5 = 'MOCK5'

        cls.rse1_id = get_rse(cls.rse1).id
        cls.rse3_id = get_rse(cls.rse3).id
        cls.rse4_id = get_rse(cls.rse4).id
        cls.rse5_id = get_rse(cls.rse5).id

        #Add Tags
        cls.T1 = tag_generator()
        cls.T2 = tag_generator()
        add_rse_attribute(cls.rse1, cls.T1, True)
        add_rse_attribute(cls.rse3, cls.T1, True)
        add_rse_attribute(cls.rse4, cls.T2, True)
        add_rse_attribute(cls.rse5, cls.T1, True)

        #Add fake weights
        add_rse_attribute(cls.rse1, "fakeweight", 10)
        add_rse_attribute(cls.rse3, "fakeweight", 0)
        add_rse_attribute(cls.rse4, "fakeweight", 0)
        add_rse_attribute(cls.rse5, "fakeweight", 0)

    # def test_stuck_rule(self):
    #     """ JUDGE REPAIRER: Test to repair a STUCK replication rule"""
    #     scope = 'mock'
    #     files = create_files(3, scope, self.rse1)
    #     dataset = 'dataset_' + str(uuid())
    #     add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
    #     attach_dids(scope, dataset, files, 'jdoe')

    #     session = get_session()
    #     new_rule = models.ReplicationRule(account='jdoe', name=dataset, scope=scope, copies=1, rse_expression=self.rse1, locked=False, grouping=RuleGrouping.DATASET, expires_at=None, weight=None, subscription_id=None, state=RuleState.STUCK)
    #     new_rule.save(session=session)
    #     session.commit()

    #     rule_repairer(once=True)

    #     assert(get_rule(rule_id=new_rule.id)['state'] == 'OK')

    #     for file in files:
    #         rse_locks = get_replica_locks(scope=file['scope'], name=file['name'], lockmode=None)
    #         assert(len(rse_locks) == 1)

    def DISABLED_stuck_rule_failed_transfer(self):
        """ JUDGE REPAIRER: Test to repair a STUCK replication rule because of a failed transfer"""
        scope = 'mock'
        files = create_files(3, scope, self.rse4)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Fake DB entries to make the RULE STUCK
        session = get_session()
        # Mark one Lock as STUCK
        session.query(models.ReplicaLock).filter(models.ReplicaLock.scope == files[0]['scope'],
                                                 models.ReplicaLock.name == files[0]['name'],
                                                 models.ReplicaLock.rse_id != self.rse4_id).one().state = LockState.STUCK
        # Mark the Rule as STUCK
        rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.id == rule_id[0]).one()

        rule.state = RuleState.STUCK
        rule.locks_replicating_cnt = 2
        rule.locks_stuck_cnt = 1

        session.commit()

        #print get_rule(rule_id=rule_id[0])

        # Run repair statement
        rule_repairer(once=True)
        assert(get_rule(rule_id=rule_id[0])['state'] == 'OK')

        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'], lockmode=None)
            assert(len(rse_locks) == 1)
