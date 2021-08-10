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
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2021
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2020
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

import unittest
from hashlib import sha256

import pytest
from dogpile.cache import make_region

from rucio.common.config import config_get
from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_did, attach_dids
from rucio.core.lock import successful_transfer, failed_transfer, get_replica_locks
from rucio.core.replica import get_replica
from rucio.core.request import cancel_request_did
from rucio.core.rse import add_rse_attribute, add_rse, update_rse, get_rse_id
from rucio.core.rule import get_rule, add_rule
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.daemons.judge.repairer import rule_repairer
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, RuleState, ReplicaState
from rucio.db.sqla.session import get_session
from rucio.tests.common import rse_name_generator
from rucio.tests.common_server import get_vo
from rucio.tests.test_rule import create_files, tag_generator


@pytest.mark.dirty
@pytest.mark.noparallel(reason='uses pre-defined rses, sets rse attributes, sets account limits')
class TestJudgeRepairer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
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

    def test_to_repair_a_rule_with_NONE_grouping_whose_transfer_failed(self):
        """ JUDGE REPAIRER: Test to repair a rule with 1 failed transfer (lock)"""

        rule_repairer(once=True)  # Clean out the repairer
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse4_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        failed_rse_id = get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id
        assert(get_replica(scope=files[2]['scope'], name=files[2]['name'], rse_id=failed_rse_id)['state'] == ReplicaState.COPYING)
        assert(get_replica(scope=files[2]['scope'], name=files[2]['name'], rse_id=failed_rse_id)['lock_cnt'] == 1)

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=get_replica_locks(scope=files[0]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=get_replica_locks(scope=files[1]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        failed_transfer(scope=scope, name=files[2]['name'], rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)

        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)
        assert(RuleState.REPLICATING == get_rule(rule_id)['state'])
        assert(get_replica(scope=files[2]['scope'], name=files[2]['name'], rse_id=failed_rse_id)['state'] == ReplicaState.UNAVAILABLE)
        assert(get_replica(scope=files[2]['scope'], name=files[2]['name'], rse_id=failed_rse_id)['lock_cnt'] == 0)

    def test_to_repair_a_rule_with_ALL_grouping_whose_transfer_failed(self):
        """ JUDGE REPAIRER: Test to repair a rule with 1 failed transfer (lock)"""

        rule_repairer(once=True)  # Clean out the repairer
        scope = InternalScope('mock', **self.vo)
        files = create_files(4, scope, self.rse4_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.T1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None, activity='DebugJudge')[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=get_replica_locks(scope=files[0]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=get_replica_locks(scope=files[1]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        failed_transfer(scope=scope, name=files[2]['name'], rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[3]['name'], rse_id=get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)
        assert(RuleState.REPLICATING == get_rule(rule_id)['state'])
        assert(get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id == get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)
        assert(get_replica_locks(scope=files[1]['scope'], name=files[1]['name'])[0].rse_id == get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

    def test_to_repair_a_rule_with_DATASET_grouping_whose_transfer_failed(self):
        """ JUDGE REPAIRER: Test to repair a rule with 1 failed transfer (lock)"""

        rule_repairer(once=True)  # Clean out the repairer
        scope = InternalScope('mock', **self.vo)
        files = create_files(4, scope, self.rse4_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, activity='DebugJudge')[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=get_replica_locks(scope=files[0]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=get_replica_locks(scope=files[1]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        failed_transfer(scope=scope, name=files[2]['name'], rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[3]['name'], rse_id=get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)
        assert(RuleState.REPLICATING == get_rule(rule_id)['state'])
        assert(get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id == get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)
        assert(get_replica_locks(scope=files[1]['scope'], name=files[1]['name'])[0].rse_id == get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

    def test_repair_a_rule_with_missing_locks(self):
        """ JUDGE EVALUATOR: Test the judge when a rule gets STUCK from re_evaluating and there are missing locks"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse4_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)

        # Add a first rule to the DS
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        attach_dids(scope, dataset, files, self.jdoe)

        # Fake judge
        re_evaluator(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)

        # Add more files to the DID
        files2 = create_files(3, scope, self.rse4_id)
        attach_dids(scope, dataset, files2, self.jdoe)

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

    def test_repair_a_rule_with_source_replica_expression(self):
        """ JUDGE EVALUATOR: Test the judge when a with two rules with source_replica_expression"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse4_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        # Add a first rule to the DS
        rule_id1 = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
        rule_id2 = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse3, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, source_replica_expression=self.rse1)[0]

        assert(RuleState.REPLICATING == get_rule(rule_id1)['state'])
        assert(RuleState.STUCK == get_rule(rule_id2)['state'])

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=self.rse1_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=self.rse1_id, nowait=False)
        successful_transfer(scope=scope, name=files[2]['name'], rse_id=self.rse1_id, nowait=False)
        # Also make replicas AVAILABLE
        session = get_session()
        replica = session.query(models.RSEFileAssociation).filter_by(scope=scope, name=files[0]['name'], rse_id=self.rse1_id).one()
        replica.state = ReplicaState.AVAILABLE
        replica = session.query(models.RSEFileAssociation).filter_by(scope=scope, name=files[1]['name'], rse_id=self.rse1_id).one()
        replica.state = ReplicaState.AVAILABLE
        replica = session.query(models.RSEFileAssociation).filter_by(scope=scope, name=files[2]['name'], rse_id=self.rse1_id).one()
        replica.state = ReplicaState.AVAILABLE
        session.commit()

        rule_repairer(once=True)

        assert(RuleState.OK == get_rule(rule_id1)['state'])
        assert(RuleState.REPLICATING == get_rule(rule_id2)['state'])

    def test_to_repair_a_rule_with_only_1_rse_whose_transfers_failed(self):
        """ JUDGE REPAIRER: Test to repair a rule with only 1 rse whose transfers failed (lock)"""

        rule_repairer(once=True)  # Clean out the repairer
        scope = InternalScope('mock', **self.vo)
        files = create_files(4, scope, self.rse4_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=get_replica_locks(scope=files[0]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=get_replica_locks(scope=files[1]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        failed_transfer(scope=scope, name=files[2]['name'], rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[3]['name'], rse_id=get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)
        cancel_request_did(scope=scope, name=files[2]['name'], dest_rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)
        cancel_request_did(scope=scope, name=files[3]['name'], dest_rse_id=get_replica_locks(scope=files[3]['scope'], name=files[2]['name'])[0].rse_id)

        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)

        # Stil assert STUCK because of delays:
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        assert(get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id == get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)
        # assert(RuleState.REPLICATING == get_rule(rule_id)['state'])
        # assert(get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id == get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

    def test_to_repair_a_rule_with_NONE_grouping_whose_transfer_failed_and_flipping_to_other_rse(self):
        """ JUDGE REPAIRER: Test to repair a rule with 1 failed transfer and flip to other rse(lock)"""

        rule_repairer(once=True)  # Clean out the repairer
        scope = InternalScope('mock', **self.vo)
        files = create_files(4, scope, self.rse4_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=get_replica_locks(scope=files[0]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=get_replica_locks(scope=files[1]['scope'], name=files[2]['name'])[0].rse_id, nowait=False)
        failed_transfer(scope=scope, name=files[2]['name'], rse_id=get_replica_locks(scope=files[2]['scope'], name=files[2]['name'])[0].rse_id)
        failed_transfer(scope=scope, name=files[3]['name'], rse_id=get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id)

        old_rse_id = get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id

        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)
        assert(RuleState.REPLICATING == get_rule(rule_id)['state'])
        assert(get_replica_locks(scope=files[3]['scope'], name=files[3]['name'])[0].rse_id != old_rse_id)

    def test_to_repair_a_rule_with_only_1_rse_whose_site_is_blocklisted(self):
        """ JUDGE REPAIRER: Test to repair a rule with only 1 rse whose site is blocklisted"""

        rse = rse_name_generator()
        rse_id = add_rse(rse, **self.vo)
        update_rse(rse_id, {'availability_write': False})
        set_local_account_limit(self.jdoe, rse_id, -1)

        rule_repairer(once=True)  # Clean out the repairer
        scope = InternalScope('mock', **self.vo)
        files = create_files(4, scope, self.rse4_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ignore_availability=True, activity='DebugJudge')[0]

        assert(RuleState.STUCK == get_rule(rule_id)['state'])
        rule_repairer(once=True)

        # Stil assert STUCK because of ignore_availability:
        assert(RuleState.STUCK == get_rule(rule_id)['state'])

        region = make_region().configure('dogpile.cache.memcached',
                                         expiration_time=3600,
                                         arguments={'url': config_get('cache', 'url', False, '127.0.0.1:11211'), 'distributed_lock': True})
        region.delete(sha256(rse.encode()).hexdigest())

        update_rse(rse_id, {'availability_write': True})
        rule_repairer(once=True)
        assert(RuleState.REPLICATING == get_rule(rule_id)['state'])
