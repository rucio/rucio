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
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import unittest

import pytest

from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import get_usage
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_did, attach_dids, detach_dids
from rucio.core.lock import get_replica_locks, get_dataset_locks
from rucio.core.rse import add_rse_attribute, get_rse_id
from rucio.core.rule import add_rule, get_rule
from rucio.daemons.abacus.account import account_update
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.db.sqla.constants import DIDType
from rucio.tests.test_rule import create_files, tag_generator


@pytest.mark.noparallel(reason='sets account limits, adds global rse attributes')
class TestJudgeEvaluator(unittest.TestCase):

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

    def test_judge_add_files_to_dataset(self):
        """ JUDGE EVALUATOR: Test the judge when adding files to dataset"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        attach_dids(scope, dataset, files, self.jdoe)
        re_evaluator(once=True)

        files = create_files(3, scope, self.rse1_id)
        attach_dids(scope, dataset, files, self.jdoe)

        # Fake judge
        re_evaluator(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)

    def test_judge_add_dataset_to_container(self):
        """ JUDGE EVALUATOR: Test the judge when adding dataset to container"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        parent_container = 'dataset_' + str(uuid())
        add_did(scope, parent_container, DIDType.CONTAINER, self.jdoe)
        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': parent_container}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)
        attach_dids(scope, parent_container, [{'scope': scope, 'name': dataset}], self.jdoe)
        # Fake judge
        re_evaluator(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)

        # Check if the DatasetLocks are created properly
        dataset_locks = [lock for lock in get_dataset_locks(scope=scope, name=dataset)]
        assert(len(dataset_locks) == 2)

    def test_account_counter_judge_evaluate_attach(self):
        """ JUDGE EVALUATOR: Test if the account counter is updated correctly when a file is added to a DS"""
        re_evaluator(once=True)
        account_update(once=True)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        account_counter_before = get_usage(self.rse1_id, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        # Fake judge
        re_evaluator(once=True)
        account_update(once=True)

        account_counter_after = get_usage(self.rse1_id, self.jdoe)
        assert(account_counter_before['bytes'] + 3 * 100 == account_counter_after['bytes'])
        assert(account_counter_before['files'] + 3 == account_counter_after['files'])

    def test_account_counter_judge_evaluate_detach(self):
        """ JUDGE EVALUATOR: Test if the account counter is updated correctly when a file is removed from a DS"""
        re_evaluator(once=True)
        account_update(once=True)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        account_update(once=True)

        account_counter_before = get_usage(self.rse1_id, self.jdoe)

        detach_dids(scope, dataset, [files[0]])

        # Fake judge
        re_evaluator(once=True)
        account_update(once=True)

        account_counter_after = get_usage(self.rse1_id, self.jdoe)
        assert(account_counter_before['bytes'] - 100 == account_counter_after['bytes'])
        assert(account_counter_before['files'] - 1 == account_counter_after['files'])

    def test_judge_evaluate_detach_datasetlock(self):
        """ JUDGE EVALUATOR: Test if the a datasetlock is detached correctly when removing a dataset from a container"""
        re_evaluator(once=True)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        container = 'container_' + str(uuid())
        add_did(scope, container, DIDType.CONTAINER, self.jdoe)
        attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)

        # Add a rule to the Container
        add_rule(dids=[{'scope': scope, 'name': container}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the datasetlock is there
        locks = [ds_lock for ds_lock in get_dataset_locks(scope=scope, name=dataset)]
        assert(len(locks) > 0)

        detach_dids(scope, container, [{'scope': scope, 'name': dataset}])

        # Fake judge
        re_evaluator(once=True)

        locks = [ds_lock for ds_lock in get_dataset_locks(scope=scope, name=dataset)]
        assert(len(locks) == 0)

    def test_judge_evaluate_detach(self):
        """ JUDGE EVALUATOR: Test if the detach is done correctly"""
        re_evaluator(once=True)

        scope = InternalScope('mock', **self.vo)
        container = 'container_' + str(uuid())
        add_did(scope, container, DIDType.CONTAINER, self.jdoe)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)
        attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)
        attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)
        attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)

        # Add a first rule to the Container
        rule_id = add_rule(dids=[{'scope': scope, 'name': container}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        # Fake judge
        re_evaluator(once=True)

        assert(9 == get_rule(rule_id)['locks_ok_cnt'])

        detach_dids(scope, dataset, [files[0]])

        # Fake judge
        re_evaluator(once=True)

        assert(8 == get_rule(rule_id)['locks_ok_cnt'])

    def test_judge_add_files_to_dataset_with_2_rules(self):
        """ JUDGE EVALUATOR: Test the judge when adding files to dataset with 2 rules"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse5, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.root, copies=1, rse_expression=self.rse5, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        attach_dids(scope, dataset, files, self.jdoe)
        re_evaluator(once=True)

        files = create_files(3, scope, self.rse1_id)
        attach_dids(scope, dataset, files, self.jdoe)

        # Fake judge
        re_evaluator(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)

    def test_judge_add_files_to_dataset_rule_on_container(self):
        """ JUDGE EVALUATOR: Test the judge when attaching file to dataset with rule on two levels of containers"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        parent_container = 'dataset_' + str(uuid())
        add_did(scope, parent_container, DIDType.CONTAINER, self.jdoe)
        attach_dids(scope, parent_container, [{'scope': scope, 'name': dataset}], self.jdoe)

        parent_parent_container = 'dataset_' + str(uuid())
        add_did(scope, parent_parent_container, DIDType.CONTAINER, self.jdoe)
        attach_dids(scope, parent_parent_container, [{'scope': scope, 'name': parent_container}], self.jdoe)

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': parent_parent_container}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Fake judge
        re_evaluator(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)

        # create more files and attach them
        more_files = create_files(3, scope, self.rse1_id)
        attach_dids(scope, dataset, more_files, self.jdoe)
        re_evaluator(once=True)
        # Check if the Locks are created properly
        for file in more_files:
            assert(len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)
