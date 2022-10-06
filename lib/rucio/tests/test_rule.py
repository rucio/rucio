# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import json
import random
import string
from logging import getLogger

import pytest

import rucio.api.rule
from rucio.api.account import add_account
from rucio.client.ruleclient import RuleClient
from rucio.common.config import config_get_bool
from rucio.common.exception import (RucioException, RuleNotFound, AccessDenied, InsufficientAccountLimit, DuplicateRule, RSEWriteBlocked,
                                    RSEOverQuota, RuleReplaceFailed, ManualRuleApprovalBlocked, InputValidationError,
                                    UnsupportedOperation, InvalidValueForKey)
from rucio.common.policy import get_policy
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account_attribute, get_usage
from rucio.core.account_limit import set_local_account_limit, set_global_account_limit
from rucio.core.did import add_did, attach_dids, set_status
from rucio.core.lock import get_replica_locks, get_dataset_locks, successful_transfer
from rucio.core.replica import add_replica, get_replica
from rucio.core.request import get_request_by_did
from rucio.core.rse import add_rse_attribute, add_rse, update_rse, get_rse_id, del_rse_attribute, set_rse_limits
from rucio.core.rse_counter import get_counter as get_rse_counter
from rucio.core.rule import add_rule, get_rule, delete_rule, add_rules, update_rule, reduce_rule, move_rule, list_rules
from rucio.core.scope import add_scope
from rucio.daemons.abacus.account import account_update
from rucio.daemons.abacus.rse import rse_update
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, OBSOLETE, RuleState, LockState
from rucio.db.sqla.session import transactional_session
from rucio.tests.common import rse_name_generator, account_name_generator, did_name_generator
from rucio.tests.common_server import get_vo

LOG = getLogger(__name__)


def create_files(nrfiles, scope, rse_id, bytes_=1):
    """
    Creates a number of test files and add replicas to rse

    :param nrfiles:  Number of files to create
    :param scope:    Scope to create the files in
    :param rse_id:   RSE to add the replica to
    :param bytes_:    Bytes of each file
    :returns:        List of dict
    """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': get_vo()}
    else:
        vo = {}

    files = []
    jdoe = InternalAccount('jdoe', **vo)
    for i in range(nrfiles):
        file = did_name_generator('file')
        if isinstance(rse_id, list):
            for r in rse_id:
                add_replica(rse_id=r, scope=scope, name=file, bytes_=bytes_, account=jdoe)
        else:
            add_replica(rse_id=rse_id, scope=scope, name=file, bytes_=bytes_, account=jdoe)
        files.append({'scope': scope, 'name': file, 'bytes': bytes_})
    return files


def tag_generator(size=8, chars=string.ascii_uppercase):
    return ''.join(random.choice(chars) for x in range(size))


@transactional_session
def check_dataset_ok_callback(scope, name, rse, rse_id, rule_id, session=None):
    message = {'scope': scope.external,
               'name': name,
               'rse': rse,
               'rse_id': rse_id,
               'rule_id': rule_id}
    if scope.vo != 'def':
        message['vo'] = scope.vo

    callbacks = session.query(models.Message.id).filter(models.Message.payload == json.dumps(message)).all()
    if len(callbacks) > 0:
        return True
    return False


@transactional_session
def check_rule_progress_callback(scope, name, progress, rule_id, session=None):
    message = {'scope': scope.external,
               'name': name,
               'rule_id': rule_id,
               'progress': progress}
    if scope.vo != 'def':
        message['vo'] = scope.vo

    callbacks = session.query(models.Message.id).filter(models.Message.payload == json.dumps(message)).all()
    if callbacks:
        return True
    return False


@pytest.fixture
def setup_class(request, vo, root_account, jdoe_account, rse_factory):
    cls = request.cls

    # Add test RSE
    cls.rse1, cls.rse1_id = rse_factory.make_mock_rse()
    cls.rse2, cls.rse2_id = rse_factory.make_mock_rse()
    cls.rse3, cls.rse3_id = rse_factory.make_mock_rse()
    cls.rse4, cls.rse4_id = rse_factory.make_mock_rse()

    # Add Tags
    cls.T1 = tag_generator()
    cls.T2 = tag_generator()
    add_rse_attribute(cls.rse1_id, cls.T1, True)
    add_rse_attribute(cls.rse2_id, cls.T1, True)
    add_rse_attribute(cls.rse3_id, cls.T2, True)
    add_rse_attribute(cls.rse4_id, cls.T1, True)

    # Add fake weights
    add_rse_attribute(cls.rse1_id, "fakeweight", 10)
    add_rse_attribute(cls.rse2_id, "fakeweight", 0)
    add_rse_attribute(cls.rse3_id, "fakeweight", 0)
    add_rse_attribute(cls.rse4_id, "fakeweight", 0)

    set_local_account_limit(jdoe_account, cls.rse1_id, -1)
    set_local_account_limit(jdoe_account, cls.rse2_id, -1)
    set_local_account_limit(jdoe_account, cls.rse3_id, -1)
    set_local_account_limit(jdoe_account, cls.rse4_id, -1)


@pytest.mark.usefixtures('setup_class')
class TestCore:

    def test_add_rule_file_none(self, mock_scope, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a group of files, NONE Grouping"""
        files = create_files(3, mock_scope, self.rse1_id)
        add_rule(dids=files, account=jdoe_account, copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = {self.rse1_id, self.rse2_id, self.rse4_id}
        for file in files:
            rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            assert(len(t1.intersection(rse_locks)) > 0)
            assert self.rse3_id not in rse_locks

    def test_add_rule_dataset_none(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, NONE Grouping"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        # Add a first rule to the DS
        add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Add a second rule and check if the right locks are created
        add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression='%s|%s' % (self.T1, self.T2), grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = {self.rse1_id, self.rse2_id, self.rse4_id}
        for file in files:
            rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            assert(len(t1.intersection(rse_locks)) == 2)
            assert self.rse3_id not in rse_locks

    def test_add_rule_duplicate(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule duplicate"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        # Add a first rule to the DS
        add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Add a second rule and check if the right locks are created
        pytest.raises(DuplicateRule, add_rule, dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

    def test_add_rules_datasets_none(self, mock_scope, did_factory, jdoe_account, root_account):
        """ REPLICATION RULE (CORE): Add replication rules to multiple datasets, NONE Grouping"""
        files1 = create_files(3, mock_scope, self.rse3_id)
        dataset1 = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset1)
        attach_dids(dids=files1, account=jdoe_account, **dataset1)

        files2 = create_files(3, mock_scope, self.rse3_id)
        dataset2 = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset2)
        attach_dids(dids=files2, account=jdoe_account, **dataset2)

        # Add the rules to both DS
        add_rules(dids=[dataset1, dataset2],
                  rules=[{'account': jdoe_account,
                          'copies': 1,
                          'rse_expression': self.T1,
                          'grouping': 'NONE',
                          'weight': None,
                          'lifetime': None,
                          'locked': False,
                          'subscription_id': None},
                         {'account': root_account,
                          'copies': 1,
                          'rse_expression': self.T1,
                          'grouping': 'NONE',
                          'weight': 'fakeweight',
                          'lifetime': None,
                          'locked': False,
                          'subscription_id': None}])

        # Check if the Locks are created properly
        for file in files1:
            rse_locks = [lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])]
            assert(rse_locks[0] == rse_locks[1])

        for file in files2:
            rse_locks = [lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])]
            assert(rse_locks[0] == rse_locks[1])

    def test_add_rule_container_none(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, NONE Grouping"""
        container = did_factory.random_container_did()
        add_did(did_type=DIDType.CONTAINER, account=jdoe_account, **container)
        all_files = []
        for i in range(3):
            files = create_files(3, mock_scope, self.rse1_id)
            all_files.extend(files)
            dataset = did_factory.random_dataset_did()
            add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
            attach_dids(dids=files, account=jdoe_account, **dataset)
            attach_dids(dids=[dataset], account=jdoe_account, **container)

        add_rule(dids=[container], account=jdoe_account, copies=1, rse_expression=self.T2, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
        for file in all_files:
            rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            assert self.rse3_id in rse_locks
            assert self.rse4_id not in rse_locks

    def test_add_rule_dataset_all(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, ALL Grouping"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = {self.rse1_id, self.rse2_id, self.rse4_id}
        first_locks = None
        for file in files:
            if first_locks is None:
                first_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

        # Check if the DatasetLocks are created properly
        dataset_locks = [lock for lock in get_dataset_locks(**dataset)]
        assert(len(t1.intersection(set([lock['rse_id'] for lock in dataset_locks]))) == 2)
        assert(len(first_locks.intersection(set([lock['rse_id'] for lock in dataset_locks]))) == 2)

    def test_add_rule_container_all(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, ALL Grouping"""
        container = did_factory.random_container_did()
        add_did(did_type=DIDType.CONTAINER, account=jdoe_account, **container)
        all_files = []
        for i in range(3):
            files = create_files(3, mock_scope, self.rse1_id)
            all_files.extend(files)
            dataset = did_factory.random_dataset_did()
            add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
            attach_dids(dids=files, account=jdoe_account, **dataset)
            attach_dids(dids=[dataset], account=jdoe_account, **container)

        add_rule(dids=[container], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        t1 = {self.rse1_id, self.rse2_id, self.rse4_id}
        first_locks = None
        for file in all_files:
            if first_locks is None:
                first_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

    def test_add_rule_requests(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, DATASET Grouping"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = {self.rse1_id, self.rse2_id, self.rse4_id}
        first_locks = None
        for file in files:
            if first_locks is None:
                first_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

        # Check if the DatasetLocks are created properly
        dataset_locks = [lock for lock in get_dataset_locks(**dataset)]
        assert(len(t1.intersection(set([lock['rse_id'] for lock in dataset_locks]))) == 2)
        assert(len(first_locks.intersection(set([lock['rse_id'] for lock in dataset_locks]))) == 2)

    def test_add_rule_dataset_dataset(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset and check if requests are created"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse4, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        for file in files:
            get_request_by_did(scope=file['scope'], name=file['name'], rse_id=self.rse4_id)

    def test_add_rule_container_dataset(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, DATASET Grouping"""
        container = did_factory.random_container_did()
        add_did(did_type=DIDType.CONTAINER, account=jdoe_account, **container)
        all_files = []
        dataset_files = []
        for i in range(3):
            files = create_files(3, mock_scope, self.rse1_id)
            all_files.extend(files)
            dataset = did_factory.random_dataset_did()
            add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
            attach_dids(dids=files, account=jdoe_account, **dataset)
            attach_dids(dids=[dataset], account=jdoe_account, **container)
            dataset_files.append((dataset, files))

        add_rule(dids=[container], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        t1 = {self.rse1_id, self.rse2_id, self.rse4_id}
        for ds, ds_files in dataset_files:
            first_locks = None
            for file in ds_files:
                if first_locks is None:
                    first_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
                rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
                assert(len(t1.intersection(rse_locks)) == 2)
                assert(len(first_locks.intersection(rse_locks)) == 2)

    def test_add_rule_dataset_none_with_weights(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, NONE Grouping, WEIGHTS"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='NONE', weight="fakeweight", lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = {self.rse1_id, self.rse2_id, self.rse4_id}
        for file in files:
            rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
            assert(len(t1.intersection(rse_locks)) == 2)
            assert self.rse1_id in rse_locks

    def test_add_rule_container_dataset_with_weights(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, DATASET Grouping, WEIGHTS"""
        container = did_factory.random_container_did()
        add_did(did_type=DIDType.CONTAINER, account=jdoe_account, **container)
        all_files = []
        dataset_files = []
        for i in range(3):
            files = create_files(3, mock_scope, self.rse1_id)
            all_files.extend(files)
            dataset = did_factory.random_dataset_did()
            add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
            attach_dids(dids=files, account=jdoe_account, **dataset)
            attach_dids(dids=[dataset], account=jdoe_account, **container)
            dataset_files.append((dataset, files))

        add_rule(dids=[container], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='DATASET', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)

        t1 = {self.rse1_id, self.rse2_id, self.rse4_id}
        for ds, ds_files in dataset_files:
            first_locks = None
            for file in ds_files:
                if first_locks is None:
                    first_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
                rse_locks = {lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])}
                assert(len(t1.intersection(rse_locks)) == 2)
                assert(len(first_locks.intersection(rse_locks)) == 2)
                assert self.rse1_id in rse_locks

    def test_get_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test to get a previously created rule"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        pytest.raises(RuleNotFound, get_rule, uuid())

    def test_delete_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test to delete a previously created rule"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='DATASET', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        delete_rule(rule_id)
        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'])
            assert(len(rse_locks) == 0)
        pytest.raises(RuleNotFound, delete_rule, uuid())

    def test_delete_rule_and_cancel_transfers(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test to delete a previously created rule and do not cancel overlapping transfers"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id_1 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        add_rule(dids=[dataset], account=jdoe_account, copies=3, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        delete_rule(rule_id_1)

        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'])
            assert(len(rse_locks) == 5)
            # TODO Need to check transfer queue here, this is actually not the check of this test case
        pytest.raises(RuleNotFound, delete_rule, uuid())

    def test_locked_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Delete a locked replication rule"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id_1 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=True, subscription_id=None)[0]

        pytest.raises(UnsupportedOperation, delete_rule, rule_id_1)
        update_rule(rule_id=rule_id_1, options={'locked': False})
        delete_rule(rule_id=rule_id_1)

    @pytest.mark.noparallel(reason='runs abacus account update')
    def test_account_counter_rule_create(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test if the account counter is updated correctly when new rule is created"""

        account_update(once=True)
        account_counter_before = get_usage(self.rse1_id, jdoe_account)

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the counter has been updated correctly
        account_update(once=True)
        account_counter_after = get_usage(self.rse1_id, jdoe_account)
        assert(account_counter_before['bytes'] + 3 * 100 == account_counter_after['bytes'])
        assert(account_counter_before['files'] + 3 == account_counter_after['files'])

    @pytest.mark.noparallel(reason='runs abacus account update')
    def test_account_counter_rule_delete(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test if the account counter is updated correctly when a rule is removed"""

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        account_update(once=True)
        account_counter_before = get_usage(self.rse1_id, jdoe_account)

        delete_rule(rule_id)
        account_update(once=True)

        # Check if the counter has been updated correctly
        account_counter_after = get_usage(self.rse1_id, jdoe_account)
        assert(account_counter_before['bytes'] - 3 * 100 == account_counter_after['bytes'])
        assert(account_counter_before['files'] - 3 == account_counter_after['files'])

    @pytest.mark.noparallel(reason='runs abacus account update')
    def test_account_counter_rule_update(self, vo, mock_scope, did_factory, jdoe_account, root_account):
        """ REPLICATION RULE (CORE): Test if the account counter is updated correctly when a rule is updated"""

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        account_update(once=True)
        account_counter_before_1 = get_usage(self.rse1_id, jdoe_account)
        account_counter_before_2 = get_usage(self.rse1_id, root_account)

        rucio.api.rule.update_replication_rule(rule_id, {'account': 'root'}, issuer='root', vo=vo)
        account_update(once=True)

        # Check if the counter has been updated correctly
        account_counter_after_1 = get_usage(self.rse1_id, jdoe_account)
        account_counter_after_2 = get_usage(self.rse1_id, root_account)
        assert(account_counter_before_1['bytes'] - 3 * 100 == account_counter_after_1['bytes'])
        assert(account_counter_before_2['bytes'] + 3 * 100 == account_counter_after_2['bytes'])

    @pytest.mark.noparallel(reason='runs abacus rse update')
    def test_rse_counter_unavailable_replicas(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test if creating UNAVAILABLE replicas updates the RSE Counter correctly"""

        rse_update(once=True)
        rse_counter_before = get_rse_counter(self.rse2_id)

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the rse has been updated correctly
        rse_update(once=True)
        rse_counter_after = get_rse_counter(self.rse2_id)
        assert(rse_counter_before['bytes'] + 3 * 100 == rse_counter_after['bytes'])
        assert(rse_counter_before['files'] + 3 == rse_counter_after['files'])

    def test_rule_add_fails_account_local_limit(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test if a rule fails correctly when local account limit conflict"""

        files = create_files(3, mock_scope, self.rse2_id, bytes_=100)
        # local quota
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        set_local_account_limit(account=jdoe_account, rse_id=self.rse2_id, bytes_=5)

        pytest.raises(InsufficientAccountLimit, add_rule, dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        set_local_account_limit(account=jdoe_account, rse_id=self.rse2_id, bytes_=-1)

    def test_rule_add_fails_account_global_limit(self, mock_scope, did_factory, random_account, rse_factory):
        """ REPLICATION RULE (CORE): Test if a rule fails correctly when global account limit conflict"""
        rse1, rse1_id = rse_factory.make_mock_rse()
        rse2, rse2_id = rse_factory.make_mock_rse()
        rse3, rse3_id = rse_factory.make_mock_rse()
        files = create_files(3, mock_scope, rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=random_account, **dataset)
        attach_dids(dids=files, account=random_account, **dataset)

        set_local_account_limit(account=random_account, rse_id=rse1_id, bytes_=400)
        # check with two global limits - one breaking limit is enough to let the rule fail
        set_global_account_limit(rse_expression=f'{rse1}|{rse2}', account=random_account, bytes_=400)
        set_global_account_limit(rse_expression=f'{rse1}|{rse3}', account=random_account, bytes_=10)
        pytest.raises(InsufficientAccountLimit, add_rule, dids=[dataset], account=random_account, copies=1, rse_expression=rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

    def test_rule_add_fails_rse_limit(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test if a rule fails correctly when rse limit set"""

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        set_rse_limits(self.rse2_id, 'MaxSpaceAvailable', 250)
        try:
            pytest.raises(RSEOverQuota, add_rule, dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
            pytest.raises(RSEOverQuota, add_rule, dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)
            # TODO: fix #5845 and uncomment this line
            # pytest.raises(RSEOverQuota, add_rule, dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
        finally:
            set_rse_limits(self.rse2_id, 'MaxSpaceAvailable', -1)

    def test_dataset_callback(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test dataset callback"""

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        set_status(open=False, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='C')[0]

        successful_transfer(scope=mock_scope, name=files[0]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[1]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[2]['name'], rse_id=self.rse2_id, nowait=False)

        # Check if rule exists
        assert(True is check_dataset_ok_callback(dataset['scope'], dataset['name'], self.rse2, self.rse2_id, rule_id))

    def test_dataset_callback_no(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test dataset callback should not be sent"""

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        set_status(open=False, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='C')[0]

        successful_transfer(scope=mock_scope, name=files[0]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[1]['name'], rse_id=self.rse2_id, nowait=False)

        # Check if rule exists
        assert(False is check_dataset_ok_callback(dataset['scope'], dataset['name'], self.rse2, self.rse2_id, rule_id))

    def test_dataset_callback_close_late(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test dataset callback with late close"""

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='C')[0]

        successful_transfer(scope=mock_scope, name=files[0]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[1]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[2]['name'], rse_id=self.rse2_id, nowait=False)

        # Check if rule exists
        assert(False is check_dataset_ok_callback(dataset['scope'], dataset['name'], self.rse2, self.rse2_id, rule_id))
        set_status(open=False, **dataset)
        assert(True is check_dataset_ok_callback(dataset['scope'], dataset['name'], self.rse2, self.rse2_id, rule_id))

    @pytest.mark.noparallel(reason='runs re_evaluator')
    def test_dataset_callback_with_evaluator(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test dataset callback with judge evaluator"""

        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='C')[0]

        assert(False is check_dataset_ok_callback(dataset['scope'], dataset['name'], self.rse2, self.rse2_id, rule_id))

        attach_dids(dids=files, account=jdoe_account, **dataset)
        set_status(open=False, **dataset)
        assert(False is check_dataset_ok_callback(dataset['scope'], dataset['name'], self.rse2, self.rse2_id, rule_id))

        re_evaluator(once=True)

        successful_transfer(scope=mock_scope, name=files[0]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[1]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[2]['name'], rse_id=self.rse2_id, nowait=False)

        assert(True is check_dataset_ok_callback(dataset['scope'], dataset['name'], self.rse2, self.rse2_id, rule_id))

    @pytest.mark.noparallel(reason='runs re_evaluator')
    def test_rule_progress_callback_with_evaluator(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test rule progress callback with judge evaluator"""

        files = create_files(30, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='P')[0]

        assert(False is check_rule_progress_callback(dataset['scope'], dataset['name'], 0, rule_id))

        attach_dids(dids=files, account=jdoe_account, **dataset)
        re_evaluator(once=True)

        set_status(open=False, **dataset)
        assert(False is check_rule_progress_callback(dataset['scope'], dataset['name'], 0, rule_id))

        successful_transfer(scope=mock_scope, name=files[0]['name'], rse_id=self.rse2_id, nowait=False)
        assert(False is check_rule_progress_callback(dataset['scope'], dataset['name'], 10, rule_id))
        successful_transfer(scope=mock_scope, name=files[1]['name'], rse_id=self.rse2_id, nowait=False)
        assert(False is check_rule_progress_callback(dataset['scope'], dataset['name'], 10, rule_id))
        successful_transfer(scope=mock_scope, name=files[2]['name'], rse_id=self.rse2_id, nowait=False)
        assert(True is check_rule_progress_callback(dataset['scope'], dataset['name'], 10, rule_id))
        successful_transfer(scope=mock_scope, name=files[3]['name'], rse_id=self.rse2_id, nowait=False)
        assert(False is check_rule_progress_callback(dataset['scope'], dataset['name'], 20, rule_id))
        successful_transfer(scope=mock_scope, name=files[4]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[5]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[6]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[7]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[8]['name'], rse_id=self.rse2_id, nowait=False)
        assert(True is check_rule_progress_callback(dataset['scope'], dataset['name'], 30, rule_id))
        successful_transfer(scope=mock_scope, name=files[9]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[10]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[11]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[12]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[13]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[14]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[15]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[16]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[17]['name'], rse_id=self.rse2_id, nowait=False)
        assert(True is check_rule_progress_callback(dataset['scope'], dataset['name'], 60, rule_id))
        successful_transfer(scope=mock_scope, name=files[18]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[19]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[20]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[21]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[22]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[23]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[24]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[25]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[26]['name'], rse_id=self.rse2_id, nowait=False)
        assert(True is check_rule_progress_callback(dataset['scope'], dataset['name'], 90, rule_id))
        successful_transfer(scope=mock_scope, name=files[27]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[28]['name'], rse_id=self.rse2_id, nowait=False)
        successful_transfer(scope=mock_scope, name=files[29]['name'], rse_id=self.rse2_id, nowait=False)
        assert(True is check_rule_progress_callback(dataset['scope'], dataset['name'], 100, rule_id))

    def test_add_rule_with_purge(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule with purge setting"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse3, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None, purge_replicas=True)[0]

        delete_rule(rule_id)

        # Check if the Locks are created properly
        for file in files:
            replica = get_replica(rse_id=self.rse3_id, scope=file['scope'], name=file['name'])
            assert(replica['tombstone'] == OBSOLETE)

    def test_add_rule_with_ignore_availability(self, vo, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule with ignore_availability setting"""
        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)
        update_rse(rse_id, {'availability_write': False})
        set_local_account_limit(jdoe_account, rse_id, -1)

        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        with pytest.raises(RSEWriteBlocked):
            add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=rse, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=rse, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None, ignore_availability=True)[0]
        for file in files:
            for filtered_lock in [lock for lock in get_replica_locks(scope=file['scope'], name=file['name'])]:
                assert(filtered_lock['state'] == LockState.STUCK)

    def test_delete_rule_country_admin(self, vo, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Delete a rule with a country admin account"""
        if get_policy() != 'atlas':
            LOG.info("Skipping atlas-specific test")
            return

        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)
        add_rse_attribute(rse_id, 'country', 'test')
        set_local_account_limit(jdoe_account, rse_id, -1)

        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=rse, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        usr = account_name_generator()
        add_account(usr, 'USER', 'rucio@email.com', 'root', vo=vo)

        with pytest.raises(AccessDenied):
            rucio.api.rule.delete_replication_rule(rule_id=rule_id, purge_replicas=None, issuer=usr, vo=vo)

        add_account_attribute(InternalAccount(usr, vo=vo), 'country-test', 'admin')
        rucio.api.rule.delete_replication_rule(rule_id=rule_id, purge_replicas=None, issuer=usr, vo=vo)

    def test_reduce_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Reduce a rule"""
        files = create_files(3, mock_scope, [self.rse1_id, self.rse2_id])
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.rse1 + '|' + self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        assert(get_rule(rule_id)['state'] == RuleState.OK)

        rule_id2 = reduce_rule(rule_id=rule_id, copies=1, exclude_expression=self.rse1)

        assert(get_rule(rule_id2)['state'] == RuleState.OK)
        pytest.raises(RuleNotFound, get_rule, rule_id)

        files = create_files(3, mock_scope, [self.rse1_id, self.rse2_id])
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.rse1 + '|' + self.rse2 + '|' + self.rse4, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        with pytest.raises(RuleReplaceFailed):
            reduce_rule(rule_id=rule_id, copies=1, exclude_expression=self.rse1 + '|' + self.rse2)

    def test_move_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Move a rule"""
        files = create_files(3, mock_scope, [self.rse1_id])
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        assert(get_rule(rule_id)['state'] == RuleState.OK)

        rule_id2 = move_rule(rule_id, self.rse2)

        assert(get_rule(rule_id2)['state'] == RuleState.REPLICATING)
        assert(get_rule(rule_id)['child_rule_id'] == rule_id2)
        assert(get_rule(rule_id2)['activity'] == get_rule(rule_id)['activity'])
        assert(get_rule(rule_id2)['source_replica_expression'] == get_rule(rule_id)['source_replica_expression'])

        pytest.raises(RuleReplaceFailed, move_rule, rule_id, self.rse3)

    def test_move_rule_with_arguments(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Move a rule with activity and source-replica-expression specified"""
        files = create_files(3, mock_scope, [self.rse1_id])
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        assert(get_rule(rule_id)['state'] == RuleState.OK)

        activity = "No User Subscriptions"
        source_replica_expression = self.rse2 + "|" + self.rse1
        rule_id2 = move_rule(rule_id, self.rse2, override={'activity': activity, 'source_replica_expression': source_replica_expression})

        assert(get_rule(rule_id2)['state'] == RuleState.REPLICATING)
        assert(get_rule(rule_id)['child_rule_id'] == rule_id2)
        assert(get_rule(rule_id2)['activity'] == activity)
        assert(get_rule(rule_id2)['source_replica_expression'] == source_replica_expression)

        pytest.raises(RuleReplaceFailed, move_rule, rule_id, self.rse3)
        pytest.raises(RucioException, move_rule, 'foo', self.rse3)

    def test_add_rule_with_scratchdisk(self, vo, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule for scratchdisk"""
        if get_policy() != 'atlas':
            LOG.info("Skipping atlas-specific test")
            return

        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)
        add_rse_attribute(rse_id, 'type', 'SCRATCHDISK')
        set_local_account_limit(jdoe_account, rse_id, -1)

        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
        assert(get_rule(rule_id)['expires_at'] is not None)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression='%s' % self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
        assert(get_rule(rule_id)['expires_at'] is None)

    def test_add_rule_with_auto_approval(self, vo, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule with auto approval"""
        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)

        files = create_files(3, mock_scope, self.rse1_id, bytes_=200)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)
        set_status(open=False, **dataset)

        with pytest.raises(InsufficientAccountLimit):
            rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]
        assert(get_rule(rule_id)['state'] == RuleState.WAITING_APPROVAL)
        delete_rule(rule_id=rule_id)

        add_rse_attribute(rse_id, 'auto_approve_bytes', 500)
        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]
        assert(get_rule(rule_id)['state'] == RuleState.WAITING_APPROVAL)
        delete_rule(rule_id=rule_id)

        del_rse_attribute(rse_id, 'auto_approve_bytes')
        add_rse_attribute(rse_id, 'auto_approve_bytes', 1000)
        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]
        assert(get_rule(rule_id)['state'] == RuleState.INJECT)

    def test_add_rule_with_manual_approval_block(self, vo, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Add a replication rule for a RSE with manual approval block"""
        rse = rse_name_generator()
        rse_id = add_rse(rse, vo=vo)
        add_rse_attribute(rse_id, 'block_manual_approval', '1')
        set_local_account_limit(jdoe_account, rse_id, -1)

        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        with pytest.raises(ManualRuleApprovalBlocked):
            add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]

    def test_update_rule_child_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Update a replication rule with a child_rule"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset1 = did_factory.random_dataset_did()
        dataset2 = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset1)
        attach_dids(dids=files, account=jdoe_account, **dataset1)
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset2)
        attach_dids(dids=files, account=jdoe_account, **dataset2)

        rule_id_1 = add_rule(dids=[dataset1], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
        rule_id_2 = add_rule(dids=[dataset2], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
        rule_id_3 = add_rule(dids=[dataset1], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        with pytest.raises(InputValidationError):
            update_rule(rule_id_1, options={'child_rule_id': rule_id_2})
        update_rule(rule_id_1, options={'child_rule_id': rule_id_3})
        with pytest.raises(UnsupportedOperation):
            delete_rule(rule_id_1)

    def test_rule_priority_set_and_update(self, mock_scope, did_factory, jdoe_account):
        files = create_files(1, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='NONE',
                           weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        assert get_rule(rule_id)['priority'] == 3
        request = get_request_by_did(scope=files[0]['scope'], name=files[0]['name'], rse_id=self.rse2_id)
        assert request['priority'] == 3

        update_rule(rule_id, {'priority': 5})
        assert get_rule(rule_id)['priority'] == 5
        assert get_request_by_did(scope=files[0]['scope'], name=files[0]['name'], rse_id=self.rse2_id)['priority'] == 5

    def test_release_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test to release a parent rule after child rule is OK"""
        files = create_files(3, mock_scope, self.rse1_id, bytes_=100)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id_1 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
        rule_id_2 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        update_rule(rule_id_1, options={'child_rule_id': rule_id_2})

        with pytest.raises(UnsupportedOperation):
            delete_rule(rule_id_1)

        successful_transfer(scope=mock_scope, name=files[0]['name'], rse_id=self.rse2_id, nowait=False)
        with pytest.raises(UnsupportedOperation):
            delete_rule(rule_id_1)
        successful_transfer(scope=mock_scope, name=files[1]['name'], rse_id=self.rse2_id, nowait=False)
        with pytest.raises(UnsupportedOperation):
            delete_rule(rule_id_1)
        successful_transfer(scope=mock_scope, name=files[2]['name'], rse_id=self.rse2_id, nowait=False)
        delete_rule(rule_id_1)

    def test_metadata__rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CORE): Test to write wfms metadata to rule"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=2, rse_expression=self.T1, grouping='NONE',
                           weight='fakeweight', lifetime=None, locked=False, meta={'task_id': 55, 'job_ids': [1, 2, 3, 4]}, subscription_id=None)[0]
        assert(get_rule(rule_id)['meta'] == json.dumps({'task_id': 55, 'job_ids': [1, 2, 3, 4]}))

    def test_rule_on_archive(self, mock_scope, jdoe_account):
        """ REPLICATION RULE (CORE): Test to add a rule on a constituent should add rule on archive"""
        archive = {'scope': mock_scope, 'name': '%s.zip' % str(uuid()), 'type': 'FILE',
                   'bytes': 2596, 'adler32': 'beefdead'}
        add_replica(rse_id=self.rse1_id, scope=mock_scope, name=archive['name'], bytes_=2596, account=jdoe_account)
        files_in_archive = [{'scope': mock_scope, 'name': 'witrep-%i-%s' % (i, str(uuid())), 'type': 'FILE',
                             'bytes': 1234, 'adler32': 'deadbeef'} for i in range(2)]
        attach_dids(mock_scope, archive['name'], files_in_archive, jdoe_account)

        add_rule(dids=[{'scope': mock_scope, 'name': files_in_archive[1]['name']}], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='NONE',
                 weight=None, lifetime=None, locked=False, subscription_id=None)
        assert(len(list(list_rules(filters={'scope': mock_scope, 'name': archive['name']}))) == 1)

        # Check the same but now a replica of the constituent exists as well
        archive = {'scope': mock_scope, 'name': '%s.zip' % str(uuid()), 'type': 'FILE',
                   'bytes': 2596, 'adler32': 'beefdead'}
        add_replica(rse_id=self.rse1_id, scope=mock_scope, name=archive['name'], bytes_=2596, account=jdoe_account)
        files_in_archive = [{'scope': mock_scope, 'name': 'witrep-%i-%s' % (i, str(uuid())), 'type': 'FILE',
                             'bytes': 1234, 'adler32': 'deadbeef'} for i in range(2)]
        attach_dids(mock_scope, archive['name'], files_in_archive, jdoe_account)
        add_replica(rse_id=self.rse1_id, scope=mock_scope, name=files_in_archive[1]['name'], bytes_=2596, account=jdoe_account)

        add_rule(dids=[{'scope': mock_scope, 'name': files_in_archive[1]['name']}], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='NONE',
                 weight=None, lifetime=None, locked=False, subscription_id=None)
        assert(len(list(list_rules(filters={'scope': mock_scope, 'name': archive['name']}))) == 0)
        assert(len(list(list_rules(filters={'scope': mock_scope, 'name': files_in_archive[1]['name']}))) == 1)

    def test_add_rule_overlapping_dids(self, vo, mock_scope, jdoe_account):
        """ REPLICATION RULE (CORE): Test various overlap cases"""

        def mktree(scope, account):
            # container1213 = container12 + container13
            # container12 = ds1 + ds2
            # container13 = ds1 + ds3
            # ds1 = file1 .. file10
            # ds2 = file11 .. file20
            # ds3 = file1, file2, file11, file12, file21 .. file25
            # 11 replicas @ rse1  -> file1 ..file7,   file21 .. file24
            #  3 replicas @ rse2 -> file8 .. file10
            #  6 replicas @ rse3 -> file11 .. file16
            #  5 replicas @ rse4 -> file17 .. file20, file25
            for i in range(1, 8):
                add_replica(rse_id=get_rse_id(self.rse1, vo=vo), scope=scope, name='file_%06d.data' % i, bytes_=10000 + i, account=account)
            for i in range(8, 11):
                add_replica(rse_id=get_rse_id(self.rse2, vo=vo), scope=scope, name='file_%06d.data' % i, bytes_=10000 + i, account=account)
            for i in range(11, 17):
                add_replica(rse_id=get_rse_id(self.rse3, vo=vo), scope=scope, name='file_%06d.data' % i, bytes_=10000 + i, account=account)
            for i in range(17, 21):
                add_replica(rse_id=get_rse_id(self.rse4, vo=vo), scope=scope, name='file_%06d.data' % i, bytes_=10000 + i, account=account)
            for i in range(21, 25):
                add_replica(rse_id=get_rse_id(self.rse1, vo=vo), scope=scope, name='file_%06d.data' % i, bytes_=10000 + i, account=account)
            for i in range(25, 26):
                add_replica(rse_id=get_rse_id(self.rse4, vo=vo), scope=scope, name='file_%06d.data' % i, bytes_=10000 + i, account=account)

            add_did(scope=scope, name='ds1', did_type='DATASET', account=account)
            attach_dids(scope=scope, name='ds1', dids=[{'scope': scope, 'name': 'file_%06d.data' % i} for i in range(1, 10 + 1)], account=account)
            add_did(scope=scope, name='ds2', did_type='DATASET', account=account)
            attach_dids(scope=scope, name='ds2', dids=[{'scope': scope, 'name': 'file_%06d.data' % i} for i in range(11, 20 + 1)], account=account)
            add_did(scope=scope, name='ds3', did_type='DATASET', account=account)
            attach_dids(scope=scope, name='ds3', dids=[{'scope': scope, 'name': 'file_%06d.data' % i} for i in (list(range(21, 25 + 1)) + [1, 2, 11, 12])], account=account)
            add_did(scope=scope, name='container12', did_type='CONTAINER', account=account)
            attach_dids(scope=scope, name='container12', dids=[{'scope': scope, 'name': 'ds1'}, {'scope': scope, 'name': 'ds2'}, ], account=account)
            add_did(scope=scope, name='container13', did_type='CONTAINER', account=account)
            attach_dids(scope=scope, name='container13', dids=[{'scope': scope, 'name': 'ds1'}, {'scope': scope, 'name': 'ds3'}, ], account=account)
            add_did(scope=scope, name='container1213', did_type='CONTAINER', account=account)
            attach_dids(scope=scope, name='container1213', dids=[{'scope': scope, 'name': 'container12'}, {'scope': scope, 'name': 'container13'}, ], account=account)

        account = jdoe_account

        # test1 : ALL grouping -> select rse1 for all 3 datasets
        scope = InternalScope(('scope1_' + str(uuid()))[:21], vo=vo)  # scope field has max 25 chars including VO
        add_scope(scope, account)
        mktree(scope, account)
        rule_ids = add_rule(dids=[{'scope': scope, 'name': 'container1213'}], copies=1, rse_expression=f'{self.rse1}|{self.rse2}|{self.rse3}|{self.rse4}',
                            grouping='ALL', account=account, weight=None, lifetime=None, locked=False, subscription_id=None)
        rule = get_rule(rule_ids[0])
        print(rule['locks_ok_cnt'], rule['locks_replicating_cnt'])
        assert(rule['locks_ok_cnt'] == 11)
        assert(rule['locks_replicating_cnt'] == 14)
        dsl1 = list(get_dataset_locks(scope, 'ds1'))
        dsl2 = list(get_dataset_locks(scope, 'ds2'))
        dsl3 = list(get_dataset_locks(scope, 'ds3'))
        print(dsl1)
        print(dsl2)
        print(dsl3)
        assert(len(dsl1) == 1 and dsl1[0]['rse'] == self.rse1)
        assert(len(dsl2) == 1 and dsl2[0]['rse'] == self.rse1)
        assert(len(dsl3) == 1 and dsl3[0]['rse'] == self.rse1)

        # test2 : DATASET grouping -> select rse1 for ds1, rse3 for ds2 and rse1 for ds3
        scope = InternalScope(('scope2_' + str(uuid()))[:21], vo=vo)  # scope field has max 25 chars
        add_scope(scope, account)
        mktree(scope, account)
        rule_ids = add_rule(dids=[{'scope': scope, 'name': 'container1213'}], copies=1, rse_expression=f'{self.rse1}|{self.rse2}|{self.rse3}|{self.rse4}',
                            grouping='DATASET', account=account, weight=None, lifetime=None, locked=False, subscription_id=None)
        rule = get_rule(rule_ids[0])
        print(rule['locks_ok_cnt'], rule['locks_replicating_cnt'])
        assert(rule['locks_ok_cnt'] == 17)
        assert(rule['locks_replicating_cnt'] == 8)
        dsl1 = list(get_dataset_locks(scope, 'ds1'))
        dsl2 = list(get_dataset_locks(scope, 'ds2'))
        dsl3 = list(get_dataset_locks(scope, 'ds3'))
        print(dsl1)
        print(dsl2)
        print(dsl3)
        assert(len(dsl1) == 1 and dsl1[0]['rse'] == self.rse1)
        assert(len(dsl2) == 1 and dsl2[0]['rse'] == self.rse3)
        assert(len(dsl3) == 1 and dsl3[0]['rse'] == self.rse1)

        # test3 : NONE grouping
        scope = InternalScope(('scope3_' + str(uuid()))[:21], vo=vo)  # scope field has max 25 chars
        add_scope(scope, account)
        mktree(scope, account)
        rule_ids = add_rule(dids=[{'scope': scope, 'name': 'container1213'}], copies=1, rse_expression=f'{self.rse1}|{self.rse2}|{self.rse3}|{self.rse4}',
                            grouping='NONE', account=account, weight=None, lifetime=None, locked=False, subscription_id=None)
        rule = get_rule(rule_ids[0])
        print(rule['locks_ok_cnt'], rule['locks_replicating_cnt'])
        assert(rule['locks_ok_cnt'] == 25)
        assert(rule['locks_replicating_cnt'] == 0)
        dsl1 = list(get_dataset_locks(scope, 'ds1'))
        dsl2 = list(get_dataset_locks(scope, 'ds2'))
        dsl3 = list(get_dataset_locks(scope, 'ds3'))
        print(dsl1)
        print(dsl2)
        print(dsl3)
        assert(len(dsl1) == 0)
        assert(len(dsl2) == 0)
        assert(len(dsl3) == 0)


def test_rule_boost(vo, mock_scope, rse_factory, file_factory):
    """ REPLICATION RULE (CORE): Update a replication rule to quicken the translation from stuck to replicating """
    jdoe = InternalAccount('jdoe', vo)
    _, tmp_rse_id = rse_factory.make_mock_rse()
    rse, rse_id = rse_factory.make_mock_rse()
    update_rse(rse_id, {'availability_write': False})
    set_local_account_limit(jdoe, rse_id, -1)
    files = create_files(3, mock_scope, tmp_rse_id)
    dataset1 = 'dataset_' + str(uuid())
    add_did(mock_scope, dataset1, DIDType.DATASET, jdoe)
    attach_dids(mock_scope, dataset1, files, jdoe)

    rule_id = add_rule(dids=[{'scope': mock_scope, 'name': dataset1}], account=jdoe, copies=1, rse_expression=rse, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None, ignore_availability=True)[0]
    before_update_rule = {}
    for file in files:
        for filtered_lock in [lock for lock in get_replica_locks(scope=file['scope'], name=file['name'])]:
            assert(filtered_lock['state'] == LockState.STUCK)
            before_update_rule[filtered_lock['name']] = filtered_lock['updated_at']
    before_update_rule_updated_at = get_rule(rule_id)['updated_at']

    update_rule(rule_id, options={'boost_rule': True})

    for file in files:
        for filtered_lock in [lock for lock in get_replica_locks(scope=file['scope'], name=file['name'])]:
            assert(before_update_rule[filtered_lock['name']] > filtered_lock['updated_at'])
    assert(before_update_rule_updated_at > get_rule(rule_id)['updated_at'])


@pytest.mark.usefixtures('setup_class')
class TestClient:

    rule_client = RuleClient()

    def test_add_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CLIENT): Add a replication rule and list full history """
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        ret = self.rule_client.add_replication_rule(dids=[{'scope': mock_scope.external, 'name': dataset['name']}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        assert isinstance(ret, list)

        rep_rules = [rep_rule for rep_rule in self.rule_client.list_replication_rule_full_history(mock_scope.external, dataset['name'])]
        assert len(rep_rules) == 1
        assert ret[0] == rep_rules[0]['rule_id']

    def test_delete_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CLIENT): Delete a replication rule """
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        ret = self.rule_client.delete_replication_rule(rule_id=rule_id)
        assert(ret is True)
        get = self.rule_client.get_replication_rule(rule_id)
        assert(get['expires_at'] is not None)

    def test_list_rules_by_did(self, mock_scope, did_factory, jdoe_account, rucio_client):
        """ DID (CLIENT): List Replication Rules per DID """
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id_1 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        rule_id_2 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse2, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        ret = rucio_client.list_did_rules(scope=mock_scope.external, name=dataset['name'])
        ids = [rule['id'] for rule in ret]

        assert rule_id_1 in ids
        assert rule_id_2 in ids

    def test_get_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CLIENT): Get Replication Rule by id """
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        ret = self.rule_client.add_replication_rule(dids=[{'scope': mock_scope.external, 'name': dataset['name']}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        get = self.rule_client.get_replication_rule(ret[0])
        assert(ret[0] == get['id'])

    def test_get_rule_by_account(self, mock_scope, did_factory, jdoe_account, rucio_client):
        """ ACCOUNT (CLIENT): Get Replication Rule by account """
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        ret = self.rule_client.add_replication_rule(dids=[{'scope': mock_scope.external, 'name': dataset['name']}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        get = rucio_client.list_account_rules('jdoe')
        rules = [rule['id'] for rule in get]

        assert ret[0] in rules

    def test_locked_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CLIENT): Delete a locked replication rule"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id_1 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=True, subscription_id=None)[0]

        pytest.raises(UnsupportedOperation, delete_rule, rule_id_1)
        self.rule_client.update_replication_rule(rule_id=rule_id_1, options={'locked': False})
        delete_rule(rule_id=rule_id_1)

    def test_dataset_lock(self, mock_scope, did_factory, jdoe_account, rucio_client):
        """ DATASETLOCK (CLIENT): Get a datasetlock for a specific dataset"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id_1 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='DATASET', weight='fakeweight', lifetime=None, locked=True, subscription_id=None)[0]

        rule_ids = [lock['rule_id'] for lock in rucio_client.get_dataset_locks(scope=mock_scope.external, name=dataset['name'])]
        assert rule_id_1 in rule_ids

    def test_change_rule_lifetime(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CLIENT): Change rule lifetime"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id_1 = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='DATASET', weight='fakeweight', lifetime=150, locked=True, subscription_id=None)[0]

        get = self.rule_client.get_replication_rule(rule_id_1)

        self.rule_client.update_replication_rule(rule_id_1, options={'lifetime': 10000})

        get2 = self.rule_client.get_replication_rule(rule_id_1)

        assert(get['expires_at'] != get2['expires_at'])

    def test_approve_rule(self, mock_scope, did_factory, jdoe_account):
        """ REPLICATION RULE (CLIENT): Approve rule"""
        files = create_files(3, mock_scope, self.rse1_id)
        dataset = did_factory.random_dataset_did()
        add_did(did_type=DIDType.DATASET, account=jdoe_account, **dataset)
        attach_dids(dids=files, account=jdoe_account, **dataset)

        rule_id = add_rule(dids=[dataset], account=jdoe_account, copies=1, rse_expression=self.rse1, grouping='DATASET', weight='fakeweight', lifetime=150, locked=True, subscription_id=None, ask_approval=True)[0]
        rule = self.rule_client.get_replication_rule(rule_id)
        assert rule['state'] == RuleState.WAITING_APPROVAL.name
        self.rule_client.approve_replication_rule(rule_id)
        rule = self.rule_client.get_replication_rule(rule_id)
        assert rule['state'] == RuleState.INJECT.name


def test_add_rule_with_0_copies(did_client, did_factory, root_account, rse_factory):
    """ REPLICATION RULE (CLIENT): Add a replication rule and list full history """
    rse, rse_id = rse_factory.make_posix_rse()
    file = did_factory.upload_test_file(rse)
    dataset_internal = did_factory.make_dataset()
    container_internal = did_factory.make_container()

    # make all scopes external
    file, dataset, container = ({'scope': did['scope'].external, 'name': did['name']} for did in (file, dataset_internal, container_internal))

    # Attach dataset to container
    did_client.add_files_to_dataset(files=[file], **dataset)
    did_client.add_datasets_to_container(dsns=[dataset], **container)

    with pytest.raises(InvalidValueForKey) as e:
        add_rule(dids=[container_internal], account=root_account, copies=0, rse_expression=rse, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)
        assert "The number of copies for a replication rule should be greater than 0" in str(e)


@pytest.mark.noparallel(reason='Asynchronos behavior when loading locks')
def test_detach_dataset_lock_removal(did_client, did_factory, root_account, rse_factory, vo):
    rse1, rse1_id = rse_factory.make_posix_rse()
    rse2, rse2_id = rse_factory.make_posix_rse()
    file = did_factory.upload_test_file(rse1)
    dataset_internal = did_factory.make_dataset()
    container_internal = did_factory.make_container()

    # make all scopes external
    file, dataset, container = ({'scope': did['scope'].external, 'name': did['name']} for did in (file, dataset_internal, container_internal))

    # Attach dataset to container
    did_client.add_files_to_dataset(files=[file], **dataset)
    did_client.add_datasets_to_container(dsns=[dataset], **container)

    add_rse_attribute(rse_id=rse1_id, key='fakeweight', value=5)
    add_rse_attribute(rse_id=rse2_id, key='fakeweight', value=5)

    rule_id = add_rule(dids=[container_internal], account=root_account, copies=2, rse_expression='fakeweight>0', grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    print("Rule id: {0}".format(rule_id))
    dataset_locks = list(get_dataset_locks(scope=dataset_internal['scope'], name=dataset['name']))
    print("Dataset locks before detach: {0}".format(dataset_locks))
    assert(len([d for d in dataset_locks if d["rule_id"] == rule_id]) == 2)

    # Detach dataset from container, this should delete all locks on the dataset
    did_client.detach_dids(**container, dids=[dataset_internal])

    re_evaluator(once=True, did_limit=None)

    dataset_locks = list(get_dataset_locks(**dataset_internal))
    print("Dataset locks after detach: {0}".format(dataset_locks))
    assert(len([d for d in dataset_locks if d["rule_id"] == rule_id]) == 0)


@pytest.mark.noparallel(reason='Asynchronos behavior when loading locks')
def test_detach_dataset_lock_removal_shared_dataset(did_client, did_factory, root_account, rse_factory, vo):
    rse1, rse1_id = rse_factory.make_posix_rse()
    rse2, rse2_id = rse_factory.make_posix_rse()
    file = did_factory.upload_test_file(rse1)
    dataset_internal = did_factory.make_dataset()
    container_internal = did_factory.make_container()
    container_internal_2 = did_factory.make_container()

    # make all scopes external
    file, dataset, container, container_2 = ({'scope': did['scope'].external, 'name': did['name']} for did in (file, dataset_internal, container_internal, container_internal_2))

    # Attach dataset to container
    did_client.add_files_to_dataset(files=[file], **dataset)
    did_client.add_datasets_to_container(dsns=[dataset], **container)
    did_client.add_datasets_to_container(dsns=[dataset], **container_2)

    add_rse_attribute(rse_id=rse1_id, key='fakeweight', value=5)
    add_rse_attribute(rse_id=rse2_id, key='fakeweight', value=5)

    rule_id = add_rule(dids=[container_internal], account=root_account, copies=2, rse_expression='fakeweight>0', grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    print("Rule id: {0}".format(rule_id))
    dataset_locks = list(get_dataset_locks(scope=dataset_internal['scope'], name=dataset['name']))
    print("Dataset locks before detach: {0}".format(dataset_locks))
    assert(len([d for d in dataset_locks if d["rule_id"] == rule_id]) == 2)

    # Detach dataset from container, this should delete all locks on the dataset
    did_client.detach_dids(**container, dids=[dataset_internal])

    re_evaluator(once=True, did_limit=None)

    dataset_locks = list(get_dataset_locks(**dataset_internal))
    print("Dataset locks after detach: {0}".format(dataset_locks))
    assert(len([d for d in dataset_locks if d["rule_id"] == rule_id]) == 0)


@pytest.mark.noparallel(reason='Asynchronos behavior when loading locks')
def test_detach_dataset_lock_removal_shared_file(did_client, did_factory, root_account, rse_factory, vo):
    rse1, rse1_id = rse_factory.make_posix_rse()
    rse2, rse2_id = rse_factory.make_posix_rse()
    file = did_factory.upload_test_file(rse1)
    dataset_internal = did_factory.make_dataset()
    dataset_internal_2 = did_factory.make_dataset()
    container_internal = did_factory.make_container()

    # make all scopes external
    file, dataset, dataset_2, container = ({'scope': did['scope'].external, 'name': did['name']} for did in (file, dataset_internal, dataset_internal_2, container_internal))

    # Attach dataset to container
    did_client.add_files_to_dataset(files=[file], **dataset)
    did_client.add_files_to_dataset(files=[file], **dataset_2)
    did_client.add_datasets_to_container(dsns=[dataset], **container)

    add_rse_attribute(rse_id=rse1_id, key='fakeweight', value=5)
    add_rse_attribute(rse_id=rse2_id, key='fakeweight', value=5)

    rule_id = add_rule(dids=[container_internal], account=root_account, copies=2, rse_expression='fakeweight>0', grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    print("Rule id: {0}".format(rule_id))
    dataset_locks = list(get_dataset_locks(scope=dataset_internal['scope'], name=dataset['name']))
    print("Dataset locks before detach: {0}".format(dataset_locks))
    assert(len([d for d in dataset_locks if d["rule_id"] == rule_id]) == 2)

    # Detach dataset from container, this should delete all locks on the dataset
    did_client.detach_dids(**container, dids=[dataset_internal])

    re_evaluator(once=True, did_limit=None)

    dataset_locks = list(get_dataset_locks(**dataset_internal))
    print("Dataset locks after detach: {0}".format(dataset_locks))
    assert(len([d for d in dataset_locks if d["rule_id"] == rule_id]) == 0)


def test_move_rule_invalid_argument(vo, rse_factory, did_factory, mock_scope, root_account):
    rse, rse_id = rse_factory.make_rse()
    new_rse, new_rse_id = rse_factory.make_rse()
    files = create_files(3, mock_scope, [rse_id])
    dataset = did_factory.random_dataset_did()
    add_did(did_type=DIDType.DATASET, account=root_account, **dataset)
    attach_dids(dids=files, account=root_account, **dataset)

    rule_id = add_rule(dids=[dataset], account=root_account, copies=1, rse_expression=rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]
    assert(get_rule(rule_id)['state'] == RuleState.OK)

    with pytest.raises(UnsupportedOperation):
        _ = move_rule(rule_id, new_rse, override={'session': 17})

    with pytest.raises(UnsupportedOperation):
        _ = move_rule(rule_id, new_rse, override={'xX_MyFirstStreetName_Xx': 17})
