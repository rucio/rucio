# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

import string
import random
import json

from nose.tools import assert_is_instance, assert_in, assert_not_in, assert_raises, assert_equal

import rucio.api.rule

from rucio.api.account import add_account
from rucio.client.accountclient import AccountClient
from rucio.client.lockclient import LockClient
from rucio.client.didclient import DIDClient
from rucio.client.ruleclient import RuleClient
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.common.utils import generate_uuid as uuid
from rucio.common.exception import (RuleNotFound, AccessDenied, InsufficientAccountLimit, DuplicateRule, RSEBlacklisted,
                                    RuleReplaceFailed, ScratchDiskLifetimeConflict, ManualRuleApprovalBlocked, UnsupportedOperation)
from rucio.core.account_counter import get_counter as get_account_counter
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.core.did import add_did, attach_dids, set_status
from rucio.core.lock import get_replica_locks, get_dataset_locks, successful_transfer
from rucio.core.account import add_account_attribute
from rucio.core.account_limit import set_account_limit, delete_account_limit
from rucio.core.request import get_request_by_did
from rucio.core.replica import add_replica, get_replica
from rucio.core.rse import add_rse_attribute, get_rse, add_rse, update_rse, get_rse_id, del_rse_attribute
from rucio.core.rse_counter import get_counter as get_rse_counter
from rucio.core.rule import add_rule, get_rule, delete_rule, add_rules, update_rule, reduce_rule
from rucio.daemons.abacus.account import account_update
from rucio.daemons.abacus.rse import rse_update
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, OBSOLETE, RuleState
from rucio.db.sqla.session import transactional_session
from rucio.tests.common import rse_name_generator, account_name_generator


def create_files(nrfiles, scope, rse, bytes=1):
    """
    Creates a number of test files and add replicas to rse

    :param nrfiles:  Number of files to create
    :param scope:    Scope to create the files in
    :param rse:      RSE to add the replica to
    :param bytes:    Bytes of each file
    :returns:        List of dict
    """
    files = []
    for i in xrange(nrfiles):
        file = 'file_%s' % uuid()
        if isinstance(rse, list):
            for r in rse:
                add_replica(rse=r, scope=scope, name=file, bytes=bytes, account='jdoe')
        else:
            add_replica(rse=rse, scope=scope, name=file, bytes=bytes, account='jdoe')
        files.append({'scope': scope, 'name': file, 'bytes': bytes})
    return files


def tag_generator(size=8, chars=string.ascii_uppercase):
    return ''.join(random.choice(chars) for x in range(size))


@transactional_session
def check_dataset_ok_callback(scope, name, rse, rule_id, session=None):
    callbacks = session.query(models.Message.id).filter(models.Message.payload == json.dumps({'scope': scope,
                                                                                              'name': name,
                                                                                              'rse': rse,
                                                                                              'rule_id': rule_id})).all()
    if len(callbacks) > 0:
        return True
    return False


class TestReplicationRuleCore():

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

    def test_add_rule_file_none(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a group of files, NONE Grouping"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        add_rule(dids=files, account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse1_id, self.rse3_id, self.rse5_id])
        for file in files:
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) > 0)
            assert_not_in(self.rse4_id, rse_locks)

    def test_add_rule_dataset_none(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, NONE Grouping"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Add a second rule and check if the right locks are created
        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression='%s|%s' % (self.T1, self.T2), grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse3_id, self.rse5_id])
        for file in files:
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert_not_in(self.rse4_id, rse_locks)

    def test_add_rule_duplicate(self):
        """ REPLICATION RULE (CORE): Add a replication rule duplicate"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Add a second rule and check if the right locks are created
        assert_raises(DuplicateRule, add_rule, dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

    def test_add_rules_datasets_none(self):
        """ REPLICATION RULE (CORE): Add replication rules to multiple datasets, NONE Grouping"""
        scope = 'mock'
        files1 = create_files(3, scope, self.rse4)
        dataset1 = 'dataset_' + str(uuid())
        add_did(scope, dataset1, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset1, files1, 'jdoe')

        files2 = create_files(3, scope, self.rse4)
        dataset2 = 'dataset_' + str(uuid())
        add_did(scope, dataset2, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset2, files2, 'jdoe')

        # Add the rules to both DS
        add_rules(dids=[{'scope': scope, 'name': dataset1}, {'scope': scope, 'name': dataset2}],
                  rules=[{'account': 'jdoe',
                          'copies': 1,
                          'rse_expression': self.T1,
                          'grouping': 'NONE',
                          'weight': None,
                          'lifetime': None,
                          'locked': False,
                          'subscription_id': None},
                         {'account': 'root',
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

    def test_add_rule_container_none(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, NONE Grouping"""
        scope = 'mock'
        container = 'container_' + str(uuid())
        add_did(scope, container, DIDType.from_sym('CONTAINER'), 'jdoe')
        all_files = []
        for i in xrange(3):
            files = create_files(3, scope, self.rse1)
            all_files.extend(files)
            dataset = 'dataset_' + str(uuid())
            add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
            attach_dids(scope, dataset, files, 'jdoe')
            attach_dids(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=1, rse_expression=self.T2, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
        for file in all_files:
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert_in(self.rse4_id, rse_locks)
            assert_not_in(self.rse5_id, rse_locks)

    def test_add_rule_dataset_all(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, ALL Grouping"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse3_id, self.rse5_id])
        first_locks = None
        for file in files:
            if first_locks is None:
                first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

        # Check if the DatasetLocks are created properly
        dataset_locks = [lock for lock in get_dataset_locks(scope=scope, name=dataset)]
        assert(len(t1.intersection(set([lock['rse_id'] for lock in dataset_locks]))) == 2)
        assert(len(first_locks.intersection(set([lock['rse_id'] for lock in dataset_locks]))) == 2)

    def test_add_rule_container_all(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, ALL Grouping"""
        scope = 'mock'
        container = 'container_' + str(uuid())
        add_did(scope, container, DIDType.from_sym('CONTAINER'), 'jdoe')
        all_files = []
        for i in xrange(3):
            files = create_files(3, scope, self.rse1)
            all_files.extend(files)
            dataset = 'dataset_' + str(uuid())
            add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
            attach_dids(scope, dataset, files, 'jdoe')
            attach_dids(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=2, rse_expression=self.T1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        t1 = set([self.rse1_id, self.rse3_id, self.rse5_id])
        first_locks = None
        for file in all_files:
            if first_locks is None:
                first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

    def test_add_rule_requests(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, DATASET Grouping"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse3_id, self.rse5_id])
        first_locks = None
        for file in files:
            if first_locks is None:
                first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

        # Check if the DatasetLocks are created properly
        dataset_locks = [lock for lock in get_dataset_locks(scope=scope, name=dataset)]
        assert(len(t1.intersection(set([lock['rse_id'] for lock in dataset_locks]))) == 2)
        assert(len(first_locks.intersection(set([lock['rse_id'] for lock in dataset_locks]))) == 2)

    def test_add_rule_dataset_dataset(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset and check if requests are created"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse5, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        for file in files:
            get_request_by_did(scope=file['scope'], name=file['name'], rse=self.rse5)

    def test_add_rule_container_dataset(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, DATASET Grouping"""
        scope = 'mock'
        container = 'container_' + str(uuid())
        add_did(scope, container, DIDType.from_sym('CONTAINER'), 'jdoe')
        all_files = []
        dataset_files = []
        for i in xrange(3):
            files = create_files(3, scope, self.rse1)
            all_files.extend(files)
            dataset = 'dataset_' + str(uuid())
            add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
            attach_dids(scope, dataset, files, 'jdoe')
            attach_dids(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')
            dataset_files.append({'scope': scope, 'name': dataset, 'files': files})

        add_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        t1 = set([self.rse1_id, self.rse3_id, self.rse5_id])
        for dataset in dataset_files:
            first_locks = None
            for file in dataset['files']:
                if first_locks is None:
                    first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
                rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
                assert(len(t1.intersection(rse_locks)) == 2)
                assert(len(first_locks.intersection(rse_locks)) == 2)

    def test_add_rule_dataset_none_with_weights(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, NONE Grouping, WEIGHTS"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight="fakeweight", lifetime=None, locked=False, subscription_id=None)

        # Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse3_id, self.rse5_id])
        for file in files:
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert_in(self.rse1_id, rse_locks)

    def test_add_rule_container_dataset_with_weights(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, DATASET Grouping, WEIGHTS"""
        scope = 'mock'
        container = 'container_' + str(uuid())
        add_did(scope, container, DIDType.from_sym('CONTAINER'), 'jdoe')
        all_files = []
        dataset_files = []
        for i in xrange(3):
            files = create_files(3, scope, self.rse1)
            all_files.extend(files)
            dataset = 'dataset_' + str(uuid())
            add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
            attach_dids(scope, dataset, files, 'jdoe')
            attach_dids(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')
            dataset_files.append({'scope': scope, 'name': dataset, 'files': files})

        add_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)

        t1 = set([self.rse1_id, self.rse3_id, self.rse5_id])
        for dataset in dataset_files:
            first_locks = None
            for file in dataset['files']:
                if first_locks is None:
                    first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
                rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
                assert(len(t1.intersection(rse_locks)) == 2)
                assert(len(first_locks.intersection(rse_locks)) == 2)
                assert_in(self.rse1_id, rse_locks)

    def test_get_rule(self):
        """ REPLICATION RULE (CORE): Test to get a previously created rule"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        assert(rule_id == get_rule(rule_id)['id'].replace('-', '').lower())
        assert_raises(RuleNotFound, get_rule, uuid())

    def test_delete_rule(self):
        """ REPLICATION RULE (CORE): Test to delete a previously created rule"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        delete_rule(rule_id)
        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'])
            assert(len(rse_locks) == 0)
        assert_raises(RuleNotFound, delete_rule, uuid())

    def test_delete_rule_and_cancel_transfers(self):
        """ REPLICATION RULE (CORE): Test to delete a previously created rule and do not cancel overlapping transfers"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id_1 = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=3, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        delete_rule(rule_id_1)

        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'])
            assert(len(rse_locks) == 5)
            # TODO Need to check transfer queue here, this is actually not the check of this test case
        assert_raises(RuleNotFound, delete_rule, uuid())

    def test_locked_rule(self):
        """ REPLICATION RULE (CORE): Delete a locked replication rule"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id_1 = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=True, subscription_id=None)[0]

        assert_raises(UnsupportedOperation, delete_rule, rule_id_1)
        update_rule(rule_id=rule_id_1, options={'locked': False})
        delete_rule(rule_id=rule_id_1)

    def test_account_counter_rule_create(self):
        """ REPLICATION RULE (CORE): Test if the account counter is updated correctly when new rule is created"""

        account_update(once=True)
        account_counter_before = get_account_counter(self.rse1_id, 'jdoe')

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the counter has been updated correctly
        account_update(once=True)
        account_counter_after = get_account_counter(self.rse1_id, 'jdoe')
        assert(account_counter_before['bytes'] + 3 * 100 == account_counter_after['bytes'])
        assert(account_counter_before['files'] + 3 == account_counter_after['files'])

    def test_account_counter_rule_delete(self):
        """ REPLICATION RULE (CORE): Test if the account counter is updated correctly when a rule is removed"""

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        account_update(once=True)
        account_counter_before = get_account_counter(self.rse1_id, 'jdoe')

        delete_rule(rule_id)
        account_update(once=True)

        # Check if the counter has been updated correctly
        account_counter_after = get_account_counter(self.rse1_id, 'jdoe')
        assert(account_counter_before['bytes'] - 3 * 100 == account_counter_after['bytes'])
        assert(account_counter_before['files'] - 3 == account_counter_after['files'])

    def test_account_counter_rule_update(self):
        """ REPLICATION RULE (CORE): Test if the account counter is updated correctly when a rule is updated"""

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        account_update(once=True)
        account_counter_before_1 = get_account_counter(self.rse1_id, 'jdoe')
        account_counter_before_2 = get_account_counter(self.rse1_id, 'root')

        update_rule(rule_id, {'account': 'root'})
        account_update(once=True)

        # Check if the counter has been updated correctly
        account_counter_after_1 = get_account_counter(self.rse1_id, 'jdoe')
        account_counter_after_2 = get_account_counter(self.rse1_id, 'root')
        assert(account_counter_before_1['bytes'] - 3 * 100 == account_counter_after_1['bytes'])
        assert(account_counter_before_2['bytes'] + 3 * 100 == account_counter_after_2['bytes'])

    def test_rse_counter_unavailable_replicas(self):
        """ REPLICATION RULE (CORE): Test if creating UNAVAILABLE replicas updates the RSE Counter correctly"""

        rse_update(once=True)
        rse_counter_before = get_rse_counter(self.rse3_id)

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse3, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        # Check if the rse has been updated correctly
        rse_update(once=True)
        rse_counter_after = get_rse_counter(self.rse3_id)
        assert(rse_counter_before['bytes'] + 3 * 100 == rse_counter_after['bytes'])
        assert(rse_counter_before['files'] + 3 == rse_counter_after['files'])

    def test_rule_add_fails_account_limit(self):
        """ REPLICATION RULE (CORE): Test if a rule fails correctly when account limit conflict"""

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        set_account_limit(account='jdoe', rse_id=self.rse1_id, bytes=5)

        assert_raises(InsufficientAccountLimit, add_rule, dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        delete_account_limit(account='jdoe', rse_id=self.rse1_id)

    def test_dataset_callback(self):
        """ REPLICATION RULE (CORE): Test dataset callback"""

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        set_status(scope=scope, name=dataset, open=False)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse3, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='C')[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=self.rse3_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=self.rse3_id, nowait=False)
        successful_transfer(scope=scope, name=files[2]['name'], rse_id=self.rse3_id, nowait=False)

        # Check if rule exists
        assert(True is check_dataset_ok_callback(scope, dataset, self.rse3, rule_id))

    def test_dataset_callback_no(self):
        """ REPLICATION RULE (CORE): Test dataset callback should not be sent"""

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        set_status(scope=scope, name=dataset, open=False)

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse3, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='C')[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=self.rse3_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=self.rse3_id, nowait=False)

        # Check if rule exists
        assert(False is check_dataset_ok_callback(scope, dataset, self.rse3, rule_id))

    def test_dataset_callback_close_late(self):
        """ REPLICATION RULE (CORE): Test dataset callback with late close"""

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse3, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='C')[0]

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=self.rse3_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=self.rse3_id, nowait=False)
        successful_transfer(scope=scope, name=files[2]['name'], rse_id=self.rse3_id, nowait=False)

        # Check if rule exists
        assert(False is check_dataset_ok_callback(scope, dataset, self.rse3, rule_id))
        set_status(scope=scope, name=dataset, open=False)
        assert(True is check_dataset_ok_callback(scope, dataset, self.rse3, rule_id))

    def test_dataset_callback_with_evaluator(self):
        """ REPLICATION RULE (CORE): Test dataset callback with judge evaluator"""

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse3, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, notify='C')[0]

        assert(False is check_dataset_ok_callback(scope, dataset, self.rse3, rule_id))

        attach_dids(scope, dataset, files, 'jdoe')
        set_status(scope=scope, name=dataset, open=False)
        assert(False is check_dataset_ok_callback(scope, dataset, self.rse3, rule_id))

        re_evaluator(once=True)

        successful_transfer(scope=scope, name=files[0]['name'], rse_id=self.rse3_id, nowait=False)
        successful_transfer(scope=scope, name=files[1]['name'], rse_id=self.rse3_id, nowait=False)
        successful_transfer(scope=scope, name=files[2]['name'], rse_id=self.rse3_id, nowait=False)

        assert(True is check_dataset_ok_callback(scope, dataset, self.rse3, rule_id))

    def test_add_rule_with_purge(self):
        """ REPLICATION RULE (CORE): Add a replication rule with purge setting"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse4, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None, purge_replicas=True)[0]

        delete_rule(rule_id)

        # Check if the Locks are created properly
        for file in files:
            replica = get_replica(rse=self.rse4, scope=file['scope'], name=file['name'])
            assert(replica['tombstone'] == OBSOLETE)

    def test_add_rule_with_ignore_availability(self):
        """ REPLICATION RULE (CORE): Add a replication rule with ignore_availability setting"""
        rse = rse_name_generator()
        add_rse(rse)
        update_rse(rse, {'availability_write': False})
        set_account_limit('jdoe', get_rse_id(rse), -1)

        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        with assert_raises(RSEBlacklisted):
            add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=rse, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=rse, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None, ignore_availability=True)[0]

    def test_delete_rule_country_admin(self):
        """ REPLICATION RULE (CORE): Delete a rule with a country admin account"""
        rse = rse_name_generator()
        add_rse(rse)
        add_rse_attribute(rse, 'country', 'test')
        set_account_limit('jdoe', get_rse_id(rse), -1)

        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=rse, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        usr = account_name_generator()
        add_account(usr, 'USER', 'rucio@email.com', 'root')

        with assert_raises(AccessDenied):
            rucio.api.rule.delete_replication_rule(rule_id=rule_id, purge_replicas=None, issuer=usr)

        add_account_attribute(usr, 'country-test', 'admin')

        rucio.api.rule.delete_replication_rule(rule_id=rule_id, purge_replicas=None, issuer=usr)

    def test_reduce_rule(self):
        """ REPLICATION RULE (CORE): Reduce a rule"""
        scope = 'mock'
        files = create_files(3, scope, [self.rse1, self.rse3])
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.rse1 + '|' + self.rse3, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        assert(get_rule(rule_id)['state'] == RuleState.OK)

        rule_id2 = reduce_rule(rule_id=rule_id, copies=1, exclude_expression=self.rse1)

        assert(get_rule(rule_id2)['state'] == RuleState.OK)
        assert_raises(RuleNotFound, get_rule, rule_id)

        scope = 'mock'
        files = create_files(3, scope, [self.rse1, self.rse3])
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.rse1 + '|' + self.rse3 + '|' + self.rse5, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        with assert_raises(RuleReplaceFailed):
            reduce_rule(rule_id=rule_id, copies=1, exclude_expression=self.rse1 + '|' + self.rse3)

    def test_add_rule_with_scratchdisk(self):
        """ REPLICATION RULE (CORE): Add a replication rule for scratchdisk"""
        rse = rse_name_generator()
        add_rse(rse)
        add_rse_attribute(rse, 'type', 'SCRATCHDISK')
        set_account_limit('jdoe', get_rse_id(rse), -1)

        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        with assert_raises(ScratchDiskLifetimeConflict):
            add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression='MOCK|%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

    def test_add_rule_with_auto_approval(self):
        """ REPLICATION RULE (CORE): Add a replication rule with auto approval"""
        rse = rse_name_generator()
        add_rse(rse)

        scope = 'mock'
        files = create_files(3, scope, self.rse1, bytes=200)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')
        set_status(scope=scope, name=dataset, open=False)

        with assert_raises(InsufficientAccountLimit):
            rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]
        assert(get_rule(rule_id)['state'] == RuleState.WAITING_APPROVAL)
        delete_rule(rule_id=rule_id)

        add_rse_attribute(rse, 'auto_approve_bytes', 500)
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]
        assert(get_rule(rule_id)['state'] == RuleState.WAITING_APPROVAL)
        delete_rule(rule_id=rule_id)

        del_rse_attribute(rse, 'auto_approve_bytes')
        add_rse_attribute(rse, 'auto_approve_bytes', 1000)
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]
        assert(get_rule(rule_id)['state'] == RuleState.INJECT)

    def test_add_rule_with_manual_approval_block(self):
        """ REPLICATION RULE (CORE): Add a replication rule for a RSE with manual approval block"""
        rse = rse_name_generator()
        add_rse(rse)
        add_rse_attribute(rse, 'block_manual_approval', '1')
        set_account_limit('jdoe', get_rse_id(rse), -1)

        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        with assert_raises(ManualRuleApprovalBlocked):
            add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression='%s' % rse, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]


class TestReplicationRuleClient():

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

        set_account_limit('jdoe', cls.rse1_id, -1)
        set_account_limit('jdoe', cls.rse3_id, -1)
        set_account_limit('jdoe', cls.rse4_id, -1)
        set_account_limit('jdoe', cls.rse5_id, -1)

    def setup(self):
        self.rule_client = RuleClient()
        self.did_client = DIDClient()
        self.subscription_client = SubscriptionClient()
        self.account_client = AccountClient()
        self.lock_client = LockClient()

    def test_add_rule(self):
        """ REPLICATION RULE (CLIENT): Add a replication rule and list full history """
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        ret = self.rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        assert_is_instance(ret, list)

        rep_rules = [rep_rule for rep_rule in self.rule_client.list_replication_rule_full_history(scope, dataset)]
        assert_equal(len(rep_rules), 1)
        assert_equal(ret[0], rep_rules[0]['rule_id'])

    def test_delete_rule(self):
        """ REPLICATION RULE (CLIENT): Delete a replication rule """
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        ret = self.rule_client.delete_replication_rule(rule_id=rule_id)
        assert(ret is True)
        get = self.rule_client.get_replication_rule(rule_id)
        assert(get['expires_at'] is not None)

    def test_list_rules_by_did(self):
        """ DID (CLIENT): List Replication Rules per DID """
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id_1 = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        rule_id_2 = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse3, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        ret = self.did_client.list_did_rules(scope=scope, name=dataset)
        ids = [rule['id'] for rule in ret]

        assert_in(rule_id_1, ids)
        assert_in(rule_id_2, ids)

    def test_get_rule(self):
        """ REPLICATION RULE (CLIENT): Get Replication Rule by id """
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        ret = self.rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        get = self.rule_client.get_replication_rule(ret[0])
        assert(ret[0] == get['id'])

    def test_get_rule_by_account(self):
        """ ACCOUNT (CLIENT): Get Replication Rule by account """
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        ret = self.rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        get = self.account_client.list_account_rules('jdoe')
        rules = [rule['id'] for rule in get]

        assert_in(ret[0], rules)

    def test_locked_rule(self):
        """ REPLICATION RULE (CLIENT): Delete a locked replication rule"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id_1 = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=True, subscription_id=None)[0]

        assert_raises(UnsupportedOperation, delete_rule, rule_id_1)
        self.rule_client.update_replication_rule(rule_id=rule_id_1, options={'locked': False})
        delete_rule(rule_id=rule_id_1)

    def test_dataset_lock(self):
        """ DATASETLOCK (CLIENT): Get a datasetlock for a specific dataset"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id_1 = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='DATASET', weight='fakeweight', lifetime=None, locked=True, subscription_id=None)[0]

        rule_ids = [lock['rule_id'] for lock in self.lock_client.get_dataset_locks(scope=scope, name=dataset)]
        assert_in(rule_id_1, rule_ids)

    def test_change_rule_lifetime(self):
        """ REPLICATION RULE (CLIENT): Change rule lifetime"""
        scope = 'mock'
        files = create_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.from_sym('DATASET'), 'jdoe')
        attach_dids(scope, dataset, files, 'jdoe')

        rule_id_1 = add_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='DATASET', weight='fakeweight', lifetime=150, locked=True, subscription_id=None)[0]

        get = self.rule_client.get_replication_rule(rule_id_1)

        self.rule_client.update_replication_rule(rule_id_1, options={'lifetime': 10000})

        get2 = self.rule_client.get_replication_rule(rule_id_1)

        assert(get['expires_at'] != get2['expires_at'])
