# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

import string
import random

from nose.tools import assert_is_instance, assert_in, assert_not_in, assert_raises

from rucio.client.accountclient import AccountClient
from rucio.client.didclient import DIDClient
from rucio.client.ruleclient import RuleClient
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.common.utils import generate_uuid as uuid
from rucio.common.exception import RuleNotFound
from rucio.core.did import add_identifier, attach_identifier
from rucio.core.lock import get_replica_locks
from rucio.core.rse import add_rse_attribute, add_file_replica, get_rse
from rucio.core.rule import add_replication_rule, get_replication_rule, delete_replication_rule
from rucio.core.scope import add_scope


def _create_test_files(nrfiles, scope, rse, size=1):
    """
    Creates a number of test files and add replicas to rse

    :param nrfiles:  Number of files to create
    :param scope:    Scope to create the files in
    :param rse:      RSE to add the replica to
    :param size:     Size of each file
    :returns:        List of dict
    """
    files = []
    for i in xrange(nrfiles):
        file = 'file_%s' % uuid()
        add_file_replica(rse=rse, scope=scope, name=file, size=size, account='jdoe')
        files.append({'scope': scope, 'name': file, 'size': size})
    return files


def _tag_generator(size=8, chars=string.ascii_uppercase):
    return ''.join(random.choice(chars) for x in range(size))


class TestReplicationRuleCore():

    @classmethod
    def setUpClass(cls):
        #Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse2 = 'MOCK2'
        cls.rse3 = 'MOCK3'
        cls.rse4 = 'MOCK4'
        cls.rse5 = 'MOCK5'

        cls.rse1_id = get_rse(cls.rse1).id
        cls.rse2_id = get_rse(cls.rse2).id
        cls.rse3_id = get_rse(cls.rse3).id
        cls.rse4_id = get_rse(cls.rse4).id
        cls.rse5_id = get_rse(cls.rse5).id

        #Add Tags
        cls.T1 = _tag_generator()
        cls.T2 = _tag_generator()
        add_rse_attribute(cls.rse1, cls.T1, True)
        add_rse_attribute(cls.rse2, cls.T1, True)
        add_rse_attribute(cls.rse3, cls.T1, True)
        add_rse_attribute(cls.rse4, cls.T2, True)
        add_rse_attribute(cls.rse5, cls.T1, True)

        #Add fake weights
        add_rse_attribute(cls.rse1, "fakeweight", 10)
        add_rse_attribute(cls.rse2, "fakeweight", 0)
        add_rse_attribute(cls.rse3, "fakeweight", 0)
        add_rse_attribute(cls.rse4, "fakeweight", 0)
        add_rse_attribute(cls.rse5, "fakeweight", 0)

    def test_add_replication_rule_file_none(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a group of files, NONE Grouping"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        add_replication_rule(dids=files, account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        #Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse2_id, self.rse3_id, self.rse5_id])
        for file in files:
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) > 0)
            assert_not_in(self.rse4_id, rse_locks)

    def test_add_replication_rule_dataset_none(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, NONE Grouping"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        #Add a first rule to the DS
        add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        #Add a second rule and check if the right locks are created
        add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression='%s|%s' % (self.T1, self.T2), grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)

        #Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse2_id, self.rse3_id, self.rse5_id])
        for file in files:
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert_not_in(self.rse4_id, rse_locks)

    def test_add_replication_rule_container_none(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, NONE Grouping"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        container = 'container_' + str(uuid())
        add_identifier(scope, container, 'container', 'jdoe')
        all_files = []
        for i in xrange(3):
            files = _create_test_files(3, scope, self.rse1)
            all_files.extend(files)
            dataset = 'dataset_' + str(uuid())
            add_identifier(scope, dataset, 'dataset', 'jdoe')
            attach_identifier(scope, dataset, files, 'jdoe')
            attach_identifier(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')

        add_replication_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=1, rse_expression=self.T2, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
        for file in all_files:
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert_in(self.rse4_id, rse_locks)
            assert_not_in(self.rse5_id, rse_locks)

    def test_add_replication_rule_dataset_all(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, ALL Grouping"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        #Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse2_id, self.rse3_id, self.rse5_id])
        first_locks = None
        for file in files:
            if first_locks is None:
                first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

    def test_add_replication_rule_container_all(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, ALL Grouping"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        container = 'container_' + str(uuid())
        add_identifier(scope, container, 'container', 'jdoe')
        all_files = []
        for i in xrange(3):
            files = _create_test_files(3, scope, self.rse1)
            all_files.extend(files)
            dataset = 'dataset_' + str(uuid())
            add_identifier(scope, dataset, 'dataset', 'jdoe')
            attach_identifier(scope, dataset, files, 'jdoe')
            attach_identifier(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')

        add_replication_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=2, rse_expression=self.T1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        t1 = set([self.rse1_id, self.rse2_id, self.rse3_id, self.rse5_id])
        first_locks = None
        for file in all_files:
            if first_locks is None:
                first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

    def test_add_replication_rule_dataset_dataset(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, DATASET Grouping"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        #Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse2_id, self.rse3_id, self.rse5_id])
        first_locks = None
        for file in files:
            if first_locks is None:
                first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert(len(first_locks.intersection(rse_locks)) == 2)

    def test_add_replication_rule_container_dataset(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, DATASET Grouping"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        container = 'container_' + str(uuid())
        add_identifier(scope, container, 'container', 'jdoe')
        all_files = []
        dataset_files = []
        for i in xrange(3):
            files = _create_test_files(3, scope, self.rse1)
            all_files.extend(files)
            dataset = 'dataset_' + str(uuid())
            add_identifier(scope, dataset, 'dataset', 'jdoe')
            attach_identifier(scope, dataset, files, 'jdoe')
            attach_identifier(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')
            dataset_files.append({'scope': scope, 'name': dataset, 'files': files})

        add_replication_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        t1 = set([self.rse1_id, self.rse2_id, self.rse3_id, self.rse5_id])
        for dataset in dataset_files:
            first_locks = None
            for file in dataset['files']:
                if first_locks is None:
                    first_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
                rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
                assert(len(t1.intersection(rse_locks)) == 2)
                assert(len(first_locks.intersection(rse_locks)) == 2)

    def test_add_replication_rule_dataset_none_with_weights(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a dataset, NONE Grouping, WEIGHTS"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight="fakeweight", lifetime=None, locked=False, subscription_id=None)

        #Check if the Locks are created properly
        t1 = set([self.rse1_id, self.rse2_id, self.rse3_id, self.rse5_id])
        for file in files:
            rse_locks = set([lock['rse_id'] for lock in get_replica_locks(scope=file['scope'], name=file['name'])])
            assert(len(t1.intersection(rse_locks)) == 2)
            assert_in(self.rse1_id, rse_locks)

    def test_add_replication_rule_container_dataset_with_weights(self):
        """ REPLICATION RULE (CORE): Add a replication rule on a container, DATASET Grouping, WEIGHTS"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        container = 'container_' + str(uuid())
        add_identifier(scope, container, 'container', 'jdoe')
        all_files = []
        dataset_files = []
        for i in xrange(3):
            files = _create_test_files(3, scope, self.rse1)
            all_files.extend(files)
            dataset = 'dataset_' + str(uuid())
            add_identifier(scope, dataset, 'dataset', 'jdoe')
            attach_identifier(scope, dataset, files, 'jdoe')
            attach_identifier(scope, container, [{'scope': scope, 'name': dataset}], 'jdoe')
            dataset_files.append({'scope': scope, 'name': dataset, 'files': files})

        add_replication_rule(dids=[{'scope': scope, 'name': container}], account='jdoe', copies=2, rse_expression=self.T1, grouping='DATASET', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)

        t1 = set([self.rse1_id, self.rse2_id, self.rse3_id, self.rse5_id])
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
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        rule_id = add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        assert(rule_id == get_replication_rule(rule_id)['id'].replace('-', '').upper())
        assert_raises(RuleNotFound, get_replication_rule, uuid())

    def test_delete_rule(self):
        """ REPLICATION RULE (CORE): Test to delete a previously created rule"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        rule_id = add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        delete_replication_rule(rule_id)
        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'])
            print rse_locks
            assert(len(rse_locks) == 0)
        assert_raises(RuleNotFound, delete_replication_rule, uuid())

    def test_delete_rule_and_cancel_transfers(self):
        """ REPLICATION RULE (CORE): Test to delete a previously created rule and do not cancel overlapping transfers"""
        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        rule_id_1 = add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=3, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]
        add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=4, rse_expression=self.T1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        delete_replication_rule(rule_id_1)

        for file in files:
            rse_locks = get_replica_locks(scope=file['scope'], name=file['name'])
            print rse_locks
            assert(len(rse_locks) == 7)
            #TODO Need to check transfer queue here, this is actually not the check of this test case
        assert_raises(RuleNotFound, delete_replication_rule, uuid())


class TestReplicationRuleClient():

    @classmethod
    def setUpClass(cls):
        #Add test RSE
        cls.rse1 = 'MOCK'
        cls.rse2 = 'MOCK2'
        cls.rse3 = 'MOCK3'
        cls.rse4 = 'MOCK4'
        cls.rse5 = 'MOCK5'

        cls.rse1_id = get_rse(cls.rse1).id
        cls.rse2_id = get_rse(cls.rse2).id
        cls.rse3_id = get_rse(cls.rse3).id
        cls.rse4_id = get_rse(cls.rse4).id
        cls.rse5_id = get_rse(cls.rse5).id

        #Add Tags
        cls.T1 = _tag_generator()
        cls.T2 = _tag_generator()
        add_rse_attribute(cls.rse1, cls.T1, True)
        add_rse_attribute(cls.rse2, cls.T1, True)
        add_rse_attribute(cls.rse3, cls.T1, True)
        add_rse_attribute(cls.rse4, cls.T2, True)
        add_rse_attribute(cls.rse5, cls.T1, True)

        #Add fake weights
        add_rse_attribute(cls.rse1, "fakeweight", 10)
        add_rse_attribute(cls.rse2, "fakeweight", 0)
        add_rse_attribute(cls.rse3, "fakeweight", 0)
        add_rse_attribute(cls.rse4, "fakeweight", 0)
        add_rse_attribute(cls.rse5, "fakeweight", 0)

    def setup(self):
        self.rule_client = RuleClient()
        self.did_client = DIDClient()
        self.subscription_client = SubscriptionClient()
        self.account_client = AccountClient()

    def test_add_replication_rule(self):
        """ REPLICATION RULE (CLIENT): Add a replication rule """

        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        ret = self.rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        assert_is_instance(ret, list)

    def test_delete_replication_rule(self):
        """ REPLICATION RULE (CLIENT): Delete a replication rule """

        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        rule_id = add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        ret = self.rule_client.delete_replication_rule(rule_id=rule_id)
        assert(ret is True)
        assert_raises(RuleNotFound, self.rule_client.delete_replication_rule, rule_id)

    def test_list_rules_by_did(self):
        """ DID (CLIENT): List Replication Rules per DID """

        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        rule_id_1 = add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse1, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        rule_id_2 = add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=1, rse_expression=self.rse2, grouping='NONE', weight='fakeweight', lifetime=None, locked=False, subscription_id=None)[0]

        ret = self.did_client.list_rules(scope=scope, name=dataset)

        ids = [rule['id'] for rule in ret]

        assert_in(rule_id_1, ids)
        assert_in(rule_id_2, ids)

    def test_get_rule(self):
        """ REPLICATION RULE (CLIENT): Get Replication Rule by id """

        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        ret = self.rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        get = self.rule_client.get_replication_rule(ret[0])

        assert(ret[0] == get['id'])

    def test_get_rule_by_account(self):
        """ ACCOUNT (CLIENT): Get Replication Rule by account """

        scope = 'scope_%s' % uuid()[:20]
        add_scope(scope, 'jdoe')
        files = _create_test_files(3, scope, self.rse1)
        dataset = 'dataset_' + str(uuid())
        add_identifier(scope, dataset, 'dataset', 'jdoe')
        attach_identifier(scope, dataset, files, 'jdoe')

        ret = self.rule_client.add_replication_rule(dids=[{'scope': scope, 'name': dataset}], account='jdoe', copies=2, rse_expression=self.T1, grouping='NONE')
        get = self.account_client.list_rules('jdoe')
        rules = [rule['id'] for rule in get]

        assert_in(ret[0], rules)
