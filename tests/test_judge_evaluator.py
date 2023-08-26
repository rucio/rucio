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

import pytest

from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import get_usage
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_did, attach_dids, detach_dids
from rucio.core.lock import get_dataset_locks, get_replica_locks, get_replica_locks_for_rule_id
from rucio.core.replica import add_replica
from rucio.core.rse import add_rse_attribute
from rucio.core.rule import add_rule, get_rule
from rucio.daemons.abacus.account import account_update
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.db.sqla.constants import DIDType, LockState
from rucio.db.sqla.models import UpdatedDID
from rucio.db.sqla.session import transactional_session
from rucio.tests.common import RSE_namedtuple
from rucio.tests.common_server import get_vo
from .test_rule import create_files, tag_generator

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .temp_factories import TemporaryDidFactory, TemporaryRSEFactory


@pytest.fixture(scope="class")
def setup_class(request, rse_factory_unittest):
    request.cls.setUpClass()


@pytest.mark.noparallel(reason='sets account limits, adds global rse attributes')
@pytest.mark.usefixtures("setup_class")
class TestJudgeEvaluator:

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        @transactional_session
        def __cleanup_updated_dids(*, session=None):
            session.query(UpdatedDID).delete()

        __cleanup_updated_dids()

        # Add test RSE
        cls.rse1, cls.rse1_id = cls.rse_factory.make_mock_rse()
        cls.rse3, cls.rse3_id = cls.rse_factory.make_mock_rse()
        cls.rse4, cls.rse4_id = cls.rse_factory.make_mock_rse()
        cls.rse5, cls.rse5_id = cls.rse_factory.make_mock_rse()

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

    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
    def test_judge_add_files_to_dataset(self):
        """ JUDGE EVALUATOR: Test the judge when adding files to dataset"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)

        attach_dids(scope, dataset, files, self.jdoe)
        re_evaluator(once=True, did_limit=None)

        files = create_files(3, scope, self.rse1_id)
        attach_dids(scope, dataset, files, self.jdoe)

        # Fake judge
        re_evaluator(once=True, did_limit=None)

        # Check if the Locks are created properly
        for file in files:
            assert len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2

    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
    def test_judge_add_dataset_to_container(self):
        """ JUDGE EVALUATOR: Test the judge when adding dataset to container"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        parent_container = 'dataset_' + str(uuid())

        # Fake judge to clean out queue
        re_evaluator(once=True, did_limit=None)

        add_did(scope, parent_container, DIDType.CONTAINER, self.jdoe)
        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': parent_container}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None)
        attach_dids(scope, parent_container, [{'scope': scope, 'name': dataset}], self.jdoe)
        # Fake judge
        re_evaluator(once=True, did_limit=None)

        # Check if the Locks are created properly
        for file in files:
            assert len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2

        # Check if the DatasetLocks are created properly
        dataset_locks = [lock for lock in get_dataset_locks(scope=scope, name=dataset)]
        assert len(dataset_locks) == 2

    # @pytest.mark.xfail(reason="This is a test for a known bug. See issue 5251")
    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
    def test_judge_dataset_grouping_all(self):
        """ JUDGE EVALUATOR: Test the judge when adding dataset to existing container with ALL grouping"""

        # create a container
        scope = InternalScope('mock', **self.vo)
        parent_container = 'container_' + str(uuid())
        add_did(scope, parent_container, DIDType.CONTAINER, self.jdoe)

        # create a dataset, populate it with an "existing" file and declare that they reside in the T1 RSE
        files = create_files(1, scope, self.rse1_id)        # rse1 has T1 tag
        dataset1 = 'dataset_' + str(uuid())
        add_did(scope, dataset1, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset1, files, self.jdoe)

        # attach the dataset to the container
        attach_dids(scope, parent_container, [{'scope': scope, 'name': dataset1}], self.jdoe)

        # add rule to copy everything in this container to T1, use grouping=ALL
        add_rule(dids=[{'scope': scope, 'name': parent_container}],
                 account=self.jdoe,
                 copies=1, rse_expression=self.T1, grouping='ALL',
                 weight=None, lifetime=None, locked=False, subscription_id=None
                 )

        re_evaluator(once=True, did_limit=None)         # to clear any history

        # create another dataset, populate it with "new" files and declare that they reside in a T2 RSE
        new_files = create_files(5, scope, self.rse4_id)        # rse4 has T2 tag
        dataset2 = 'dataset_' + str(uuid())
        add_did(scope, dataset2, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset2, new_files, self.jdoe)

        # attach the new dataset to the container
        attach_dids(scope, parent_container, [{'scope': scope, 'name': dataset2}], self.jdoe)

        # re-run the evaluator
        re_evaluator(once=True, did_limit=None)

        # check if the evaluator created locks to move the new files to the same RSE where old files are
        for file in new_files:
            locks = get_replica_locks(scope=file['scope'], name=file['name'])
            assert len(locks) == 1
            lock = locks[0]
            assert lock["rse_id"] == self.rse1_id

    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
    def test_account_counter_judge_evaluate_attach(self):
        """ JUDGE EVALUATOR: Test if the account counter is updated correctly when a file is added to a DS"""
        re_evaluator(once=True, did_limit=None)
        account_update(once=True)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes_=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        account_counter_before = get_usage(self.rse1_id, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        # Fake judge
        re_evaluator(once=True, did_limit=None)
        account_update(once=True)

        account_counter_after = get_usage(self.rse1_id, self.jdoe)
        assert account_counter_before['bytes'] + 3 * 100 == account_counter_after['bytes']
        assert account_counter_before['files'] + 3 == account_counter_after['files']

    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
    def test_account_counter_judge_evaluate_detach(self):
        """ JUDGE EVALUATOR: Test if the account counter is updated correctly when a file is removed from a DS"""
        re_evaluator(once=True, did_limit=None)
        account_update(once=True)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes_=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        # Add a first rule to the DS
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)

        account_update(once=True)

        account_counter_before = get_usage(self.rse1_id, self.jdoe)

        detach_dids(scope, dataset, [files[0]])

        # Fake judge
        re_evaluator(once=True, did_limit=None)
        account_update(once=True)

        account_counter_after = get_usage(self.rse1_id, self.jdoe)
        assert account_counter_before['bytes'] - 100 == account_counter_after['bytes']
        assert account_counter_before['files'] - 1 == account_counter_after['files']

    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
    def test_judge_evaluate_detach_datasetlock(self):
        """ JUDGE EVALUATOR: Test if the a datasetlock is detached correctly when removing a dataset from a container"""
        re_evaluator(once=True, did_limit=None)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes_=100)
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
        assert len(locks) > 0

        detach_dids(scope, container, [{'scope': scope, 'name': dataset}])

        # Fake judge
        re_evaluator(once=True, did_limit=None)

        locks = [ds_lock for ds_lock in get_dataset_locks(scope=scope, name=dataset)]
        assert len(locks) == 0

    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
    def test_judge_evaluate_detach(self):
        """ JUDGE EVALUATOR: Test if the detach is done correctly"""
        re_evaluator(once=True, did_limit=None)

        scope = InternalScope('mock', **self.vo)
        container = 'container_' + str(uuid())
        add_did(scope, container, DIDType.CONTAINER, self.jdoe)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes_=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)
        attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes_=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)
        attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)

        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id, bytes_=100)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)
        attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)

        # Add a first rule to the Container
        rule_id = add_rule(dids=[{'scope': scope, 'name': container}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='ALL', weight=None, lifetime=None, locked=False, subscription_id=None)[0]

        # Fake judge
        re_evaluator(once=True, did_limit=None)

        assert get_rule(rule_id)['locks_ok_cnt'] == 9

        detach_dids(scope, dataset, [files[0]])

        # Fake judge
        re_evaluator(once=True, did_limit=None)

        assert get_rule(rule_id)['locks_ok_cnt'] == 8

    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
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
        re_evaluator(once=True, did_limit=None)

        files = create_files(3, scope, self.rse1_id)
        attach_dids(scope, dataset, files, self.jdoe)

        # Fake judge
        re_evaluator(once=True, did_limit=None)

        # Check if the Locks are created properly
        for file in files:
            assert len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2

    @pytest.mark.noparallel(reason="uses mock scope and predefined RSEs; runs judge evaluator")
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
        re_evaluator(once=True, did_limit=None)

        # Check if the Locks are created properly
        for file in files:
            assert len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2

        # create more files and attach them
        more_files = create_files(3, scope, self.rse1_id)
        attach_dids(scope, dataset, more_files, self.jdoe)
        re_evaluator(once=True, did_limit=None)
        # Check if the Locks are created properly
        for file in more_files:
            assert len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2


def test_judge_double_rule_on_container(
    did_factory: "TemporaryDidFactory",
    rse_factory: "TemporaryRSEFactory",
    root_account: "InternalAccount"
):
    """
    JUDGE EVALUATOR:
    Test the judge evaluator on a container with two rules. The order in which
    rules and datasets are added is relevant to the testcase.

    1. A container C is created and a first dataset D1 is added to C.
    2. A first rule A is created on the container C.
    3. Then another dataset D2 is added to the container C.
    4. Then a rule B is created on the container C.
    5. Run judge-evaluator.

    NOTE I am unsure whether the judge-evaluator is expected to run here.

    We assert that both rules must be in state OK. Both rules must be applied to
    each DID that can be traced back to the parent container C.
    """
    # create RSE, setup
    RSE = RSE_namedtuple(*rse_factory.make_mock_rse())
    rsekey, rseval = tag_generator(), tag_generator()
    add_rse_attribute(RSE.id, rsekey, rseval)

    # 1. create container C, add dataset D1 (with file F1)
    C = did_factory.make_container()
    D1 = did_factory.make_dataset()
    attach_dids(dids=[D1], account=root_account, **C)
    F1 = did_factory.random_file_did()
    add_replica(rse_id=RSE.id, account=root_account, bytes_=10, **F1)
    attach_dids(dids=[F1], account=root_account, **D1)

    # 2. Add rule A to container C
    # > bind C to RSE using RSE name
    A, = add_rule(
        dids=[C],
        account=root_account,
        copies=1,
        rse_expression=RSE.name,
        grouping="DATASET",
        weight=None,
        lifetime=None,
        locked=False,
        subscription_id=None
    )

    # 3. Add dataset D2 to container C (with file F2)
    D2 = did_factory.make_dataset()
    attach_dids(dids=[D2], account=root_account, **C)
    F2 = did_factory.random_file_did()
    add_replica(rse_id=RSE.id, account=root_account, bytes_=10, **F2)
    attach_dids(dids=[F2], account=root_account, **D2)

    # 4. Add rule B to container C
    # > bind C to RSE using RSE attribute
    B, = add_rule(
        dids=[C],
        account=root_account,
        copies=1,
        rse_expression=f"{rsekey}={rseval}",
        grouping="DATASET",
        weight=None,
        lifetime=None,
        locked=False,
        subscription_id=None
    )

    # 5. Run fake judge-evaluator
    re_evaluator(once=True, did_limit=None)

    # Assertions
    for ruleid in (A, B):
        locks = get_replica_locks_for_rule_id(ruleid)
        assert len(locks) == 2  # 2 locks
        assert all([lock["state"] == LockState.OK for lock in locks])  # all OK


def test_judge_double_container_with_existing_rule(
    did_factory: "TemporaryDidFactory",
    rse_factory: "TemporaryRSEFactory",
    root_account: "InternalAccount"
):
    """
    JUDGE EVALUATOR:
    Test the judge in attaching to a file structure with two nested
    containers. The root container has a rule.
    """
    RSE = RSE_namedtuple(*rse_factory.make_mock_rse())

    # create container C1 with rule
    C1 = did_factory.make_container()

    add_rule(
        dids=[C1],
        account=root_account,
        copies=1,
        rse_expression=RSE.name,
        grouping='DATASET',
        weight=None,
        lifetime=None,
        locked=False,
        subscription_id=None
    )

    # create setup: C2->D->F
    C2 = did_factory.make_container()
    D = did_factory.make_dataset()
    F = did_factory.random_file_did()
    add_replica(rse_id=RSE.id, account=root_account, bytes_=10, **F)

    attach_dids(dids=[F], account=root_account, **D)
    attach_dids(dids=[D], account=root_account, **C2)

    # attach setup to C1 (result: C1->C2->D->F)
    attach_dids(dids=[C2], account=root_account, **C1)

    # fake judge
    re_evaluator(once=True, did_limit=None)

    # assertions
    replicalocks = get_replica_locks(**F)
    assert len(replicalocks) == 1
    assert replicalocks[0].state == LockState.OK
    datasetlocks = list(get_dataset_locks(**D))
    assert len(datasetlocks) == 1
    assert datasetlocks[0]["state"] == LockState.OK

    # detach again
    detach_dids(dids=[C2], **C1)
    re_evaluator(once=True, did_limit=None)

    assert not get_replica_locks(**F)
    assert not get_replica_locks(**D)
