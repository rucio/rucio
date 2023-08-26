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

from datetime import datetime, timedelta

import pytest

from rucio.common.config import config_get_bool
from rucio.common.exception import RuleNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_did, attach_dids
from rucio.core.lock import get_replica_locks
from rucio.core.rse import add_rse_attribute
from rucio.core.rule import add_rule, get_rule, approve_rule, deny_rule, list_rules
from rucio.daemons.judge.injector import rule_injector
from rucio.db.sqla.constants import DIDType, RuleState
from rucio.db.sqla.models import ReplicationRule
from rucio.db.sqla.session import transactional_session
from rucio.tests.common_server import get_vo
from .test_rule import create_files, tag_generator


@pytest.fixture(scope="class")
def setup_class(request, rse_factory_unittest):
    request.cls.setUpClass()


@pytest.mark.noparallel(reason='uses pre-defined RSE, sets account limits, adds global rse attributes')
@pytest.mark.usefixtures("setup_class")
class TestJudgeEvaluator:

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

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

        set_local_account_limit(cls.jdoe, cls.rse1_id, -1)
        set_local_account_limit(cls.jdoe, cls.rse3_id, -1)
        set_local_account_limit(cls.jdoe, cls.rse4_id, -1)
        set_local_account_limit(cls.jdoe, cls.rse5_id, -1)

    def test_judge_inject_rule(self):
        """ JUDGE INJECTOR: Test the judge when injecting a rule"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        # Add a first rule to the DS
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, asynchronous=True)[0]

        assert (get_rule(rule_id)['state'] == RuleState.INJECT)

        rule_injector(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert (len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2)
        assert (get_rule(rule_id)['state'] == RuleState.REPLICATING)

    def test_judge_inject_delayed_rule(self):
        """ JUDGE INJECTOR: Test the judge when injecting a delayed rule"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(1, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)
        [file] = files

        # Add a delayed rule
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=2, rse_expression=self.T1, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, delay_injection=3600)[0]

        rule = get_rule(rule_id)
        assert rule['state'] == RuleState.INJECT
        assert rule['updated_at'] < rule['created_at']
        assert datetime.utcnow() + timedelta(seconds=3550) < rule['created_at'] < datetime.utcnow() + timedelta(seconds=3650)

        # The time to create the rule has not yet arrived. The injector must skip this rule, no locks must be created
        rule_injector(once=True)
        assert get_rule(rule_id)['state'] == RuleState.INJECT
        assert not get_replica_locks(scope=file['scope'], name=file['name'])

        # simulate that time to inject the rule has arrived
        @transactional_session
        def __update_created_at(*, session=None):
            session.query(ReplicationRule).filter_by(id=rule_id).one().created_at = datetime.utcnow()
        __update_created_at()

        # The injector must create the locks now
        rule_injector(once=True)
        assert get_rule(rule_id)['state'] == RuleState.REPLICATING
        assert len(get_replica_locks(scope=file['scope'], name=file['name'])) == 2

    def test_judge_ask_approval(self):
        """ JUDGE INJECTOR: Test the judge when asking approval for a rule"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        # Add a first rule to the DS
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse4, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]

        assert (get_rule(rule_id)['state'] == RuleState.WAITING_APPROVAL)

        approve_rule(rule_id=rule_id, approver=self.jdoe)

        assert (get_rule(rule_id)['state'] == RuleState.INJECT)

        rule_injector(once=True)

        # Check if the Locks are created properly
        for file in files:
            assert (len(get_replica_locks(scope=file['scope'], name=file['name'])) == 1)
        assert (get_rule(rule_id)['state'] == RuleState.REPLICATING)

    def test_judge_deny_rule(self):
        """ JUDGE INJECTOR: Test the judge when asking approval for a rule and denying it"""
        scope = InternalScope('mock', **self.vo)
        files = create_files(3, scope, self.rse1_id)
        dataset = 'dataset_' + str(uuid())
        add_did(scope, dataset, DIDType.DATASET, self.jdoe)
        attach_dids(scope, dataset, files, self.jdoe)

        # Add a first rule to the DS
        rule_id = add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse4, grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, ask_approval=True)[0]

        assert (get_rule(rule_id)['state'] == RuleState.WAITING_APPROVAL)

        deny_rule(rule_id=rule_id, approver=self.jdoe)

        pytest.raises(RuleNotFound, get_rule, rule_id)

    def test_add_rule_with_r2d2_container_treating(self):
        """ JUDGE INJECTOR (CORE): Add a replication rule with an r2d2 container treatment"""
        scope = InternalScope('mock', **self.vo)
        container = 'asdf.r2d2_request.2016-04-01-15-00-00.ads.' + str(uuid())
        add_did(scope, container, DIDType.CONTAINER, self.jdoe)
        datasets = []
        for i in range(3):
            files = create_files(3, scope, self.rse1_id)
            dataset = 'dataset_' + str(uuid())
            datasets.append(dataset)
            add_did(scope, dataset, DIDType.DATASET, self.jdoe)
            attach_dids(scope, dataset, files, self.jdoe)
            attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)
        rule_id = add_rule(dids=[{'scope': scope, 'name': container}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=900, locked=False, subscription_id=None, ask_approval=True)[0]
        approve_rule(rule_id, approver=self.jdoe)
        assert (get_rule(rule_id)['state'] == RuleState.INJECT)
        rule_injector(once=True)
        # Check if there is a rule for each file
        with pytest.raises(RuleNotFound):
            get_rule(rule_id)
        for dataset in datasets:
            assert (len([r for r in list_rules({'scope': scope, 'name': dataset})]) > 0)

    def test_add_rule_with_r2d2_container_treating_and_duplicate_rule(self):
        """ JUDGE INJECTOR (CORE): Add a replication rule with an r2d2 container treatment and duplicate rule"""
        scope = InternalScope('mock', **self.vo)
        container = 'asdf.r2d2_request.2016-04-01-15-00-00.ads.' + str(uuid())
        add_did(scope, container, DIDType.CONTAINER, self.jdoe)
        datasets = []
        for i in range(3):
            files = create_files(3, scope, self.rse1_id)
            dataset = 'dataset_' + str(uuid())
            datasets.append(dataset)
            add_did(scope, dataset, DIDType.DATASET, self.jdoe)
            attach_dids(scope, dataset, files, self.jdoe)
            attach_dids(scope, container, [{'scope': scope, 'name': dataset}], self.jdoe)
        add_rule(dids=[{'scope': scope, 'name': dataset}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=900, locked=False, subscription_id=None, ask_approval=False)
        rule_id = add_rule(dids=[{'scope': scope, 'name': container}], account=self.jdoe, copies=1, rse_expression=self.rse1, grouping='DATASET', weight=None, lifetime=900, locked=False, subscription_id=None, ask_approval=True)[0]
        approve_rule(rule_id, approver=self.jdoe)
        assert (get_rule(rule_id)['state'] == RuleState.INJECT)
        rule_injector(once=True)
        # Check if there is a rule for each file
        with pytest.raises(RuleNotFound):
            get_rule(rule_id)
        for dataset in datasets:
            assert (len([r for r in list_rules({'scope': scope, 'name': dataset})]) > 0)
